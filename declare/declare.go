// Package declare sends a service's declaration to the membership register when
// the service starts, as the service itself.
//
// The document is what [permissions.Declaration] renders for the service's Sets:
// each service key with its levels and its permissions. [Task] posts it, asking
// for a token that carries one `declare:<key>` scope per key in the document,
// and one `declare-group:<group>` scope per level group that is not named like
// the key it is declared under, and nothing else, so the register can hold the
// service to the keys and groups its deployment granted it.
//
// The declaration may also carry products (what a product gives, in services,
// and what it needs) and the caller's own account in a product (the levels it
// holds); see [Product] and [Account]. A program that only attaches its account
// declares no service at all. Beside the scopes above the token then carries one
// `declare-product:<key>` scope per product, one `declare-give:<service>` scope per
// service a product gives that is not a service of the same document, and one
// `declare-account:<product>` scope per account. A service that passes no products
// and no accounts sends the same document and asks for the same scopes as before.
//
// A service adds the task at start and forgets it. Start returns at once and
// never fails because the register is away; the task sends in the background,
// tries again with a growing pause while the register cannot be reached or
// answers with an outage, and sends again at an interval once it has been
// accepted. A refusal (the register understood the document and said no) is
// reported and tried again only after the longest pause: it is cured by a change
// of the deployment or of the document, not by waiting a second. An accepted
// answer that says an entry is waiting (it refers to something the register does
// not hold yet) is sent again after the longest pause, for as long as any entry
// waits.
package declare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-authbyte/permissions"
)

const (
	// Path is where the register takes a declaration, below its root address.
	Path = "/api/v1/declarations"
	// ScopePrefix starts the scope that grants one service key: `declare:<key>`.
	ScopePrefix = "declare:"
	// GroupScopePrefix starts the scope that grants one level group that is not
	// named like the service key it is declared under: `declare-group:<group>`.
	GroupScopePrefix = "declare-group:"
	// ProductScopePrefix starts the scope that grants one product key:
	// `declare-product:<key>`.
	ProductScopePrefix = "declare-product:"
	// GiveScopePrefix starts the scope that grants giving one service that is not
	// declared in the same document: `declare-give:<service>`.
	GiveScopePrefix = "declare-give:"
	// AccountScopePrefix starts the scope that grants one account in a product:
	// `declare-account:<product>`.
	AccountScopePrefix = "declare-account:"
	// TaskName is the name the task answers to a service's task list.
	TaskName = "service-declaration"
)

// The defaults a zero [Config] value takes.
const (
	// DefaultFirstPause is the wait after the first failed attempt.
	DefaultFirstPause = time.Second
	// DefaultLongestPause is the longest wait between two attempts after a
	// failure, and the only wait after a refusal.
	DefaultLongestPause = time.Minute
	// DefaultRepeat is how long an accepted declaration waits before it is sent
	// again.
	DefaultRepeat = time.Hour
)

// The limits the register holds a document to, checked by [New] so that a
// document it would refuse is refused before anything is sent.
const (
	// MaxProducts is the most products one document carries.
	MaxProducts = 20
	// MaxAccounts is the most accounts one document carries.
	MaxAccounts = 20
	// MaxGives is the most services one product gives.
	MaxGives = 50
	// MaxNeeds is the most products one product needs.
	MaxNeeds = 20
	// MaxLevels is the most levels one account holds.
	MaxLevels = 50
	// MaxDisplayName is the most characters a display name has.
	MaxDisplayName = 200
	// MaxAnswerBytes is how much of an accepted answer is read for entries that
	// wait; a longer answer is taken as accepted with none waiting.
	MaxAnswerBytes = 256 * 1024
)

var wordShape = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// Product is a product the declaration names: a display name, the services it
// gives (each, optionally, under a feature name) and the products it needs.
type Product struct {
	// Key is one lower-case word, such as "suite".
	Key string
	// DisplayName is 1 to 200 characters with no control character.
	DisplayName string
	// Gives lists what the product gives: 1 to 50 entries, no (Service, Feature)
	// pair twice.
	Gives []Give
	// Needs lists the keys of the products this one needs: at most 20, never its
	// own key.
	Needs []string
}

// Give is one service a product gives, optionally under a feature name.
type Give struct {
	// Service is a service key, one lower-case word.
	Service string
	// Feature is a short text; left out of the document when empty.
	Feature string
}

// Account is the caller's own account in a product, with the levels it holds. It
// never names a client: the register takes the caller to be the one it is.
type Account struct {
	// Product is the key of the product the account is in.
	Product string
	// DisplayName is 1 to 200 characters with no control character.
	DisplayName string
	// Roles are the levels the account holds: at most 50, none twice.
	Roles []Level
}

// Level is one level of a service's role ladder, by service, group and level.
type Level struct {
	Service string
	Group   string
	Level   string
}

// Waiting is an entry of an accepted answer that the register could not take yet,
// because something it refers to is not registered yet. Nothing is wrong; the task
// asks again.
type Waiting struct {
	// Kind is "product" or "account".
	Kind string
	// Key is the entry's key: the product key (for an account, the product it is in).
	Key string
	// Reason is what is missing: "product", "service" or "level"; empty if the
	// answer gave none.
	Reason string
}

// Doer makes a call as the service itself. [authclient.Client] is one.
type Doer interface {
	DoService(ctx context.Context, audience, scope, method, fullURL string,
		reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
}

// Config shapes a [Task]. Zero values take the defaults.
type Config struct {
	// FirstPause is the wait after the first failed attempt; each further failure
	// doubles it. Default [DefaultFirstPause].
	FirstPause time.Duration
	// LongestPause is the longest the doubling reaches, and the wait after a
	// refusal. Default [DefaultLongestPause]; it may not be shorter than
	// FirstPause.
	LongestPause time.Duration
	// Repeat is how often an accepted declaration is sent again. Default
	// [DefaultRepeat].
	Repeat time.Duration
	// OnError is told about every attempt that failed: a call that could not be
	// made, a token that was not given, an outage answer, or a refusal (an
	// [*Error] carrying the status and the register's reason). Optional. It is
	// called on the task's own goroutine, so a callback that blocks delays the
	// next attempt and makes Stop wait.
	OnError func(err error)
	// OnDeclared is told when the register accepted the declaration, with the
	// body of its answer. Optional. It is called on the task's own goroutine, so
	// a callback that blocks delays the next attempt and makes Stop wait.
	OnDeclared func(answer []byte)
	// OnWaiting is told, after OnDeclared, about the entries of an accepted answer
	// that wait for something not registered yet. Optional; the same rule about
	// blocking applies.
	OnWaiting func(waiting []Waiting)
	// Products are declared beside the Sets, each with the services it gives and
	// the products it needs. Optional.
	Products []Product
	// Accounts are the caller's own accounts in products. Optional.
	Accounts []Account
}

// Error is an answer of the register that is not an acceptance. It carries the
// status and, when the answer is a problem document, its code and detail.
type Error struct {
	// Status is the HTTP status the register answered with.
	Status int
	// Code is the problem document's `code`, such as `err:membership:forbidden`;
	// empty when the answer had none.
	Code string
	// Detail is the problem document's `detail`; empty when the answer had none.
	Detail string
}

// Error names the status, the code and the detail, so that the line a service
// logs says what to change.
func (e *Error) Error() string {
	msg := fmt.Sprintf("declare: the register answered %d", e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}

	return msg
}

// Task declares the service's Sets to the register. It satisfies the task
// interface of the framework (Name, Start, Stop).
type Task struct {
	do       Doer
	url      string
	audience string
	scope    string
	body     []byte
	cfg      Config

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// New answers the task that declares sets to the register at baseURL (its root,
// without the API path), reached as the service itself for audience. With
// cfg.Products or cfg.Accounts given, no set is needed.
func New(do Doer, baseURL, audience string, cfg Config, sets ...*permissions.Set) (*Task, error) {
	if do == nil {
		return nil, errors.New("declare: a client is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("declare: %q is not an absolute address", baseURL)
	}
	if audience == "" {
		return nil, errors.New("declare: the register's audience is required")
	}
	if len(sets) == 0 && len(cfg.Products) == 0 && len(cfg.Accounts) == 0 {
		return nil, errors.New("declare: name at least one set to declare")
	}
	if cfg.FirstPause < 0 || cfg.LongestPause < 0 || cfg.Repeat < 0 {
		return nil, errors.New("declare: a pause or an interval may not be negative")
	}
	if cfg.FirstPause == 0 {
		cfg.FirstPause = DefaultFirstPause
	}
	if cfg.LongestPause == 0 {
		cfg.LongestPause = DefaultLongestPause
	}
	if cfg.Repeat == 0 {
		cfg.Repeat = DefaultRepeat
	}
	if cfg.LongestPause < cfg.FirstPause {
		return nil, fmt.Errorf("declare: the longest pause (%s) is shorter than the first (%s)",
			cfg.LongestPause, cfg.FirstPause)
	}

	if err := validate(cfg.Products, cfg.Accounts); err != nil {
		return nil, err
	}
	// The task keeps its own copies, so a later change to the caller's slices
	// cannot change what is sent or asked for.
	cfg.Products = cloneProducts(cfg.Products)
	cfg.Accounts = cloneAccounts(cfg.Accounts)

	body, err := buildBody(sets, cfg.Products, cfg.Accounts)
	if err != nil {
		return nil, err
	}

	return &Task{
		do:       do,
		url:      strings.TrimRight(baseURL, "/") + Path,
		audience: audience,
		scope:    scopeFor(sets, cfg.Products, cfg.Accounts),
		body:     body,
		cfg:      cfg,
	}, nil
}

func cloneProducts(in []Product) []Product {
	out := slices.Clone(in)
	for i := range out {
		out[i].Gives = slices.Clone(out[i].Gives)
		out[i].Needs = slices.Clone(out[i].Needs)
	}

	return out
}

func cloneAccounts(in []Account) []Account {
	out := slices.Clone(in)
	for i := range out {
		out[i].Roles = slices.Clone(out[i].Roles)
	}

	return out
}

func checkWord(what, v string) error {
	if !wordShape.MatchString(v) {
		return fmt.Errorf("declare: %s %q must be one lower-case word of at most 64 characters", what, v)
	}

	return nil
}

func checkNoControl(what, v string) error {
	if strings.ContainsFunc(v, unicode.IsControl) {
		return fmt.Errorf("declare: %s may not contain a control character", what)
	}

	return nil
}

func checkDisplayName(what, v string) error {
	if n := utf8.RuneCountInString(v); n < 1 || n > MaxDisplayName {
		return fmt.Errorf("declare: %s display name must be 1 to %d characters, not %d", what, MaxDisplayName, n)
	}

	return checkNoControl(what+" display name", v)
}

// validate holds the products and accounts to the limits the register enforces.
func validate(products []Product, accounts []Account) error {
	if len(products) > MaxProducts {
		return fmt.Errorf("declare: at most %d products, not %d", MaxProducts, len(products))
	}
	if len(accounts) > MaxAccounts {
		return fmt.Errorf("declare: at most %d accounts, not %d", MaxAccounts, len(accounts))
	}

	seenProduct := map[string]bool{}
	for i, p := range products {
		what := fmt.Sprintf("product %d", i+1)
		if err := checkWord(what+" key", p.Key); err != nil {
			return err
		}
		what = fmt.Sprintf("product %q", p.Key)
		if seenProduct[p.Key] {
			return fmt.Errorf("declare: %s is declared twice", what)
		}
		seenProduct[p.Key] = true
		if err := checkDisplayName(what, p.DisplayName); err != nil {
			return err
		}
		if len(p.Gives) < 1 || len(p.Gives) > MaxGives {
			return fmt.Errorf("declare: %s must give 1 to %d services, not %d", what, MaxGives, len(p.Gives))
		}
		seenGive := map[Give]bool{}
		for _, g := range p.Gives {
			if err := checkWord(what+" gives a service", g.Service); err != nil {
				return err
			}
			if err := checkNoControl(what+" feature", g.Feature); err != nil {
				return err
			}
			if seenGive[g] {
				return fmt.Errorf("declare: %s gives service %q with feature %q twice", what, g.Service, g.Feature)
			}
			seenGive[g] = true
		}
		if len(p.Needs) > MaxNeeds {
			return fmt.Errorf("declare: %s needs at most %d products, not %d", what, MaxNeeds, len(p.Needs))
		}
		for _, n := range p.Needs {
			if err := checkWord(what+" needs a product", n); err != nil {
				return err
			}
			if n == p.Key {
				return fmt.Errorf("declare: %s may not need itself", what)
			}
		}
	}

	seenAccount := map[string]bool{}
	for i, a := range accounts {
		what := fmt.Sprintf("account %d", i+1)
		if err := checkWord(what+" product", a.Product); err != nil {
			return err
		}
		what = fmt.Sprintf("account in product %q", a.Product)
		if seenAccount[a.Product] {
			return fmt.Errorf("declare: product %q has more than one account", a.Product)
		}
		seenAccount[a.Product] = true
		if err := checkDisplayName(what, a.DisplayName); err != nil {
			return err
		}
		if len(a.Roles) > MaxLevels {
			return fmt.Errorf("declare: %s holds at most %d levels, not %d", what, MaxLevels, len(a.Roles))
		}
		seenLevel := map[Level]bool{}
		for _, l := range a.Roles {
			if err := checkWord(what+" level service", l.Service); err != nil {
				return err
			}
			if err := checkWord(what+" level group", l.Group); err != nil {
				return err
			}
			if err := checkWord(what+" level", l.Level); err != nil {
				return err
			}
			if seenLevel[l] {
				return fmt.Errorf("declare: %s holds level %s/%s:%s twice", what, l.Service, l.Group, l.Level)
			}
			seenLevel[l] = true
		}
	}

	return nil
}

// buildBody renders the document. With no products and no accounts it is exactly
// what [permissions.Declaration] renders; otherwise one object holding the
// services (when there are sets), the products and the accounts.
func buildBody(sets []*permissions.Set, products []Product, accounts []Account) ([]byte, error) {
	var services []byte
	if len(sets) > 0 {
		var err error
		if services, err = permissions.Declaration(sets...); err != nil {
			return nil, err
		}
	}
	if len(products) == 0 && len(accounts) == 0 {
		return services, nil
	}

	type giveDoc struct {
		Service string `json:"service"`
		Feature string `json:"feature,omitempty"`
	}
	type productDoc struct {
		Key         string    `json:"key"`
		DisplayName string    `json:"displayName"`
		Gives       []giveDoc `json:"gives"`
		Needs       []string  `json:"needs"`
	}
	type levelDoc struct {
		Service string `json:"service"`
		Group   string `json:"group"`
		Level   string `json:"level"`
	}
	type accountDoc struct {
		Product     string     `json:"product"`
		DisplayName string     `json:"displayName"`
		Roles       []levelDoc `json:"roles"`
	}
	var doc struct {
		Services json.RawMessage `json:"services,omitempty"`
		Products []productDoc    `json:"products,omitempty"`
		Accounts []accountDoc    `json:"accounts,omitempty"`
	}
	if services != nil {
		var d struct {
			Services json.RawMessage `json:"services"`
		}
		if err := json.Unmarshal(services, &d); err != nil {
			return nil, fmt.Errorf("declare: %w", err)
		}
		doc.Services = d.Services
	}
	for _, p := range products {
		pd := productDoc{Key: p.Key, DisplayName: p.DisplayName, Gives: make([]giveDoc, 0, len(p.Gives)),
			Needs: append([]string{}, p.Needs...)}
		for _, g := range p.Gives {
			pd.Gives = append(pd.Gives, giveDoc(g))
		}
		doc.Products = append(doc.Products, pd)
	}
	for _, a := range accounts {
		ad := accountDoc{Product: a.Product, DisplayName: a.DisplayName, Roles: make([]levelDoc, 0, len(a.Roles))}
		for _, l := range a.Roles {
			ad.Roles = append(ad.Roles, levelDoc(l))
		}
		doc.Accounts = append(doc.Accounts, ad)
	}

	return json.MarshalIndent(doc, "", "  ")
}

// scopeFor answers the scope string the token is asked with: `declare:<key>` for
// every service key of the document, and `declare-group:<group>` for every level
// whose group differs from the key of the service entry it is declared under;
// then `declare-product:<key>` for every product, `declare-give:<service>` for
// every service a product gives that is not a service of the document, and
// `declare-account:<product>` for every account; each once, sorted together and
// joined by one space.
func scopeFor(sets []*permissions.Set, products []Product, accounts []Account) string {
	seen := map[string]bool{}
	var scopes []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			scopes = append(scopes, s)
		}
	}
	own := map[string]bool{}
	for _, s := range sets {
		if s == nil {
			continue
		}
		key := permissions.ServiceKeys(s)[0]
		own[key] = true
		add(ScopePrefix + key)
		for _, r := range s.Levels() {
			if r.Group != key {
				add(GroupScopePrefix + r.Group)
			}
		}
	}
	for _, p := range products {
		add(ProductScopePrefix + p.Key)
		for _, g := range p.Gives {
			if !own[g.Service] {
				add(GiveScopePrefix + g.Service)
			}
		}
	}
	for _, a := range accounts {
		add(AccountScopePrefix + a.Product)
	}
	slices.Sort(scopes)

	return strings.Join(scopes, " ")
}

// Name implements the framework's task interface.
func (t *Task) Name() string { return TaskName }

// Start begins sending in the background and returns at once; the register being
// away is not a failure of Start. The loop ends when ctx ends or [Task.Stop] is
// called. A second Start is an error.
func (t *Task) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		return errors.New("declare: the task is already started")
	}
	t.started = true
	loopCtx, cancel := context.WithCancel(ctx)
	t.cancel = cancel
	t.done = make(chan struct{})
	go t.run(loopCtx, t.done)

	return nil
}

// Stop ends the loop and waits for it to end; no request is made after it
// returns. It is safe to call more than once, or without Start.
func (t *Task) Stop() {
	t.mu.Lock()
	cancel, done := t.cancel, t.done
	t.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func (t *Task) run(ctx context.Context, done chan struct{}) {
	defer close(done)

	pause := t.cfg.FirstPause
	for ctx.Err() == nil {
		var wait time.Duration
		waiting, err := t.send(ctx)
		switch {
		case err == nil && waiting:
			// Accepted, but an entry refers to something not registered yet: ask
			// again after the longest pause, not the repeat interval.
			pause, wait = t.cfg.FirstPause, t.cfg.LongestPause
		case err == nil:
			pause, wait = t.cfg.FirstPause, t.cfg.Repeat
		case ctx.Err() != nil:
			return
		case refused(err):
			t.fail(err)
			wait = t.cfg.LongestPause
		default:
			t.fail(err)
			wait = pause
			pause = min(pause*2, t.cfg.LongestPause)
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()

			return
		case <-timer.C:
		}
	}
}

func (t *Task) fail(err error) {
	if t.cfg.OnError != nil {
		t.cfg.OnError(err)
	}
}

// refused reports an answer that is a decision about the document, which waiting
// a second does not change: every answer but 200, a 5xx or a 429. (An outage or a
// request to slow down is tried again with the growing pause; anything else the
// register said, including a status this sender does not expect, waits the
// longest pause.)
func refused(err error) bool {
	var e *Error

	return errors.As(err, &e) && e.Status < http.StatusInternalServerError && e.Status != http.StatusTooManyRequests
}

// waitingIn answers the entries of an accepted answer whose status is "waiting".
// An answer that is too long or cannot be read has none. A line whose key is not
// one lower-case word still counts as waiting, but is passed on with an empty key,
// and a reason other than "product", "service" or "level" is passed on empty.
func waitingIn(body []byte) []Waiting {
	if len(body) > MaxAnswerBytes {
		return nil
	}
	type line struct {
		Key    string `json:"key"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	var answer struct {
		Products []line `json:"products"`
		Accounts []line `json:"accounts"`
	}
	if json.Unmarshal(body, &answer) != nil {
		return nil
	}
	var out []Waiting
	for _, l := range answer.Products {
		if l.Status == "waiting" {
			out = append(out, waitingLine("product", l.Key, l.Reason))
		}
	}
	for _, l := range answer.Accounts {
		if l.Status == "waiting" {
			out = append(out, waitingLine("account", l.Key, l.Reason))
		}
	}

	return out
}

// waitingLine builds a [Waiting] from one line of an answer, keeping the key only
// when it is one lower-case word and the reason only when it is a known one.
func waitingLine(kind, key, reason string) Waiting {
	w := Waiting{Kind: kind}
	if wordShape.MatchString(key) {
		w.Key = key
	}
	switch reason {
	case "product", "service", "level":
		w.Reason = reason
	}

	return w
}

// send makes one attempt. It answers true when the register accepted the
// document but an entry waits for something not registered yet.
func (t *Task) send(ctx context.Context) (bool, error) {
	h := http.Header{"Accept": {"application/json"}, "Content-Type": {"application/json"}}
	res, err := t.do.DoService(ctx, t.audience, t.scope, http.MethodPost, t.url, h, t.body)
	if err != nil {
		return false, fmt.Errorf("declare: %w", err)
	}
	if res.StatusCode == http.StatusOK {
		if t.cfg.OnDeclared != nil {
			t.cfg.OnDeclared(res.Body)
		}
		waiting := waitingIn(res.Body)
		if len(waiting) > 0 && t.cfg.OnWaiting != nil {
			t.cfg.OnWaiting(waiting)
		}

		return len(waiting) > 0, nil
	}

	e := &Error{Status: res.StatusCode}
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(res.Body, &problem) == nil {
		e.Code, e.Detail = problem.Code, problem.Detail
	}

	return false, e
}
