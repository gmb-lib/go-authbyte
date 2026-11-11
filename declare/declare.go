// Package declare sends a service's declaration to the membership register when
// the service starts, as the service itself.
//
// The document is what [permissions.Declaration] renders for the service's Sets:
// each service key with its levels and its permissions. [Task] posts it, asking
// for a token that carries exactly one `declare:<key>` scope per key in the
// document and nothing else, so the register can hold the service to the keys
// its deployment granted it.
//
// A service adds the task at start and forgets it. Start returns at once and
// never fails because the register is away; the task sends in the background,
// tries again with a growing pause while the register cannot be reached or
// answers with an outage, and sends again at an interval once it has been
// accepted. A refusal (the register understood the document and said no) is
// reported and tried again only after the longest pause: it is cured by a change
// of the deployment or of the document, not by waiting a second.
package declare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-authbyte/permissions"
)

const (
	// Path is where the register takes a declaration, below its root address.
	Path = "/api/v1/declarations"
	// ScopePrefix starts the scope that grants one service key: `declare:<key>`.
	ScopePrefix = "declare:"
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
// without the API path), reached as the service itself for audience.
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
	if len(sets) == 0 {
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

	body, err := permissions.Declaration(sets...)
	if err != nil {
		return nil, err
	}
	keys := permissions.ServiceKeys(sets...)
	slices.Sort(keys)
	scopes := make([]string, len(keys))
	for i, k := range keys {
		scopes[i] = ScopePrefix + k
	}

	return &Task{
		do:       do,
		url:      strings.TrimRight(baseURL, "/") + Path,
		audience: audience,
		scope:    strings.Join(scopes, " "),
		body:     body,
		cfg:      cfg,
	}, nil
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
		switch err := t.send(ctx); {
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

func (t *Task) send(ctx context.Context) error {
	h := http.Header{"Accept": {"application/json"}, "Content-Type": {"application/json"}}
	res, err := t.do.DoService(ctx, t.audience, t.scope, http.MethodPost, t.url, h, t.body)
	if err != nil {
		return fmt.Errorf("declare: %w", err)
	}
	if res.StatusCode == http.StatusOK {
		if t.cfg.OnDeclared != nil {
			t.cfg.OnDeclared(res.Body)
		}

		return nil
	}

	e := &Error{Status: res.StatusCode}
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(res.Body, &problem) == nil {
		e.Code, e.Detail = problem.Code, problem.Detail
	}

	return e
}
