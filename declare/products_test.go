package declare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-authbyte/permissions"
)

// indented renders a compact JSON text the way the document is rendered.
func indented(t *testing.T, compact string) string {
	t.Helper()
	var b bytes.Buffer
	qt.Assert(t, qt.IsNil(json.Indent(&b, []byte(compact), "", "  ")))

	return b.String()
}

// firstCall starts a task for the sets and the config, waits for its first call
// and answers it.
func firstCall(t *testing.T, cfg Config, ss ...*permissions.Set) call {
	t.Helper()
	cfg.Repeat = time.Hour
	f := newFake(ok)
	task, err := New(f, "http://register:8080/", "svc:register", cfg, ss...)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(task.Stop)
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 1)

	return f.all()[0]
}

func suite() Product {
	return Product{
		Key:         "suite",
		DisplayName: "Suite",
		Gives:       []Give{{Service: "alpha", Feature: "tasks"}, {Service: "beta"}},
		Needs:       []string{"base"},
	}
}

func TestSetsOnlyAsksTheSameAndSendsTheSameBytes(t *testing.T) {
	c := firstCall(t, Config{}, sets(t, "alpha", "beta")...)
	want, err := permissions.Declaration(sets(t, "alpha", "beta")...)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(c.body), string(want)))
	qt.Assert(t, qt.Equals(c.scope, "declare:alpha declare:beta"))
}

func TestAProductGivingAnOwnAndAForeignService(t *testing.T) {
	p := Product{Key: "suite", DisplayName: "Suite", Gives: []Give{{Service: "alpha", Feature: "tasks"}, {Service: "beta"}}}
	c := firstCall(t, Config{Products: []Product{p}}, sets(t, "alpha")...)
	qt.Assert(t, qt.Equals(c.scope, "declare-give:beta declare-product:suite declare:alpha"))

	services, err := permissions.Declaration(sets(t, "alpha")...)
	qt.Assert(t, qt.IsNil(err))
	var d struct {
		Services json.RawMessage `json:"services"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(services, &d)))
	compact := `{"services":` + string(d.Services) +
		`,"products":[{"key":"suite","displayName":"Suite","gives":[{"service":"alpha","feature":"tasks"},{"service":"beta"}],"needs":[]}]}`
	var b bytes.Buffer
	qt.Assert(t, qt.IsNil(json.Compact(&b, []byte(compact))))
	qt.Assert(t, qt.Equals(string(c.body), indented(t, b.String())))
}

func TestAccountsOnlyNeedNoSet(t *testing.T) {
	a := Account{Product: "suite", DisplayName: "Suite account", Roles: []Level{{Service: "alpha", Group: "tasks", Level: "read"}}}
	c := firstCall(t, Config{Accounts: []Account{a}})
	qt.Assert(t, qt.Equals(c.scope, "declare-account:suite"))
	qt.Assert(t, qt.Equals(string(c.body), indented(t,
		`{"accounts":[{"product":"suite","displayName":"Suite account","roles":[{"service":"alpha","group":"tasks","level":"read"}]}]}`)))
}

func TestAnAccountWithNoLevelsSendsAnEmptyList(t *testing.T) {
	c := firstCall(t, Config{Accounts: []Account{{Product: "suite", DisplayName: "Suite account"}}})
	qt.Assert(t, qt.Equals(string(c.body), indented(t,
		`{"accounts":[{"product":"suite","displayName":"Suite account","roles":[]}]}`)))
}

func TestAProductAndAnAccountTogether(t *testing.T) {
	a := Account{Product: "suite", DisplayName: "Suite account", Roles: []Level{{Service: "alpha", Group: "tasks", Level: "read"}}}
	c := firstCall(t, Config{Products: []Product{suite()}, Accounts: []Account{a}})
	qt.Assert(t, qt.Equals(c.scope,
		"declare-account:suite declare-give:alpha declare-give:beta declare-product:suite"))
	qt.Assert(t, qt.Equals(string(c.body), indented(t,
		`{"products":[{"key":"suite","displayName":"Suite","gives":[{"service":"alpha","feature":"tasks"},{"service":"beta"}],"needs":["base"]}],`+
			`"accounts":[{"product":"suite","displayName":"Suite account","roles":[{"service":"alpha","group":"tasks","level":"read"}]}]}`)))
}

func TestProductsKeepTheGivenOrder(t *testing.T) {
	p := func(k string) Product {
		return Product{Key: k, DisplayName: k, Gives: []Give{{Service: "alpha"}}}
	}
	c := firstCall(t, Config{Products: []Product{p("zeta"), p("alpha"), p("mid")}})
	var d struct {
		Products []struct {
			Key string `json:"key"`
		} `json:"products"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(c.body, &d)))
	qt.Assert(t, qt.Equals(len(d.Products), 3))
	qt.Assert(t, qt.Equals(d.Products[0].Key, "zeta"))
	qt.Assert(t, qt.Equals(d.Products[1].Key, "alpha"))
	qt.Assert(t, qt.Equals(d.Products[2].Key, "mid"))
}

func word(n int) string { return "a" + strings.Repeat("b", n-1) }

func products(n int) []Product {
	out := make([]Product, n)
	for i := range out {
		out[i] = Product{Key: fmt.Sprintf("p%d", i), DisplayName: "P", Gives: []Give{{Service: "alpha"}}}
	}

	return out
}

func accounts(n int) []Account {
	out := make([]Account, n)
	for i := range out {
		out[i] = Account{Product: fmt.Sprintf("p%d", i), DisplayName: "A"}
	}

	return out
}

func gives(n int) []Give {
	out := make([]Give, n)
	for i := range out {
		out[i] = Give{Service: "alpha", Feature: fmt.Sprintf("f%d", i)}
	}

	return out
}

func needs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("n%d", i)
	}

	return out
}

func levels(n int) []Level {
	out := make([]Level, n)
	for i := range out {
		out[i] = Level{Service: "alpha", Group: "tasks", Level: fmt.Sprintf("l%d", i)}
	}

	return out
}

func oneProduct(mod func(*Product)) []Product {
	p := Product{Key: "suite", DisplayName: "Suite", Gives: []Give{{Service: "alpha"}}}
	mod(&p)

	return []Product{p}
}

func oneAccount(mod func(*Account)) []Account {
	a := Account{Product: "suite", DisplayName: "Suite account"}
	mod(&a)

	return []Account{a}
}

func TestProductAndAccountLimits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		products []Product
		accounts []Account
		ok       bool
	}{
		{"20 products", products(20), nil, true},
		{"21 products", products(21), nil, false},
		{"20 accounts", nil, accounts(20), true},
		{"21 accounts", nil, accounts(21), false},
		{"50 gives", oneProduct(func(p *Product) { p.Gives = gives(50) }), nil, true},
		{"51 gives", oneProduct(func(p *Product) { p.Gives = gives(51) }), nil, false},
		{"0 gives", oneProduct(func(p *Product) { p.Gives = nil }), nil, false},
		{"20 needs", oneProduct(func(p *Product) { p.Needs = needs(20) }), nil, true},
		{"21 needs", oneProduct(func(p *Product) { p.Needs = needs(21) }), nil, false},
		{"50 levels", nil, oneAccount(func(a *Account) { a.Roles = levels(50) }), true},
		{"51 levels", nil, oneAccount(func(a *Account) { a.Roles = levels(51) }), false},
		{"a product key of 64", oneProduct(func(p *Product) { p.Key = word(64) }), nil, true},
		{"a product key of 65", oneProduct(func(p *Product) { p.Key = word(65) }), nil, false},
		{"an empty product key", oneProduct(func(p *Product) { p.Key = "" }), nil, false},
		{"an upper-case product key", oneProduct(func(p *Product) { p.Key = "Suite" }), nil, false},
		{"a product key starting with a digit", oneProduct(func(p *Product) { p.Key = "1suite" }), nil, false},
		{"a give service of 64", oneProduct(func(p *Product) { p.Gives = []Give{{Service: word(64)}} }), nil, true},
		{"a give service of 65", oneProduct(func(p *Product) { p.Gives = []Give{{Service: word(65)}} }), nil, false},
		{"a needed key of 65", oneProduct(func(p *Product) { p.Needs = []string{word(65)} }), nil, false},
		{"an account product of 64", nil, oneAccount(func(a *Account) { a.Product = word(64) }), true},
		{"an account product of 65", nil, oneAccount(func(a *Account) { a.Product = word(65) }), false},
		{"a level service of 65", nil, oneAccount(func(a *Account) {
			a.Roles = []Level{{Service: word(65), Group: "tasks", Level: "read"}}
		}), false},
		{"a level group of 65", nil, oneAccount(func(a *Account) {
			a.Roles = []Level{{Service: "alpha", Group: word(65), Level: "read"}}
		}), false},
		{"a level name of 64", nil, oneAccount(func(a *Account) {
			a.Roles = []Level{{Service: "alpha", Group: "tasks", Level: word(64)}}
		}), true},
		{"a level name of 65", nil, oneAccount(func(a *Account) {
			a.Roles = []Level{{Service: "alpha", Group: "tasks", Level: word(65)}}
		}), false},
		{"a product display name of 200", oneProduct(func(p *Product) { p.DisplayName = strings.Repeat("x", 200) }), nil, true},
		{"a product display name of 201", oneProduct(func(p *Product) { p.DisplayName = strings.Repeat("x", 201) }), nil, false},
		{"a product display name of 200 wide characters", oneProduct(func(p *Product) { p.DisplayName = strings.Repeat("ž", 200) }), nil, true},
		{"a product display name of 201 wide characters", oneProduct(func(p *Product) { p.DisplayName = strings.Repeat("ž", 201) }), nil, false},
		{"an empty product display name", oneProduct(func(p *Product) { p.DisplayName = "" }), nil, false},
		{"a control character in a product display name", oneProduct(func(p *Product) { p.DisplayName = "Su\x07ite" }), nil, false},
		{"a new line in a product display name", oneProduct(func(p *Product) { p.DisplayName = "Su\nite" }), nil, false},
		{"a control character in a feature", oneProduct(func(p *Product) { p.Gives = []Give{{Service: "alpha", Feature: "ta\tsks"}} }), nil, false},
		{"an account display name of 200", nil, oneAccount(func(a *Account) { a.DisplayName = strings.Repeat("x", 200) }), true},
		{"an account display name of 201", nil, oneAccount(func(a *Account) { a.DisplayName = strings.Repeat("x", 201) }), false},
		{"an empty account display name", nil, oneAccount(func(a *Account) { a.DisplayName = "" }), false},
		{"a control character in an account display name", nil, oneAccount(func(a *Account) { a.DisplayName = "Su\x00ite" }), false},
		{"a product needing itself", oneProduct(func(p *Product) { p.Needs = []string{"suite"} }), nil, false},
		{"a product key twice", append(oneProduct(func(*Product) {}), oneProduct(func(*Product) {})...), nil, false},
		{"a give pair twice", oneProduct(func(p *Product) {
			p.Gives = []Give{{Service: "alpha", Feature: "tasks"}, {Service: "alpha", Feature: "tasks"}}
		}), nil, false},
		{"one service under two features", oneProduct(func(p *Product) {
			p.Gives = []Give{{Service: "alpha", Feature: "tasks"}, {Service: "alpha", Feature: "plans"}}
		}), nil, true},
		{"a level twice", nil, oneAccount(func(a *Account) {
			a.Roles = []Level{{Service: "alpha", Group: "tasks", Level: "read"}, {Service: "alpha", Group: "tasks", Level: "read"}}
		}), false},
		{"a product twice in accounts", nil, append(oneAccount(func(*Account) {}), oneAccount(func(*Account) {})...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(newFake(ok), "http://r:1", "a", Config{Products: tc.products, Accounts: tc.accounts})
			if tc.ok {
				qt.Assert(t, qt.IsNil(err))
			} else {
				qt.Assert(t, qt.IsNotNil(err))
			}
		})
	}
}

func TestNothingToDeclareIsStillRefused(t *testing.T) {
	_, err := New(newFake(ok), "http://r:1", "a", Config{})
	qt.Assert(t, qt.IsNotNil(err))
}

func TestAnInvalidProductIsRefusedBesideSets(t *testing.T) {
	_, err := New(newFake(ok), "http://r:1", "a",
		Config{Products: oneProduct(func(p *Product) { p.Needs = []string{"suite"} })}, sets(t, "alpha")...)
	qt.Assert(t, qt.IsNotNil(err))
}

func TestAWaitingAnswerIsSentAgainAfterTheLongestPauseNotTheRepeat(t *testing.T) {
	const longest, repeat = 20 * time.Millisecond, 600 * time.Millisecond
	waiting := `{"products":[{"key":"suite","status":"added"}],"accounts":[{"key":"suite","status":"waiting","reason":"level"}]}`
	f := newFake(func(_ context.Context, n int) (*authclient.BackgroundResponse, error) {
		body := waiting
		if n >= 2 {
			body = `{"products":[{"key":"suite","status":"added"}],"accounts":[{"key":"suite","status":"added"}]}`
		}

		return &authclient.BackgroundResponse{StatusCode: 200, Body: []byte(body)}, nil
	})
	var mu sync.Mutex
	var lines [][]Waiting
	var declared int
	task, err := New(f, "http://register:8080/", "svc:register", Config{
		FirstPause: time.Millisecond, LongestPause: longest, Repeat: repeat,
		Products:   []Product{suite()},
		Accounts:   []Account{{Product: "suite", DisplayName: "Suite account"}},
		OnDeclared: func([]byte) { mu.Lock(); declared++; mu.Unlock() },
		OnWaiting:  func(w []Waiting) { mu.Lock(); lines = append(lines, w); mu.Unlock() },
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(task.Stop)
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 4)
	task.Stop()

	calls := f.all()
	for i, atLeast := range []time.Duration{longest, longest, repeat} {
		gap := calls[i+1].at.Sub(calls[i].at)
		qt.Assert(t, qt.IsTrue(gap >= atLeast), qt.Commentf("gap %d was %s, want at least %s", i, gap, atLeast))
	}
	// The waiting answers came back after the short pause, not the repeat interval.
	for i := range 2 {
		gap := calls[i+1].at.Sub(calls[i].at)
		qt.Assert(t, qt.IsTrue(gap < repeat/2), qt.Commentf("gap %d was %s, the longest pause is %s", i, gap, longest))
	}
	mu.Lock()
	defer mu.Unlock()
	qt.Assert(t, qt.IsTrue(declared >= 3))
	qt.Assert(t, qt.Equals(len(lines), 2))
	qt.Assert(t, qt.DeepEquals(lines[0], []Waiting{{Kind: "account", Key: "suite", Reason: "level"}}))
}

func TestAWaitingProductLineAlsoWaits(t *testing.T) {
	got := waitingIn([]byte(`{"products":[{"key":"suite","status":"waiting","reason":"service"},{"key":"x","status":"unchanged"}]}`))
	qt.Assert(t, qt.DeepEquals(got, []Waiting{{Kind: "product", Key: "suite", Reason: "service"}}))
}

func TestAHostileWaitingLineIsNarrowedButStillWaits(t *testing.T) {
	long := strings.Repeat("a", 5000)
	body, err := json.Marshal(map[string]any{
		"products": []map[string]string{
			{"key": long, "status": "waiting", "reason": "service"},
			{"key": "line\nbreak", "status": "waiting", "reason": "level"},
			{"key": "suite", "status": "waiting", "reason": "something-else"},
			{"key": "Suite", "status": "waiting", "reason": strings.Repeat("r", 5000)},
		},
		"accounts": []map[string]string{
			{"key": "x y", "status": "waiting", "reason": "product"},
		},
	})
	qt.Assert(t, qt.IsNil(err))
	got := waitingIn(body)
	qt.Assert(t, qt.DeepEquals(got, []Waiting{
		{Kind: "product", Key: "", Reason: "service"},
		{Kind: "product", Key: "", Reason: "level"},
		{Kind: "product", Key: "suite", Reason: ""},
		{Kind: "product", Key: "", Reason: ""},
		{Kind: "account", Key: "", Reason: "product"},
	}))
}

func TestAnAnswerWithNothingWaitingReturnsToTheRepeat(t *testing.T) {
	for _, status := range []string{"added", "unchanged", "changed"} {
		got := waitingIn([]byte(`{"products":[{"key":"suite","status":"` + status + `"}]}`))
		qt.Assert(t, qt.Equals(len(got), 0))
	}
}

func TestAnUnparsableAnswerIsASuccessOnTheRepeat(t *testing.T) {
	f := newFake(func(context.Context, int) (*authclient.BackgroundResponse, error) {
		return &authclient.BackgroundResponse{StatusCode: 200, Body: []byte("not json")}, nil
	})
	// A longest pause of an hour would hold the second call back for the whole
	// wait, so a second call within the deadline shows the repeat interval ruled.
	task, err := New(f, "http://register:8080/", "svc:register", Config{
		FirstPause: time.Millisecond, LongestPause: time.Hour, Repeat: 10 * time.Millisecond,
		Products: []Product{suite()},
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(task.Stop)
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 2)
}

func TestAnAnswerOverTheReadLimitIsTakenAsNothingWaiting(t *testing.T) {
	body := `{"products":[{"key":"suite","status":"waiting"}]}` + strings.Repeat(" ", MaxAnswerBytes)
	qt.Assert(t, qt.Equals(len(waitingIn([]byte(body))), 0))
}

func TestAnAnswerOfSetsOnlyReturnsToTheRepeat(t *testing.T) {
	f := newFake(func(context.Context, int) (*authclient.BackgroundResponse, error) {
		return &authclient.BackgroundResponse{StatusCode: 200, Body: []byte(`{"services":[]}`)}, nil
	})
	task := newTask(t, f, Config{LongestPause: time.Hour, Repeat: 10 * time.Millisecond}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 2)
}
