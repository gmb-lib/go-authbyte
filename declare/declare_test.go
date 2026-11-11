package declare

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-authbyte/permissions"
)

type call struct {
	at       time.Time
	audience string
	scope    string
	method   string
	url      string
	header   http.Header
	body     []byte
}

// fakeDoer records every call and answers from a script. No network.
type fakeDoer struct {
	mu    sync.Mutex
	calls []call
	// answer decides the n-th answer (from 0); it may block, and should return
	// when ctx ends.
	answer func(ctx context.Context, n int) (*authclient.BackgroundResponse, error)
	seen   chan struct{}
}

func newFake(answer func(ctx context.Context, n int) (*authclient.BackgroundResponse, error)) *fakeDoer {
	return &fakeDoer{answer: answer, seen: make(chan struct{}, 1024)}
}

func (f *fakeDoer) DoService(ctx context.Context, audience, scope, method, fullURL string,
	h http.Header, body []byte,
) (*authclient.BackgroundResponse, error) {
	f.mu.Lock()
	n := len(f.calls)
	f.calls = append(f.calls, call{time.Now(), audience, scope, method, fullURL, h.Clone(), body})
	f.mu.Unlock()
	f.seen <- struct{}{}

	return f.answer(ctx, n)
}

func (f *fakeDoer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.calls)
}

func (f *fakeDoer) all() []call {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]call(nil), f.calls...)
}

// waitCalls waits until the Doer has been called n times.
func (f *fakeDoer) waitCalls(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for f.count() < n {
		select {
		case <-f.seen:
		case <-deadline:
			t.Fatalf("waited for %d calls, saw %d", n, f.count())
		}
	}
}

func ok(_ context.Context, _ int) (*authclient.BackgroundResponse, error) {
	return &authclient.BackgroundResponse{StatusCode: 200, Body: []byte(`{"services":[]}`)}, nil
}

func status(code int, body string) func(context.Context, int) (*authclient.BackgroundResponse, error) {
	return func(context.Context, int) (*authclient.BackgroundResponse, error) {
		return &authclient.BackgroundResponse{StatusCode: code, Body: []byte(body)}, nil
	}
}

func sets(t *testing.T, keys ...string) []*permissions.Set {
	t.Helper()
	var out []*permissions.Set
	for _, k := range keys {
		s, err := permissions.New(k, "Service "+k, []permissions.Permission{
			{Feature: "task", Act: "view", Description: "View", Class: permissions.Ordinary, Plane: permissions.Object},
		})
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNil(s.AddLevels(permissions.Rung{Group: k, Level: "read"})))
		out = append(out, s)
	}

	return out
}

func newTask(t *testing.T, f *fakeDoer, cfg Config, keys ...string) *Task {
	t.Helper()
	task, err := New(f, "http://register:8080/", "svc:register", cfg, sets(t, keys...)...)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(task.Stop)

	return task
}

func TestNewRefusals(t *testing.T) {
	s := sets(t, "projects")
	f := newFake(ok)
	for _, tc := range []struct {
		name string
		do   Doer
		base string
		aud  string
		cfg  Config
		sets []*permissions.Set
	}{
		{"no client", nil, "http://r:1", "a", Config{}, s},
		{"a relative address", f, "register:8080", "a", Config{}, s},
		{"no address", f, "", "a", Config{}, s},
		{"no audience", f, "http://r:1", "", Config{}, s},
		{"no sets", f, "http://r:1", "a", Config{}, nil},
		{"a nil set", f, "http://r:1", "a", Config{}, []*permissions.Set{nil}},
		{"two sets under one key", f, "http://r:1", "a", Config{}, append(sets(t, "projects"), s...)},
		{"a negative pause", f, "http://r:1", "a", Config{FirstPause: -1}, s},
		{"a longest pause under the first", f, "http://r:1", "a", Config{FirstPause: time.Minute, LongestPause: time.Second}, s},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var do Doer
			if tc.do != nil {
				do = tc.do
			}
			_, err := New(do, tc.base, tc.aud, tc.cfg, tc.sets...)
			qt.Assert(t, qt.IsNotNil(err))
		})
	}
}

func TestZeroConfigTakesTheDefaults(t *testing.T) {
	task := newTask(t, newFake(ok), Config{}, "projects")
	qt.Assert(t, qt.Equals(task.cfg.FirstPause, DefaultFirstPause))
	qt.Assert(t, qt.Equals(task.cfg.LongestPause, DefaultLongestPause))
	qt.Assert(t, qt.Equals(task.cfg.Repeat, DefaultRepeat))
	qt.Assert(t, qt.Equals(task.Name(), TaskName))
}

func TestTheRequestAsksExactlyTheDocumentsScopes(t *testing.T) {
	f := newFake(ok)
	task := newTask(t, f, Config{Repeat: time.Hour}, "projects", "authority")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 1)

	c := f.all()[0]
	qt.Assert(t, qt.Equals(c.scope, "declare:authority declare:projects"))
	qt.Assert(t, qt.Equals(c.audience, "svc:register"))
	qt.Assert(t, qt.Equals(c.method, http.MethodPost))
	qt.Assert(t, qt.Equals(c.url, "http://register:8080/api/v1/declarations"))
	qt.Assert(t, qt.Equals(c.header.Get("Content-Type"), "application/json"))

	want, err := permissions.Declaration(sets(t, "projects", "authority")...)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(c.body), string(want)))
}

func TestStartReturnsAtOnceWhileTheRegisterDoesNotAnswer(t *testing.T) {
	release := make(chan struct{})
	f := newFake(func(ctx context.Context, n int) (*authclient.BackgroundResponse, error) {
		if n == 0 {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		return ok(ctx, n)
	})
	declared := make(chan []byte, 4)
	task := newTask(t, f, Config{Repeat: time.Hour, OnDeclared: func(a []byte) { declared <- a }}, "projects")

	returned := make(chan error, 1)
	go func() { returned <- task.Start(context.Background()) }()
	select {
	case err := <-returned:
		qt.Assert(t, qt.IsNil(err))
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return while the register did not answer")
	}
	f.waitCalls(t, 1) // the document is on its way, and the register has not answered
	select {
	case <-declared:
		t.Fatal("declared before the register answered")
	default:
	}

	close(release)
	select {
	case a := <-declared:
		qt.Assert(t, qt.Equals(string(a), `{"services":[]}`))
	case <-time.After(5 * time.Second):
		t.Fatal("the declaration was not reported once the register answered")
	}
}

func TestStartDoesNotFailWhenTheRegisterIsDown(t *testing.T) {
	f := newFake(func(ctx context.Context, n int) (*authclient.BackgroundResponse, error) {
		if n < 2 {
			return nil, errors.New("connection refused")
		}

		return ok(ctx, n)
	})
	var errs []error
	var mu sync.Mutex
	declared := make(chan struct{}, 1)
	task := newTask(t, f, Config{
		FirstPause: time.Millisecond, LongestPause: 5 * time.Millisecond, Repeat: time.Hour,
		OnError:    func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() },
		OnDeclared: func([]byte) { declared <- struct{}{} },
	}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	select {
	case <-declared:
	case <-time.After(5 * time.Second):
		t.Fatal("never declared")
	}
	mu.Lock()
	defer mu.Unlock()
	qt.Assert(t, qt.Equals(len(errs), 2))
}

func TestPausesGrowAndAreCapped(t *testing.T) {
	const first, longest = 10 * time.Millisecond, 40 * time.Millisecond
	for name, answer := range map[string]func(context.Context, int) (*authclient.BackgroundResponse, error){
		"a transport error": func(context.Context, int) (*authclient.BackgroundResponse, error) {
			return nil, errors.New("connection refused")
		},
		"a 503": status(503, ""),
		"a 429": status(429, ""),
		"a token the service was refused": func(context.Context, int) (*authclient.BackgroundResponse, error) {
			return nil, &authclient.Error{Hop: authclient.HopToken, Status: 500}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(answer)
			task := newTask(t, f, Config{FirstPause: first, LongestPause: longest, Repeat: time.Hour}, "projects")
			qt.Assert(t, qt.IsNil(task.Start(context.Background())))
			f.waitCalls(t, 7)
			task.Stop()

			calls := f.all()
			want := []time.Duration{first, 2 * first, longest, longest, longest, longest}
			for i, w := range want {
				gap := calls[i+1].at.Sub(calls[i].at)
				// A timer never fires early, so each gap is at least the pause.
				qt.Assert(t, qt.IsTrue(gap >= w), qt.Commentf("gap %d was %s, want at least %s", i, gap, w))
			}
			// Without the cap the sixth gap would be 320ms.
			last := calls[6].at.Sub(calls[5].at)
			qt.Assert(t, qt.IsTrue(last < 150*time.Millisecond), qt.Commentf("the last gap was %s, the cap is %s", last, longest))
		})
	}
}

func TestARefusalIsReportedOnceAndRetriedOnlyAfterTheLongestPause(t *testing.T) {
	const longest = 300 * time.Millisecond
	f := newFake(status(403, `{"code":"err:membership:forbidden","title":"Forbidden","detail":"authority is not granted"}`))
	var mu sync.Mutex
	var errs []error
	task := newTask(t, f, Config{
		FirstPause: 2 * time.Millisecond, LongestPause: longest, Repeat: time.Hour,
		OnError: func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() },
	}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 1)

	// A tight loop at the first pause would have made dozens of calls by now.
	time.Sleep(longest / 2)
	qt.Assert(t, qt.Equals(f.count(), 1))
	mu.Lock()
	qt.Assert(t, qt.Equals(len(errs), 1))
	var refused *Error
	qt.Assert(t, qt.IsTrue(errors.As(errs[0], &refused)))
	mu.Unlock()
	qt.Assert(t, qt.Equals(refused.Status, 403))
	qt.Assert(t, qt.Equals(refused.Code, "err:membership:forbidden"))
	qt.Assert(t, qt.Equals(refused.Detail, "authority is not granted"))
	qt.Assert(t, qt.StringContains(refused.Error(), "403"))
	qt.Assert(t, qt.StringContains(refused.Error(), "err:membership:forbidden"))

	f.waitCalls(t, 2)
	calls := f.all()
	qt.Assert(t, qt.IsTrue(calls[1].at.Sub(calls[0].at) >= longest))
}

func TestARefusalWithNoProblemBodyStillCarriesItsStatus(t *testing.T) {
	f := newFake(status(422, "not json"))
	got := make(chan error, 1)
	task := newTask(t, f, Config{LongestPause: time.Hour, Repeat: time.Hour, OnError: func(err error) { got <- err }}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	var refused *Error
	qt.Assert(t, qt.IsTrue(errors.As(<-got, &refused)))
	qt.Assert(t, qt.Equals(refused.Status, 422))
	qt.Assert(t, qt.Equals(refused.Code, ""))
}

func TestTheDocumentIsSentAgainAfterTheRepeatInterval(t *testing.T) {
	f := newFake(ok)
	task := newTask(t, f, Config{Repeat: 10 * time.Millisecond}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 3)
	calls := f.all()
	qt.Assert(t, qt.IsTrue(calls[1].at.Sub(calls[0].at) >= 10*time.Millisecond))
	qt.Assert(t, qt.Equals(string(calls[2].body), string(calls[0].body)))
}

func TestNoRequestIsMadeAfterStop(t *testing.T) {
	f := newFake(ok)
	task := newTask(t, f, Config{Repeat: time.Millisecond}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 3)
	task.Stop()
	n := f.count()
	time.Sleep(100 * time.Millisecond)
	qt.Assert(t, qt.Equals(f.count(), n))
	task.Stop() // a second Stop is harmless
}

func TestStopEndsALoopWaitingOnAnUnansweredRegister(t *testing.T) {
	f := newFake(func(ctx context.Context, _ int) (*authclient.BackgroundResponse, error) {
		<-ctx.Done()

		return nil, ctx.Err()
	})
	errs := make(chan error, 4)
	task := newTask(t, f, Config{OnError: func(err error) { errs <- err }}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 1)

	stopped := make(chan struct{})
	go func() { task.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not end the task")
	}
	qt.Assert(t, qt.Equals(len(errs), 0)) // a call ended by Stop is not a failure to report
}

func TestStopEndsALoopWaitingOutAPause(t *testing.T) {
	f := newFake(status(403, ""))
	task := newTask(t, f, Config{FirstPause: time.Millisecond, LongestPause: time.Hour}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	f.waitCalls(t, 1)
	time.Sleep(20 * time.Millisecond) // into the hour-long pause

	stopped := make(chan struct{})
	go func() { task.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not end the task")
	}
	qt.Assert(t, qt.Equals(f.count(), 1))
}

func TestACancelledStartContextEndsTheLoop(t *testing.T) {
	f := newFake(ok)
	ctx, cancel := context.WithCancel(context.Background())
	task := newTask(t, f, Config{Repeat: time.Millisecond}, "projects")
	qt.Assert(t, qt.IsNil(task.Start(ctx)))
	f.waitCalls(t, 2)
	cancel()
	task.Stop()
	n := f.count()
	time.Sleep(50 * time.Millisecond)
	qt.Assert(t, qt.Equals(f.count(), n))
}

func TestStartTwiceIsAnErrorAndStopWithoutStartIsHarmless(t *testing.T) {
	task := newTask(t, newFake(ok), Config{Repeat: time.Hour}, "projects")
	task.Stop()
	qt.Assert(t, qt.IsNil(task.Start(context.Background())))
	qt.Assert(t, qt.IsNotNil(task.Start(context.Background())))
}
