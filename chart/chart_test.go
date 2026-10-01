package chart

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// fakeSource is the register: one chart per tenant, and every call recorded.
type fakeSource struct {
	mu     sync.Mutex
	charts map[string]Chart
	fail   error
	asked  []string // "tenant@version" per Chart call
	called chan string
}

func (f *fakeSource) Chart(_ context.Context, tenant, version string) (Chart, bool, error) {
	f.mu.Lock()
	defer func() {
		f.mu.Unlock()
		if f.called != nil {
			f.called <- tenant
		}
	}()
	f.asked = append(f.asked, tenant+"@"+version)
	if f.fail != nil {
		return Chart{}, false, f.fail
	}
	c := f.charts[tenant]
	if version != "" && version == c.Version {
		return Chart{}, false, nil
	}

	return c, true, nil
}

// fakeStore keeps copies in memory.
type fakeStore struct {
	mu        sync.Mutex
	tenants   []string
	copies    map[string]Chart
	confirmed map[string]time.Time
	replaced  int
}

func newStore(tenants ...string) *fakeStore {
	return &fakeStore{tenants: tenants, copies: map[string]Chart{}, confirmed: map[string]time.Time{}}
}

func (s *fakeStore) Tenants(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.tenants...), nil
}

func (s *fakeStore) Version(_ context.Context, tenant string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.copies[tenant].Version, nil
}

func (s *fakeStore) Replace(_ context.Context, tenant string, c Chart, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.copies[tenant] = c
	s.confirmed[tenant] = at
	s.replaced++

	return nil
}

func (s *fakeStore) Confirm(_ context.Context, tenant string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.confirmed[tenant] = at

	return nil
}

// clock is a settable time.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func start() *clock { return &clock{t: time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)} }

func tree(version string, below map[string][]string) Chart {
	return Chart{Version: version, Below: below}
}

func keeper(t *testing.T, src Source, st Store, c *clock) *Keeper {
	t.Helper()
	k, err := New(src, st, Config{Interval: time.Second, TrustWindow: time.Minute, Now: c.now})
	qt.Assert(t, qt.IsNil(err))

	return k
}

func TestNewRefusesWhatCannotWork(t *testing.T) {
	st, src := newStore(), &fakeSource{}

	_, err := New(nil, st, Config{})
	qt.Check(t, qt.ErrorMatches(err, `.*a source and a store are required`))
	_, err = New(src, nil, Config{})
	qt.Check(t, qt.ErrorMatches(err, `.*a source and a store are required`))
	_, err = New(src, st, Config{Interval: -time.Second})
	qt.Check(t, qt.ErrorMatches(err, `.*cannot be negative`))
	_, err = New(src, st, Config{Interval: time.Minute, TrustWindow: time.Minute})
	qt.Check(t, qt.ErrorMatches(err, `.*must be longer than the interval.*`))

	k, err := New(src, st, Config{})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(k.cfg.Interval, DefaultInterval))
	qt.Check(t, qt.Equals(k.cfg.TrustWindow, DefaultTrustWindow))
}

func TestSyncCopiesTheChart(t *testing.T) {
	c := start()
	src := &fakeSource{charts: map[string]Chart{"t1": tree(`"v1"`, map[string][]string{"sub:a": {"sub:b"}})}}
	st := newStore("t1")
	k := keeper(t, src, st, c)

	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	qt.Check(t, qt.DeepEquals(src.asked, []string{"t1@"}))
	qt.Check(t, qt.DeepEquals(st.copies["t1"].Below, map[string][]string{"sub:a": {"sub:b"}}))
	qt.Check(t, qt.Equals(st.confirmed["t1"], c.now()))
	qt.Check(t, qt.Equals(st.replaced, 1))
}

func TestAnUnchangedAnswerOnlyMovesTheConfirmation(t *testing.T) {
	c := start()
	src := &fakeSource{charts: map[string]Chart{"t1": tree(`"v1"`, nil)}}
	st := newStore("t1")
	k := keeper(t, src, st, c)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	c.add(10 * time.Second)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	qt.Check(t, qt.DeepEquals(src.asked, []string{"t1@", `t1@"v1"`}))
	qt.Check(t, qt.Equals(st.replaced, 1))
	qt.Check(t, qt.Equals(st.confirmed["t1"], c.now()))
}

// A move in the chart replaces the copy whole, and a chart emptied is a copy with
// nobody below anyone.
func TestAMoveReplacesTheCopy(t *testing.T) {
	c := start()
	src := &fakeSource{charts: map[string]Chart{"t1": tree(`"v1"`, map[string][]string{"sub:a": {"sub:b", "sub:c"}})}}
	st := newStore("t1")
	k := keeper(t, src, st, c)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	src.charts["t1"] = tree(`"v2"`, map[string][]string{"sub:a": {"sub:b"}})
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))
	qt.Check(t, qt.Equals(st.replaced, 2))
	qt.Check(t, qt.DeepEquals(st.copies["t1"].Below["sub:a"], []string{"sub:b"}))

	src.charts["t1"] = tree(`"v3"`, nil)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))
	qt.Check(t, qt.HasLen(st.copies["t1"].Below, 0))
}

func TestAnUnreachableRegisterKeepsTheCopyAndStopsTrustingItAfterTheWindow(t *testing.T) {
	c := start()
	src := &fakeSource{charts: map[string]Chart{"t1": tree(`"v1"`, map[string][]string{"sub:a": {"sub:b"}})}}
	st := newStore("t1")
	k := keeper(t, src, st, c)
	k.cycle(context.Background())
	confirmedAt := c.now()
	qt.Assert(t, qt.IsNil(k.Ready()))

	src.fail = errors.New("connection refused")
	c.add(30 * time.Second)
	qt.Check(t, qt.ErrorMatches(k.Sync(context.Background(), "t1"), `.*connection refused`))
	qt.Check(t, qt.Equals(st.copies["t1"].Version, `"v1"`))
	qt.Check(t, qt.Equals(st.confirmed["t1"], confirmedAt))
	qt.Check(t, qt.IsNil(k.Ready())) // still inside the window
	qt.Check(t, qt.IsFalse(confirmedAt.Before(k.TrustedSince())))

	c.add(31 * time.Second)
	qt.Check(t, qt.IsTrue(confirmedAt.Before(k.TrustedSince())))
	qt.Check(t, qt.ErrorMatches(k.Ready(), `.*1 tenant\(s\) are not confirmed: t1`))

	src.fail = nil
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))
	qt.Check(t, qt.IsNil(k.Ready()))
}

func TestReadyWaitsForTheFirstCycle(t *testing.T) {
	k := keeper(t, &fakeSource{charts: map[string]Chart{}}, newStore(), start())

	qt.Check(t, qt.ErrorMatches(k.Ready(), `.*have not been read yet`))
	k.cycle(context.Background())
	qt.Check(t, qt.IsNil(k.Ready()))
}

func TestTrustedSinceIsTheWindowBeforeNow(t *testing.T) {
	c := start()
	k := keeper(t, &fakeSource{}, newStore(), c)

	qt.Check(t, qt.Equals(k.TrustedSince(), c.now().Add(-time.Minute)))
}

func TestAFailedCycleIsToldAndTheOthersStillRun(t *testing.T) {
	c := start()
	src := &fakeSource{charts: map[string]Chart{"t1": tree(`"v1"`, nil), "t2": tree(`"v9"`, nil)}}
	st := newStore("t0", "t1", "t2")
	src.charts["t0"] = tree(`"v0"`, nil)

	var mu sync.Mutex
	var failed []string
	k, err := New(src, st, Config{Interval: time.Second, TrustWindow: time.Minute, Now: c.now,
		OnError: func(tenant string, _ error) {
			mu.Lock()
			failed = append(failed, tenant)
			mu.Unlock()
		}})
	qt.Assert(t, qt.IsNil(err))

	k.cycle(context.Background())
	qt.Check(t, qt.HasLen(failed, 0))
	qt.Check(t, qt.Equals(st.copies["t2"].Version, `"v9"`))

	src.fail = errors.New("down")
	k.cycle(context.Background())
	qt.Check(t, qt.DeepEquals(failed, []string{"t0", "t1", "t2"}))
}

func TestWakeReadsANewTenantAtOnce(t *testing.T) {
	c := start()
	src := &fakeSource{charts: map[string]Chart{"new": tree(`"v1"`, nil)}, called: make(chan string, 8)}
	st := newStore()
	k, err := New(src, st, Config{Interval: time.Hour, TrustWindow: 2 * time.Hour, Now: c.now})
	qt.Assert(t, qt.IsNil(err))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	k.Wake("new")
	select {
	case got := <-src.called:
		qt.Check(t, qt.Equals(got, "new"))
	case <-time.After(5 * time.Second):
		t.Fatal("the woken tenant was not read")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		st.mu.Lock()
		v := st.copies["new"].Version
		st.mu.Unlock()
		if v == `"v1"` || time.Now().After(deadline) {
			qt.Check(t, qt.Equals(v, `"v1"`))

			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	qt.Check(t, qt.IsNil(<-done))
	qt.Check(t, qt.IsNil(k.Ready()))

	k.Wake("") // an empty tenant is ignored rather than queued
}
