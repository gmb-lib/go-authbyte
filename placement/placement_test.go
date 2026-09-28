package placement

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/permissions"
)

// fakeSource is the register: one answer per tenant, and every call recorded.
type fakeSource struct {
	mu       sync.Mutex
	defs     map[string]Definitions
	fail     error
	unknown  []string
	asked    []string // "tenant@version" per Definitions call
	reported []map[string]int
	called   chan string
}

func (f *fakeSource) Definitions(_ context.Context, tenant, version string) (Definitions, bool, error) {
	f.mu.Lock()
	defer func() {
		f.mu.Unlock()
		if f.called != nil {
			f.called <- tenant
		}
	}()
	f.asked = append(f.asked, tenant+"@"+version)
	if f.fail != nil {
		return Definitions{}, false, f.fail
	}
	d := f.defs[tenant]
	if version != "" && version == d.Version {
		return Definitions{}, false, nil
	}

	return d, true, nil
}

func (f *fakeSource) Report(_ context.Context, _ string, counts map[string]int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reported = append(f.reported, maps.Clone(counts))

	return f.unknown, nil
}

// fakeStore keeps copies and counts in memory.
type fakeStore struct {
	mu        sync.Mutex
	tenants   []string
	copies    map[string]Definitions
	confirmed map[string]time.Time
	counts    map[string]map[string]int
	replaced  int
}

func newStore(tenants ...string) *fakeStore {
	return &fakeStore{
		tenants:   tenants,
		copies:    map[string]Definitions{},
		confirmed: map[string]time.Time{},
		counts:    map[string]map[string]int{},
	}
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

func (s *fakeStore) Replace(_ context.Context, tenant string, d Definitions, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.copies[tenant] = d
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

func (s *fakeStore) Counts(_ context.Context, tenant string) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return maps.Clone(s.counts[tenant]), nil
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

func roles(version string, keys ...string) Definitions {
	return Definitions{Version: version, Roles: []Role{{ID: "r1", Name: "Manager", Keys: keys}}}
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

func TestSyncCopiesTheRolesAndReportsTheCountsTheFirstTime(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	src := &fakeSource{defs: map[string]Definitions{"t1": roles(`"v1"`, "projects/task:edit")}}
	st := newStore("t1")
	k := keeper(t, src, st, c)

	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	qt.Check(t, qt.DeepEquals(src.asked, []string{"t1@"}))
	qt.Check(t, qt.Equals(st.copies["t1"].Version, `"v1"`))
	qt.Check(t, qt.Equals(st.confirmed["t1"], c.now()))
	qt.Check(t, qt.Equals(st.replaced, 1))
	// Nothing placed yet is still a report: the register learns this service holds none.
	qt.Check(t, qt.DeepEquals(src.reported, []map[string]int{{}}))
}

func TestAnUnchangedAnswerOnlyMovesTheConfirmation(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	src := &fakeSource{defs: map[string]Definitions{"t1": roles(`"v1"`, "projects/task:edit")}}
	st := newStore("t1")
	k := keeper(t, src, st, c)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	c.add(10 * time.Second)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	qt.Check(t, qt.DeepEquals(src.asked, []string{"t1@", `t1@"v1"`}))
	qt.Check(t, qt.Equals(st.replaced, 1))
	qt.Check(t, qt.Equals(st.confirmed["t1"], c.now()))
	qt.Check(t, qt.HasLen(src.reported, 1)) // the counts did not move, so nothing is sent again
}

func TestAChangedRoleReplacesTheCopy(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	src := &fakeSource{defs: map[string]Definitions{"t1": roles(`"v1"`, "projects/task:edit")}}
	st := newStore("t1")
	k := keeper(t, src, st, c)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	src.defs["t1"] = roles(`"v2"`)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	qt.Check(t, qt.Equals(st.replaced, 2))
	qt.Check(t, qt.Equals(st.copies["t1"].Version, `"v2"`))
	qt.Check(t, qt.HasLen(st.copies["t1"].Roles[0].Keys, 0))
}

func TestCountsAreReportedWhenTheyChange(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	src := &fakeSource{defs: map[string]Definitions{"t1": roles(`"v1"`)}}
	st := newStore("t1")
	k := keeper(t, src, st, c)
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	st.counts["t1"] = map[string]int{"r1": 2}
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))
	qt.Assert(t, qt.IsNil(k.Sync(context.Background(), "t1")))

	qt.Check(t, qt.DeepEquals(src.reported, []map[string]int{{}, {"r1": 2}}))
}

func TestAPlacedRoleTheTenantDeletedIsSaid(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	src := &fakeSource{defs: map[string]Definitions{"t1": roles(`"v1"`)}, unknown: []string{"gone"}}
	st := newStore("t1")
	st.counts["t1"] = map[string]int{"gone": 1}
	k := keeper(t, src, st, c)

	err := k.Sync(context.Background(), "t1")

	qt.Check(t, qt.ErrorMatches(err, `.*no longer has: gone`))
	qt.Check(t, qt.Equals(st.confirmed["t1"], c.now())) // the copy itself is current
}

func TestAnUnreachableRegisterKeepsTheCopyAndStopsTrustingItAfterTheWindow(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	src := &fakeSource{defs: map[string]Definitions{"t1": roles(`"v1"`, "projects/task:edit")}}
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
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	k := keeper(t, &fakeSource{defs: map[string]Definitions{}}, newStore(), c)

	qt.Check(t, qt.ErrorMatches(k.Ready(), `.*have not been read yet`))
	k.cycle(context.Background())
	qt.Check(t, qt.IsNil(k.Ready()))
}

func TestTrustedSinceIsTheWindowBeforeNow(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	k := keeper(t, &fakeSource{}, newStore(), c)

	qt.Check(t, qt.Equals(k.TrustedSince(), c.now().Add(-time.Minute)))
}

func TestAFailedCycleIsToldAndTheOthersStillRun(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	src := &fakeSource{defs: map[string]Definitions{"t1": roles(`"v1"`), "t2": roles(`"v9"`)}}
	st := newStore("t0", "t1", "t2")
	st.counts["t0"] = nil

	var mu sync.Mutex
	var failed []string
	k, err := New(src, st, Config{Interval: time.Second, TrustWindow: time.Minute, Now: c.now,
		OnError: func(tenant string, _ error) {
			mu.Lock()
			failed = append(failed, tenant)
			mu.Unlock()
		}})
	qt.Assert(t, qt.IsNil(err))
	// t0 has no roles in the register: an empty answer is not a failure, only a copy with nothing in it.
	src.defs["t0"] = Definitions{Version: `"v0"`}

	k.cycle(context.Background())

	qt.Check(t, qt.HasLen(failed, 0))
	qt.Check(t, qt.Equals(st.copies["t2"].Version, `"v9"`))

	src.fail = errors.New("down")
	k.cycle(context.Background())
	qt.Check(t, qt.DeepEquals(failed, []string{"t0", "t1", "t2"}))
}

func TestWakeReadsANewTenantAtOnce(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	src := &fakeSource{defs: map[string]Definitions{"new": roles(`"v1"`)}, called: make(chan string, 8)}
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

	// The copy is written just after the answer arrives, so wait for it.
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

func TestKeysHoldOnlyTheExactPermission(t *testing.T) {
	set := permissions.MustNew("projects", "Test", []permissions.Permission{
		{Feature: "task", Act: "edit", Description: "Edit a task",
			Class: permissions.Ordinary, Plane: permissions.Object},
		{Feature: "task", Act: "editOwn", Description: "Edit your own task",
			Class: permissions.Ordinary, Plane: permissions.Object},
	})
	keys := Keys{"projects/task:editOwn"}

	qt.Check(t, qt.IsTrue(keys.Holds(set.Declared("task", "editOwn"))))
	qt.Check(t, qt.IsFalse(keys.Holds(set.Declared("task", "edit"))))
}
