package apikeys

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingDerive stands in for argon2id: cheap and deterministic, it records every call's cost
// parameters and can hold calls back so a test can fill the derive slots.
type countingDerive struct {
	mu    sync.Mutex
	calls []Params
	hold  chan struct{}
	held  chan struct{}
}

func (d *countingDerive) derive(secret, salt []byte, p Params, n uint32) []byte {
	d.mu.Lock()
	d.calls = append(d.calls, p)
	hold, held := d.hold, d.held
	d.mu.Unlock()

	if hold != nil {
		held <- struct{}{}
		<-hold
	}

	h := sha256.New()
	h.Write(secret)
	h.Write(salt)
	_ = binary.Write(h, binary.BigEndian, p)

	out := make([]byte, 0, n)
	for sum := h.Sum(nil); uint32(len(out)) < n; sum = h.Sum(sum[:0]) {
		out = append(out, sum...)
		h.Write(sum)
	}

	return out[:n]
}

func (d *countingDerive) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.calls)
}

func (d *countingDerive) last() Params {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.calls[len(d.calls)-1]
}

// memStore is a key store the way a service keeps one: a stored string per lookup part; a revoked
// or replaced key is simply not there.
type memStore struct {
	mu   sync.Mutex
	rows map[string]string
	err  error
	hits int
}

func newMemStore() *memStore { return &memStore{rows: map[string]string{}} }

func (m *memStore) lookup(_ context.Context, lookup string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.hits++
	if m.err != nil {
		return "", false, m.err
	}

	h, ok := m.rows[lookup]

	return h, ok, nil
}

func (m *memStore) put(k Minted) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rows[k.Lookup] = k.Hash
}

func (m *memStore) replace(old, k Minted) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.rows, old.Lookup)
	m.rows[k.Lookup] = k.Hash
}

func (m *memStore) lookups() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.hits
}

type fixture struct {
	scheme *Scheme
	derive *countingDerive
	store  *memStore
	v      *Verifier
}

// newFixture builds a scheme at the default parameters with the counting derive, a store and a
// verifier with a generous limit, so a test changes only what it is about.
func newFixture(t *testing.T, vc VerifierConfig) *fixture {
	t.Helper()

	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}

	d := &countingDerive{}
	s.derive = d.derive

	if vc.Limiter == nil {
		l, err := NewMemoryLimiter(LimitConfig{Attempts: 1000, Window: time.Minute, MaxCallers: 100})
		if err != nil {
			t.Fatalf("NewMemoryLimiter: %v", err)
		}

		vc.Limiter = l
	}

	st := newMemStore()

	v, err := s.NewVerifier(st.lookup, vc)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	return &fixture{scheme: s, derive: d, store: st, v: v}
}

func (f *fixture) mint(t *testing.T) Minted {
	t.Helper()

	k, err := f.scheme.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	return k
}

func TestRightKeyVerifiesWithOneDerive(t *testing.T) {
	f := newFixture(t, VerifierConfig{})
	k := f.mint(t)
	f.store.put(k)

	before := f.derive.count()

	res, err := f.v.Verify(context.Background(), "caller", k.Key.Reveal())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if res.Lookup != k.Lookup {
		t.Fatalf("result names lookup part %q, want %q", res.Lookup, k.Lookup)
	}

	if res.Rehash != "" {
		t.Fatal("a hash at the scheme's parameters was handed back for rehashing")
	}

	if n := f.derive.count() - before; n != 1 {
		t.Fatalf("%d derives, want 1", n)
	}
}

func TestWrongUnknownAndMalformedKeysAreRefusedWithTheSameWork(t *testing.T) {
	f := newFixture(t, VerifierConfig{})
	k := f.mint(t)
	f.store.put(k)

	other := f.mint(t) // never stored: its lookup part is unknown
	wrong := mutateSecret(t, f.scheme, k.Key.Reveal())

	for name, key := range map[string]string{
		"wrong secret":   wrong,
		"unknown lookup": other.Key.Reveal(),
		"malformed":      "not a key",
		"empty":          "",
	} {
		before := f.derive.count()

		_, err := f.v.Verify(context.Background(), "caller", key)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v, want ErrInvalid", name, err)
		}

		if n := f.derive.count() - before; n != 1 {
			t.Fatalf("%s: %d derives, want exactly 1", name, n)
		}

		if p := f.derive.last(); p != DefaultParams() {
			t.Fatalf("%s: derived at %+v, want the scheme's %+v", name, p, DefaultParams())
		}
	}
}

func TestWrongUnknownAndMalformedKeysTakeAlikeTime(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real argon2id derives")
	}

	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatal(err)
	}

	st := newMemStore()

	k, err := s.Mint()
	if err != nil {
		t.Fatal(err)
	}

	st.put(k)
	other, _ := s.Mint()

	v, err := s.NewVerifier(st.lookup, VerifierConfig{})
	if err != nil {
		t.Fatal(err)
	}

	median := func(key string) time.Duration {
		var runs []time.Duration

		for range 7 {
			start := time.Now()
			_, _ = v.Verify(context.Background(), "caller", key)
			runs = append(runs, time.Since(start))
		}

		slices.Sort(runs)

		return runs[len(runs)/2]
	}

	times := map[string]time.Duration{
		"wrong secret":   median(mutateSecret(t, s, k.Key.Reveal())),
		"unknown lookup": median(other.Key.Reveal()),
		"malformed":      median("not a key"),
	}

	fastest, slowest := time.Duration(1<<62), time.Duration(0)
	for _, d := range times {
		fastest, slowest = min(fastest, d), max(slowest, d)
	}

	// Coarse on purpose: the derive is the cost being equalised, and it dwarfs everything else.
	if slowest > 2*fastest {
		t.Fatalf("median times differ by more than twice: %v", times)
	}
}

func TestMalformedKeyMakesNoLookup(t *testing.T) {
	f := newFixture(t, VerifierConfig{})

	if _, err := f.v.Verify(context.Background(), "caller", "not a key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}

	if n := f.store.lookups(); n != 0 {
		t.Fatalf("%d lookups for a malformed key, want 0", n)
	}
}

func TestOverlongInputIsRefusedAsMalformed(t *testing.T) {
	f := newFixture(t, VerifierConfig{})
	k := f.mint(t)
	f.store.put(k)

	full := k.Key.Reveal()

	if _, err := f.v.Verify(context.Background(), "caller", full); err != nil {
		t.Fatalf("a key at the exact length refused: %v", err)
	}

	for name, key := range map[string]string{
		"one byte over": full + "A",
		"1 MiB":         full + strings.Repeat("A", 1<<20),
	} {
		before := f.derive.count()

		_, err := f.v.Verify(context.Background(), "caller", key)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v, want ErrInvalid", name, err)
		}

		if n := f.derive.count() - before; n != 1 {
			t.Fatalf("%s: %d derives, want the 1 every malformed key pays", name, n)
		}
	}
}

func TestDummyPathNeverSucceeds(t *testing.T) {
	f := newFixture(t, VerifierConfig{})
	unknown := f.mint(t)

	// Make every derive answer the dummy hash's own tag, as if the presented secret matched it.
	f.scheme.derive = func(_, _ []byte, _ Params, n uint32) []byte {
		return append([]byte(nil), f.scheme.dummy.tag[:n]...)
	}

	if _, err := f.v.Verify(context.Background(), "caller", unknown.Key.Reveal()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unknown key matching the dummy hash got %v, want ErrInvalid", err)
	}

	if _, err := f.v.Verify(context.Background(), "caller", "not a key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a malformed key matching the dummy hash got %v, want ErrInvalid", err)
	}
}

func TestRegeneratingLeavesOnlyTheNewestKey(t *testing.T) {
	f := newFixture(t, VerifierConfig{})

	first := f.mint(t)
	f.store.put(first)

	second := f.mint(t)
	f.store.replace(first, second)

	third := f.mint(t)
	f.store.replace(second, third)

	for name, k := range map[string]Minted{"first": first, "second": second} {
		if _, err := f.v.Verify(context.Background(), "caller", k.Key.Reveal()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s key after regeneration: got %v, want ErrInvalid", name, err)
		}
	}

	if _, err := f.v.Verify(context.Background(), "caller", third.Key.Reveal()); err != nil {
		t.Fatalf("newest key refused: %v", err)
	}

	if first.Lookup == third.Lookup || second.Lookup == third.Lookup {
		t.Fatal("a regenerated key reused an older lookup part")
	}
}

func TestLimitIsCheckedBeforeTheKey(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}

	l, err := NewMemoryLimiter(LimitConfig{Attempts: 3, Window: time.Minute, MaxCallers: 10, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}

	f := newFixture(t, VerifierConfig{Limiter: l})
	k := f.mint(t)
	f.store.put(k)

	// Successful attempts count too: the limit runs before the outcome is known.
	for i := 1; i <= 3; i++ {
		if _, err := f.v.Verify(context.Background(), "caller", k.Key.Reveal()); err != nil {
			t.Fatalf("attempt %d of 3: %v", i, err)
		}
	}

	derives, lookups := f.derive.count(), f.store.lookups()

	_, err = f.v.Verify(context.Background(), "caller", k.Key.Reveal())
	if !errors.Is(err, ErrLimited) {
		t.Fatalf("attempt 4 of 3: got %v, want ErrLimited", err)
	}

	if f.derive.count() != derives || f.store.lookups() != lookups {
		t.Fatal("a limited attempt still looked the key up or derived")
	}

	if after, ok := RetryAfter(err); !ok || after <= 0 {
		t.Fatalf("a limited attempt carries no retry delay (%v, %v)", after, ok)
	}

	if _, err := f.v.Verify(context.Background(), "other-caller", k.Key.Reveal()); err != nil {
		t.Fatalf("another caller limited: %v", err)
	}
}

func TestVerifierWithoutALimiterStillLimits(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatal(err)
	}

	s.derive = (&countingDerive{}).derive
	st := newMemStore()

	v, err := s.NewVerifier(st.lookup, VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	limit := DefaultLimitConfig().Attempts

	for i := 0; i < limit; i++ {
		if _, err := v.Verify(context.Background(), "caller", "not a key"); errors.Is(err, ErrLimited) {
			t.Fatalf("limited at attempt %d, before the default limit of %d", i+1, limit)
		}
	}

	if _, err := v.Verify(context.Background(), "caller", "not a key"); !errors.Is(err, ErrLimited) {
		t.Fatalf("attempt %d past the default limit: got %v, want ErrLimited", limit+1, err)
	}
}

func TestDeriveCapRefusesAtOnceWhenFull(t *testing.T) {
	f := newFixture(t, VerifierConfig{MaxDerives: 2})
	hold := make(chan struct{})
	f.derive.hold = hold
	f.derive.held = make(chan struct{}, 2)

	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := f.v.Verify(context.Background(), "caller", "not a key")
			results <- err
		}()
	}

	<-f.derive.held
	<-f.derive.held

	before := f.derive.count()

	_, err := f.v.Verify(context.Background(), "caller", "not a key")
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("a check past the cap: got %v, want ErrBusy", err)
	}

	if f.derive.count() != before {
		t.Fatal("a check refused as busy still derived")
	}

	if after, ok := RetryAfter(err); !ok || after <= 0 {
		t.Fatalf("a busy refusal carries no retry delay (%v, %v)", after, ok)
	}

	hold <- struct{}{}
	<-results

	f.derive.mu.Lock()
	f.derive.hold = nil
	f.derive.mu.Unlock()

	if _, err := f.v.Verify(context.Background(), "caller", "not a key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a check after a slot was freed: got %v, want ErrInvalid", err)
	}

	close(hold)
	<-results
}

func TestCancelledContextDerivesNothingAndFreesItsSlot(t *testing.T) {
	f := newFixture(t, VerifierConfig{MaxDerives: 1})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	before := f.derive.count()

	if _, err := f.v.Verify(ctx, "caller", "not a key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}

	if f.derive.count() != before {
		t.Fatal("a cancelled check derived")
	}

	for i := range 3 {
		if _, err := f.v.Verify(context.Background(), "caller", "not a key"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("check %d after the cancelled one: got %v, want ErrInvalid (slot leaked?)", i+1, err)
		}
	}
}

func TestStoreFailureIsNotAWrongKey(t *testing.T) {
	f := newFixture(t, VerifierConfig{})
	k := f.mint(t)
	f.store.put(k)
	f.store.err = errors.New("connection refused")

	before := f.derive.count()

	_, err := f.v.Verify(context.Background(), "caller", k.Key.Reveal())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}

	if errors.Is(err, ErrInvalid) {
		t.Fatal("a store failure reads as a wrong key")
	}

	if f.derive.count() != before {
		t.Fatal("a check whose lookup failed still derived")
	}
}

func TestStatusForEachRefusal(t *testing.T) {
	limited := &retryError{err: ErrLimited, after: time.Second}
	busy := &retryError{err: ErrBusy, after: time.Second}

	for _, c := range []struct {
		err  error
		want int
	}{
		{ErrInvalid, http.StatusUnauthorized},
		{limited, http.StatusTooManyRequests},
		{busy, http.StatusServiceUnavailable},
		{ErrStoredHash, http.StatusInternalServerError},
		{ErrUnavailable, http.StatusServiceUnavailable},
		{context.Canceled, http.StatusServiceUnavailable},
		{context.DeadlineExceeded, http.StatusServiceUnavailable},
		{errNoCaller, http.StatusInternalServerError},
	} {
		if got := HTTPStatus(c.err); got != c.want {
			t.Errorf("HTTPStatus(%v) = %d, want %d", c.err, got, c.want)
		}
	}

	for _, err := range []error{limited, busy} {
		if after, ok := RetryAfter(err); !ok || after != time.Second {
			t.Errorf("RetryAfter(%v) = %v, %v; want 1s, true", err, after, ok)
		}
	}

	if _, ok := RetryAfter(ErrInvalid); ok {
		t.Error("an invalid key carries a retry delay")
	}
}

// storedAt builds the stored string of key k at parameters p, the way a store would hold one made
// under other parameters.
func storedAt(t *testing.T, s *Scheme, k Minted, p Params) string {
	t.Helper()

	pk, err := s.parse(k.Key.Reveal())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	salt := make([]byte, saltLen)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	return s.hashWith(pk, salt, p)
}

func TestStoredParametersAreBounded(t *testing.T) {
	floor := Params{Memory: 19456, Iterations: 2, Parallelism: 1}
	ceiling := Params{Memory: 65536, Iterations: 4, Parallelism: 4}

	s, err := NewScheme(Config{Scheme: "tk", Params: floor, Floor: floor, Ceiling: ceiling})
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}

	d := &countingDerive{}
	s.derive = d.derive
	st := newMemStore()

	l, _ := NewMemoryLimiter(LimitConfig{Attempts: 1000, Window: time.Minute, MaxCallers: 10})

	v, err := s.NewVerifier(st.lookup, VerifierConfig{Limiter: l})
	if err != nil {
		t.Fatal(err)
	}

	k, err := s.Mint()
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		p    Params
		ok   bool
	}{
		{"at the floor", floor, true},
		{"memory one below the floor", Params{floor.Memory - 1, floor.Iterations, floor.Parallelism}, false},
		{"iterations one below the floor", Params{floor.Memory, floor.Iterations - 1, floor.Parallelism}, false},
		{"at the ceiling", ceiling, true},
		{"memory one above the ceiling", Params{ceiling.Memory + 1, ceiling.Iterations, ceiling.Parallelism}, false},
		{"iterations one above the ceiling", Params{ceiling.Memory, ceiling.Iterations + 1, ceiling.Parallelism}, false},
		{"parallelism one above the ceiling", Params{ceiling.Memory, ceiling.Iterations, ceiling.Parallelism + 1}, false},
		{"zero memory", Params{0, floor.Iterations, floor.Parallelism}, false},
		{"zero iterations", Params{floor.Memory, 0, floor.Parallelism}, false},
		{"zero parallelism", Params{floor.Memory, floor.Iterations, 0}, false},
	} {
		st.rows[k.Lookup] = storedAt(t, s, k, c.p)
		before := d.count()

		_, err := v.Verify(context.Background(), "caller", k.Key.Reveal())

		switch {
		case c.ok && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case !c.ok && !errors.Is(err, ErrStoredHash):
			t.Errorf("%s: got %v, want ErrStoredHash", c.name, err)
		case !c.ok && errors.Is(err, ErrInvalid):
			t.Errorf("%s: a refused stored string reads as a wrong key", c.name)
		}

		if !c.ok && d.count() > before && d.last() == c.p {
			t.Errorf("%s: derived at the refused parameters", c.name)
		}
	}
}

func TestBelowCurrentParametersHandsBackANewHash(t *testing.T) {
	old := Params{Memory: 19456, Iterations: 2, Parallelism: 1}
	current := Params{Memory: 47104, Iterations: 2, Parallelism: 1}

	ceiling := Params{Memory: 1 << 17, Iterations: 8, Parallelism: 4}

	s, err := NewScheme(Config{Scheme: "tk", Params: current, Floor: old, Ceiling: ceiling})
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}

	s.derive = (&countingDerive{}).derive
	st := newMemStore()
	l, _ := NewMemoryLimiter(LimitConfig{Attempts: 1000, Window: time.Minute, MaxCallers: 10})

	v, err := s.NewVerifier(st.lookup, VerifierConfig{Limiter: l})
	if err != nil {
		t.Fatal(err)
	}

	k, _ := s.Mint()

	mixed := Params{old.Memory, current.Iterations + 1, current.Parallelism}

	for _, c := range []struct {
		name   string
		p      Params
		rehash bool
		to     Params
	}{
		{"below the current", old, true, current},
		{"at the current", current, false, Params{}},
		{"above the current", Params{current.Memory * 2, current.Iterations, current.Parallelism}, false, Params{}},
		{"mixed: more iterations, less memory", mixed, true, Params{current.Memory, mixed.Iterations, current.Parallelism}},
	} {
		stored := storedAt(t, s, k, c.p)
		st.rows[k.Lookup] = stored

		res, err := v.Verify(context.Background(), "caller", k.Key.Reveal())
		if err != nil {
			t.Fatalf("%s: refused: %v", c.name, err)
		}

		if got := res.Rehash != ""; got != c.rehash {
			t.Fatalf("%s: rehash handed back = %v, want %v", c.name, got, c.rehash)
		}

		if c.rehash {
			if res.Replaces != stored {
				t.Fatalf("%s: the rehash names %q as what it replaces, want the stored string checked", c.name, res.Replaces)
			}

			if nst, err := s.decodeStored(res.Rehash); err != nil || nst.params != c.to {
				t.Fatalf("%s: rehashed to %+v (%v), want %+v: raised where below, never lowered", c.name, nst.params, err, c.to)
			}

			st.rows[k.Lookup] = res.Rehash

			again, err := v.Verify(context.Background(), "caller", k.Key.Reveal())
			if err != nil {
				t.Fatalf("%s: the handed-back hash does not verify: %v", c.name, err)
			}

			if again.Rehash != "" {
				t.Fatalf("%s: the handed-back hash asks to be rehashed again", c.name)
			}
		}
	}
}
