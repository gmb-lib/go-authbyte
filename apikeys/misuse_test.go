package apikeys

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmptyCallerIsRefused(t *testing.T) {
	f := newFixture(t, VerifierConfig{})
	k := f.mint(t)
	f.store.put(k)

	derives := f.derive.count()

	_, err := f.v.Verify(context.Background(), "", k.Key.Reveal())
	if !errors.Is(err, errNoCaller) {
		t.Fatalf("got %v, want the empty-caller refusal", err)
	}

	if f.derive.count() != derives || f.store.lookups() != 0 {
		t.Fatal("a check with no caller still looked up or derived")
	}
}

func TestRaisingParamsKeepsExistingKeysWorking(t *testing.T) {
	old, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatal(err)
	}

	d := &countingDerive{}
	old.derive = d.derive

	k, err := old.Mint()
	if err != nil {
		t.Fatal(err)
	}

	// The service raises its parameters and names no floor.
	raised, err := NewScheme(Config{Scheme: "tk", Params: Params{Memory: 47104, Iterations: 2, Parallelism: 1}})
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}

	raised.derive = d.derive
	st := newMemStore()
	st.put(k)

	v, err := raised.NewVerifier(st.lookup, VerifierConfig{})
	if err != nil {
		t.Fatal(err)
	}

	res, err := v.Verify(context.Background(), "caller", k.Key.Reveal())
	if err != nil {
		t.Fatalf("a key minted before the parameters were raised is refused: %v", err)
	}

	if res.Rehash == "" {
		t.Fatal("a key below the raised parameters handed back no rehash")
	}
}

func TestLimiterTellsLongCallersApartByTheirWholeName(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := newTestLimiter(t, 1, 10, c)

	long := strings.Repeat("x", 1<<16)

	if ok, _ := l.Allow(long + "a"); !ok {
		t.Fatal("first long caller refused")
	}

	if ok, _ := l.Allow(long + "b"); !ok {
		t.Fatal("a second long caller, different only at its end, shares the first one's limit")
	}

	if ok, _ := l.Allow(long + "a"); ok {
		t.Fatal("the first long caller was not limited on its second attempt")
	}
}

// Many checks at once, with the cache on, the store changing under them and the limiter shared:
// run with the race detector, this is where a data race would show.
func TestConcurrentChecksAreSafe(t *testing.T) {
	f := newFixture(t, VerifierConfig{CacheTTL: time.Minute, CacheSize: 8, MaxDerives: 4})

	keys := make([]Minted, 6)
	for i := range keys {
		keys[i] = f.mint(t)
		f.store.put(keys[i])
	}

	var wg sync.WaitGroup

	for g := range 16 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range 50 {
				k := keys[(g+i)%len(keys)]
				key := k.Key.Reveal()

				if i%7 == 0 {
					key = "not a key"
				}

				_, err := f.v.Verify(context.Background(), "caller-"+strconv.Itoa(g%3), key)
				if err != nil && !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrLimited) {
					t.Errorf("unexpected error: %v", err)
				}

				if i%10 == 0 {
					if next, err := f.scheme.Mint(); err == nil {
						f.store.replace(k, next)
						f.store.put(k)
					}
				}
			}
		}()
	}

	wg.Wait()
}
