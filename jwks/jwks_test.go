package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// keySet serves a JWKS whose contents the test can swap, standing in for an
// issuer that rotates its signing key.
type keySet struct {
	mu    sync.Mutex
	kid   string
	pub   any
	hits  atomic.Int64
	fails bool
}

func newKeySet(t *testing.T, kid string) *keySet {
	t.Helper()

	return &keySet{kid: kid, pub: newPub(t)}
}

func newPub(t *testing.T) any {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return &k.PublicKey
}

func (s *keySet) rotate(t *testing.T, kid string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kid, s.pub = kid, newPub(t)
}

func (s *keySet) server(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)

		s.mu.Lock()
		defer s.mu.Unlock()

		if s.fails {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{KeyID: s.kid, Key: s.pub, Algorithm: "ES256", Use: "sig"}},
		})
	}))
	t.Cleanup(srv.Close)

	return srv
}

// The regression this package exists to prevent: a key rotated in while the
// cache is still INSIDE its TTL must be picked up. Before the fix, refresh()
// decided whether to fetch by looking at the cache's age, so a young cache
// short-circuited the very refresh an unknown kid had just asked for — and the
// consumer rejected every token signed by the new key until it was restarted.
func TestKey_UnknownKidRefreshesEvenWhileCacheIsFresh(t *testing.T) {
	t.Parallel()

	ks := newKeySet(t, "kid-1")
	srv := ks.server(t)

	c := New(srv.URL, time.Hour) // TTL far longer than the test
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	if _, err := c.Key(context.Background(), "kid-1"); err != nil {
		t.Fatalf("warm the cache: %v", err)
	}

	if got := ks.hits.Load(); got != 1 {
		t.Fatalf("expected 1 fetch to warm the cache, got %d", got)
	}

	ks.rotate(t, "kid-2")

	// The cache is nowhere near its TTL, but kid-2 is unknown: fetch anyway.
	// Time advances past the rate limit so this is not the throttled path.
	c.now = func() time.Time { return time.Unix(1_700_000_060, 0) }

	if _, err := c.Key(context.Background(), "kid-2"); err != nil {
		t.Fatalf("rotated key must resolve without a restart, got: %v", err)
	}

	if got := ks.hits.Load(); got != 2 {
		t.Fatalf("expected exactly 1 refetch for the unknown kid, got %d fetches total", got)
	}
}

func TestKey_UnknownKidIsRateLimited(t *testing.T) {
	t.Parallel()

	ks := newKeySet(t, "kid-1")
	srv := ks.server(t)

	now := time.Unix(1_700_000_000, 0)
	c := New(srv.URL, time.Hour, WithMinRefreshInterval(30*time.Second))
	c.now = func() time.Time { return now }

	if _, err := c.Key(context.Background(), "kid-1"); err != nil {
		t.Fatalf("warm the cache: %v", err)
	}

	now = now.Add(31 * time.Second)

	// First unknown kid: one fetch.
	if _, err := c.Key(context.Background(), "nope-1"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}

	after := ks.hits.Load()
	if after != 2 {
		t.Fatalf("first unknown kid should fetch once (2 total), got %d", after)
	}

	// More unknown kids inside the window: no further traffic at the issuer.
	now = now.Add(5 * time.Second)

	for _, kid := range []string{"nope-2", "nope-3", "nope-4"} {
		if _, err := c.Key(context.Background(), kid); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("want ErrUnknownKey for %s, got %v", kid, err)
		}
	}

	if got := ks.hits.Load(); got != after {
		t.Fatalf("unknown kids inside the window must not refetch: %d -> %d", after, got)
	}

	// Once the window passes, one more attempt is allowed.
	now = now.Add(31 * time.Second)

	if _, err := c.Key(context.Background(), "nope-5"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}

	if got := ks.hits.Load(); got != after+1 {
		t.Fatalf("expected one fetch after the window reopened, got %d", got)
	}
}

// A cache hit must never reach the network — validation stays off the hot path.
func TestKey_CachedKidDoesNotFetch(t *testing.T) {
	t.Parallel()

	ks := newKeySet(t, "kid-1")
	srv := ks.server(t)

	c := New(srv.URL, time.Hour)
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	for range 5 {
		if _, err := c.Key(context.Background(), "kid-1"); err != nil {
			t.Fatalf("cached lookup: %v", err)
		}
	}

	if got := ks.hits.Load(); got != 1 {
		t.Fatalf("cached kid must not refetch, got %d fetches", got)
	}
}

// A failing issuer is rate-limited too: attempts are throttled, not just
// successes, so an outage upstream does not turn into a request storm.
func TestKey_FailingIssuerIsThrottledAndSurfaced(t *testing.T) {
	t.Parallel()

	ks := newKeySet(t, "kid-1")
	ks.fails = true
	srv := ks.server(t)

	now := time.Unix(1_700_000_000, 0)
	c := New(srv.URL, time.Hour, WithMinRefreshInterval(30*time.Second))
	c.now = func() time.Time { return now }

	if _, err := c.Key(context.Background(), "kid-1"); err == nil {
		t.Fatal("a failing issuer must surface an error, not a silent miss")
	}

	if got := ks.hits.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}

	now = now.Add(5 * time.Second)

	if _, err := c.Key(context.Background(), "kid-1"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("throttled retry reports the kid as unknown, got %v", err)
	}

	if got := ks.hits.Load(); got != 1 {
		t.Fatalf("a failing fetch must be throttled too, got %d attempts", got)
	}
}

// Concurrent misses collapse into one fetch: the de-duplication is on the cache
// stamp, so goroutines queued behind the lock take the winner's result.
func TestKey_ConcurrentMissesFetchOnce(t *testing.T) {
	t.Parallel()

	ks := newKeySet(t, "kid-1")
	srv := ks.server(t)

	c := New(srv.URL, time.Hour)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, _ = c.Key(context.Background(), "kid-1")
		}()
	}

	wg.Wait()

	if got := ks.hits.Load(); got != 1 {
		t.Fatalf("concurrent cold misses must collapse to one fetch, got %d", got)
	}
}
