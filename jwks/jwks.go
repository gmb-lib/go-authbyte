// Package jwks provides a caching client for an Identity/Auth JWKS endpoint.
// Public signing keys are cached per pod and refreshed on a TTL; a request for
// an unknown `kid` triggers an out-of-band refresh (fail-closed if it stays
// unknown, and rate-limited so unknown kids cannot be used to generate traffic
// at the issuer). Validation never blocks on a network call once the cache is
// warm.
//
// The unknown-kid refresh is what lets a signing-key rotation take effect
// without restarting every consumer: the issuer publishes the new key, the first
// token carrying it misses the cache, and the fetch that follows picks it up.
package jwks

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ErrUnknownKey is returned when no key matches the requested kid even after a
// refresh.
var ErrUnknownKey = errors.New("jwks: no key for kid")

// DefaultMinRefreshInterval bounds how often an unknown kid may cause a fetch.
// Without it, tokens carrying made-up kids would let any caller drive traffic at
// the issuer; with it, an unrecognised kid costs at most one fetch per interval
// and a genuine key rotation is picked up within that long.
const DefaultMinRefreshInterval = 30 * time.Second

// Client fetches and caches a JWKS document.
type Client struct {
	url         string
	ttl         time.Duration
	minInterval time.Duration
	http        *http.Client
	now         func() time.Time

	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client used to fetch the JWKS.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithMinRefreshInterval overrides how often an unknown kid may trigger a fetch.
// Lower values shorten the window during which a rotated key is rejected; higher
// values give the issuer more protection from unknown-kid traffic.
func WithMinRefreshInterval(d time.Duration) Option {
	return func(c *Client) { c.minInterval = d }
}

// New returns a JWKS client for the given endpoint and cache TTL.
func New(jwksURL string, ttl time.Duration, opts ...Option) *Client {
	c := &Client{
		url:         jwksURL,
		ttl:         ttl,
		minInterval: DefaultMinRefreshInterval,
		http:        &http.Client{Timeout: 10 * time.Second},
		now:         time.Now,
		keys:        make(map[string]crypto.PublicKey),
	}

	for _, o := range opts {
		o(c)
	}

	return c
}

// Key returns the public key for kid, refreshing the cache if the kid is
// unknown or the cache has expired.
func (c *Client) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if k, ok := c.cached(kid); ok {
		return k, nil
	}

	// Record which version of the cache we based that miss on, so refresh can
	// tell "nobody has fetched since I looked" from "another goroutine already
	// fetched while I waited for the lock". Deciding that on the cache's AGE
	// instead is what made an unknown kid unrecoverable: a cache still inside its
	// TTL looked fresh, so the refresh short-circuited and the key that had just
	// been rotated in was never fetched.
	c.mu.RLock()
	seenAt := c.fetchedAt
	c.mu.RUnlock()

	if err := c.refresh(ctx, seenAt); err != nil {
		return nil, err
	}

	if k, ok := c.cached(kid); ok {
		return k, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnknownKey, kid)
}

func (c *Client) cached(kid string) (crypto.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.now().Sub(c.fetchedAt) > c.ttl {
		return nil, false
	}

	k, ok := c.keys[kid]

	return k, ok
}

// refresh fetches the JWKS and replaces the cache.
//
// seenAt is the cache stamp the caller observed before asking. If the stamp has
// moved by the time we hold the lock, another goroutine fetched what we were
// about to fetch and we take their result — that, not the cache's age, is the
// correct de-duplication test. Beyond that, fetches are rate-limited by
// minInterval so a stream of unknown kids cannot be turned into a stream of
// requests to the issuer.
func (c *Client) refresh(ctx context.Context, seenAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Another goroutine refreshed while we waited for the lock.
	if !c.fetchedAt.Equal(seenAt) {
		return nil
	}

	// Rate limit on ATTEMPTS, not successes: a failing issuer must not be
	// hammered either. Returning nil leaves the caller to report the kid as
	// unknown from the cache it already has.
	now := c.now()
	if !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < c.minInterval {
		return nil
	}
	c.lastAttempt = now

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("jwks: parse failed: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(set.Keys))
	for i := range set.Keys {
		k := set.Keys[i]
		keys[k.KeyID] = k.Key
	}

	c.keys = keys
	c.fetchedAt = c.now()

	return nil
}
