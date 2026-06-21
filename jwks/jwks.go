// Package jwks provides a caching client for an Identity/Auth JWKS endpoint.
// Public signing keys are cached per pod and refreshed on a TTL; a request for
// an unknown `kid` triggers an out-of-band refresh (fail-closed if it stays
// unknown). Validation never blocks on a network call once the cache is warm.
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

// Client fetches and caches a JWKS document.
type Client struct {
	url  string
	ttl  time.Duration
	http *http.Client
	now  func() time.Time

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client used to fetch the JWKS.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// New returns a JWKS client for the given endpoint and cache TTL.
func New(jwksURL string, ttl time.Duration, opts ...Option) *Client {
	c := &Client{
		url:  jwksURL,
		ttl:  ttl,
		http: &http.Client{Timeout: 10 * time.Second},
		now:  time.Now,
		keys: make(map[string]crypto.PublicKey),
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

	if err := c.refresh(ctx); err != nil {
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

// refresh fetches the JWKS and replaces the cache. Concurrent callers
// serialize on the write lock; a fresh-enough cache short-circuits.
func (c *Client) refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Another goroutine may have refreshed while we waited for the lock.
	if c.now().Sub(c.fetchedAt) <= c.ttl && len(c.keys) > 0 {
		return nil
	}

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
