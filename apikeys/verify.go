package apikeys

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

var (
	// ErrInvalid refuses a presented key: wrong, unknown, revoked or malformed alike.
	ErrInvalid = errors.New("apikeys: invalid key")
	// ErrLimited refuses a check because its caller made too many; RetryAfter says when to try again.
	ErrLimited = errors.New("apikeys: too many attempts")
	// ErrBusy refuses a check because every derive slot is taken; RetryAfter says when to try again.
	ErrBusy = errors.New("apikeys: too many checks at once")
	// ErrStoredHash refuses a check because the key's stored string is malformed or outside the
	// scheme's bounds: the store is corrupt or tampered with, which is the service's alarm, not the
	// caller's fault. The key is not accepted.
	ErrStoredHash = errors.New("apikeys: stored hash refused")
	// ErrUnavailable wraps the store's error when a key could not be looked up.
	ErrUnavailable = errors.New("apikeys: key store unavailable")

	errNoCaller = errors.New("apikeys: a check needs its caller, or every caller shares one limit")
)

// Defaults for VerifierConfig.
const (
	// DefaultMaxDerives is how many derives run at once: at the default parameters, 4 × 19 MiB.
	DefaultMaxDerives = 4
	// DefaultBusyRetryAfter is the retry delay a check refused for want of a derive slot carries.
	DefaultBusyRetryAfter = time.Second
	// DefaultCacheSize is how many keys a cache holds when CacheTTL turns it on.
	DefaultCacheSize = 1024
)

type retryError struct {
	err   error
	after time.Duration
}

func (e *retryError) Error() string { return e.err.Error() }
func (e *retryError) Unwrap() error { return e.err }

// RetryAfter returns the delay a refusal for load (ErrLimited, ErrBusy) carries.
func RetryAfter(err error) (time.Duration, bool) {
	var r *retryError
	if errors.As(err, &r) {
		return r.after, true
	}

	return 0, false
}

// HTTPStatus maps a check's error to the status a service answers it with: 401 for an invalid key,
// 429 when limited ([RFC 6585 §4]), 503 when busy, the store is down or the check was cut short
// ([RFC 9110 §15.6.4]), 500 for a refused stored string, which the service should also raise as an
// alarm; a load refusal's RetryAfter goes in Retry-After ([RFC 9110 §10.2.3]).
func HTTPStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrInvalid):
		return http.StatusUnauthorized
	case errors.Is(err, ErrLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrBusy), errors.Is(err, ErrUnavailable),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// Lookup finds the stored string of the key with the given lookup part. A key that was revoked or
// replaced by a new one is not found; it is asked on every check, so a revocation counts at once.
// It runs outside the derive cap: the store's own connection pool and the deadline of the ctx given
// to Verify bound how many wait on it and for how long.
type Lookup func(ctx context.Context, lookup string) (stored string, found bool, err error)

// VerifierConfig tunes a Verifier; its zero value is usable.
type VerifierConfig struct {
	// Limiter limits each caller's attempts before anything else is done, successes included, since
	// the outcome is not known yet; nil means a MemoryLimiter at DefaultLimitConfig, which suits keys
	// exchanged now and then. A service that checks a key on every request gives a higher limit.
	Limiter Limiter
	// MaxDerives caps the derives running at once; a check past it is refused with ErrBusy at once.
	// Zero means DefaultMaxDerives.
	MaxDerives int
	// BusyRetryAfter is the delay an ErrBusy carries; zero means DefaultBusyRetryAfter.
	BusyRetryAfter time.Duration
	// CacheTTL, when set, keeps a checked key's success that long, so a service that checks the key
	// on every request does not derive each time. Zero means no cache.
	CacheTTL time.Duration
	// CacheSize bounds the cache; zero means DefaultCacheSize.
	CacheSize int
	// Now is the cache's clock; nil means time.Now. Only tests set it.
	Now func() time.Time
}

// Verifier checks presented keys of one scheme.
type Verifier struct {
	scheme    *Scheme
	lookup    Lookup
	limiter   Limiter
	slots     chan struct{}
	busyAfter time.Duration
	cache     *successCache
}

// Result is a passed check: the key's lookup part and, when its stored string is below the scheme's
// minted parameters in any field, Rehash, a new stored string for the caller to save in place of
// Replaces, the one the key passed against. Save it only where the store still holds Replaces, so a
// key changed in between is never overwritten.
type Result struct {
	Lookup   string
	Rehash   string
	Replaces string
}

// NewVerifier returns a verifier that finds stored strings through lookup.
func (s *Scheme) NewVerifier(lookup Lookup, c VerifierConfig) (*Verifier, error) {
	if lookup == nil {
		return nil, errors.New("apikeys: a verifier needs a lookup")
	}

	if c.MaxDerives < 0 || c.BusyRetryAfter < 0 || c.CacheTTL < 0 || c.CacheSize < 0 {
		return nil, errors.New("apikeys: a verifier's limits must not be negative")
	}

	if c.Limiter == nil {
		l, err := NewMemoryLimiter(DefaultLimitConfig())
		if err != nil {
			return nil, err
		}

		c.Limiter = l
	}

	if c.MaxDerives == 0 {
		c.MaxDerives = DefaultMaxDerives
	}

	if c.BusyRetryAfter == 0 {
		c.BusyRetryAfter = DefaultBusyRetryAfter
	}

	v := &Verifier{scheme: s, lookup: lookup, limiter: c.Limiter, slots: make(chan struct{}, c.MaxDerives), busyAfter: c.BusyRetryAfter}

	if c.CacheTTL > 0 {
		if c.CacheSize == 0 {
			c.CacheSize = DefaultCacheSize
		}

		if c.Now == nil {
			c.Now = time.Now
		}

		v.cache = &successCache{ttl: c.CacheTTL, size: c.CacheSize, now: c.Now, entries: map[string]cacheEntry{}}
	}

	return v, nil
}

// Verify checks key for caller, whom the limit counts. In order: the caller's limit; the key's
// shape; its lookup; a derive slot; one derive; a constant-time comparison. Past the limit and the
// slot, every check pays exactly one derive, a wrong, an unknown and a malformed key alike, and only
// a known key can pass; the derive costs the same for all three while the keys' stored strings are
// at the scheme's minted parameters.
//
// The caller is what the limit is kept by, so it must be something a client cannot choose freely:
// the connection's address (an IPv6 client by its /64), never a forwarded-for header the service
// does not set itself. It must not be empty. A flood of callers never seen before shares one
// allowance once the limiter's table is full, which keeps the limiter's memory and the derives it
// lets through bounded, at the price of new callers waiting while the flood lasts.
func (v *Verifier) Verify(ctx context.Context, caller, key string) (Result, error) {
	if caller == "" {
		return Result{}, errNoCaller
	}

	if ok, after := v.limiter.Allow(caller); !ok {
		return Result{}, &retryError{err: ErrLimited, after: after}
	}

	s := v.scheme

	k, perr := s.parse(key)

	var (
		stored  string
		st      storedHash
		known   bool
		refused error
	)

	if perr == nil {
		var (
			found bool
			err   error
		)

		stored, found, err = v.lookup(ctx, k.lookup)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}

		if found {
			st, refused = s.decodeStored(stored)
			known = refused == nil
		}
	}

	if known && v.cache != nil && v.cache.hit(k.lookup, stored, k.secret) {
		return Result{Lookup: k.lookup}, nil
	}

	secret := k.secret
	if !known {
		st = s.dummy
	}

	if perr != nil {
		secret = make([]byte, secretLen)
	}

	select {
	case v.slots <- struct{}{}:
	default:
		return Result{}, &retryError{err: ErrBusy, after: v.busyAfter}
	}
	defer func() { <-v.slots }()

	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	match := subtle.ConstantTimeCompare(s.derive(secret, st.salt, st.params, uint32(len(st.tag))), st.tag) == 1

	switch {
	case refused != nil:
		return Result{}, refused
	case !known || !match:
		return Result{}, ErrInvalid
	}

	res := Result{Lookup: k.lookup}

	if to, ok := s.rehashTo(st.params); ok {
		salt := make([]byte, saltLen)
		if _, err := io.ReadFull(s.rand, salt); err == nil {
			res.Rehash, res.Replaces = s.hashWith(k, salt, to), stored
		}
	} else if v.cache != nil {
		v.cache.put(k.lookup, stored, k.secret)
	}

	return res, nil
}

// successCache remembers passed checks. An entry holds the stored string it passed against and a
// digest of the secret, never the secret; the lookup still runs on every check, so a regenerated,
// revoked or rehashed key never hits an old entry.
type successCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	size    int
	now     func() time.Time
	entries map[string]cacheEntry
}

type cacheEntry struct {
	stored  string
	digest  [sha256.Size]byte
	expires time.Time
}

func (c *successCache) hit(lookup, stored string, secret []byte) bool {
	digest := sha256.Sum256(secret)

	c.mu.Lock()
	e, ok := c.entries[lookup]
	c.mu.Unlock()

	return ok && c.now().Before(e.expires) && e.stored == stored && subtle.ConstantTimeCompare(e.digest[:], digest[:]) == 1
}

func (c *successCache) put(lookup, stored string, secret []byte) {
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[lookup]; !ok && len(c.entries) >= c.size {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}

		for k := range c.entries {
			if len(c.entries) < c.size {
				break
			}

			delete(c.entries, k)
		}
	}

	c.entries[lookup] = cacheEntry{stored: stored, digest: sha256.Sum256(secret), expires: now.Add(c.ttl)}
}

func (c *successCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}
