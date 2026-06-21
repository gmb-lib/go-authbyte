// Package replay provides the DPoP `jti` replay cache. A proof is accepted at
// most once within its validity window; a second presentation of the same jti
// is rejected. The default backend is per-pod in-memory (spec decision A-1); a
// Redis backend is available for cluster-wide enforcement.
package replay

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store records seen DPoP proof identifiers.
type Store interface {
	// CheckAndSet records jti and reports whether it is the first time it has
	// been seen within ttl. A false return means the proof is a replay.
	CheckAndSet(ctx context.Context, jti string, ttl time.Duration) (firstSeen bool, err error)
}

// Memory is a per-pod in-memory replay store with lazy expiry plus a periodic
// sweep.
type Memory struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	now    func() time.Time
	lastGC time.Time
}

// NewMemory returns an in-memory replay store.
func NewMemory() *Memory {
	return &Memory{
		seen: make(map[string]time.Time),
		now:  time.Now,
	}
}

// CheckAndSet implements Store.
func (m *Memory) CheckAndSet(_ context.Context, jti string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()

	if exp, ok := m.seen[jti]; ok && exp.After(now) {
		return false, nil
	}

	m.seen[jti] = now.Add(ttl)
	m.gc(now)

	return true, nil
}

// gc evicts expired entries at most once per second.
func (m *Memory) gc(now time.Time) {
	if now.Sub(m.lastGC) < time.Second {
		return
	}

	for k, exp := range m.seen {
		if !exp.After(now) {
			delete(m.seen, k)
		}
	}

	m.lastGC = now
}

// Redis is a cluster-wide replay store backed by Redis SET NX.
type Redis struct {
	client redis.UniversalClient
	prefix string
}

// NewRedis returns a Redis-backed replay store.
func NewRedis(client redis.UniversalClient) *Redis {
	return &Redis{client: client, prefix: "dpop:jti:"}
}

// CheckAndSet implements Store using SET key value NX EX ttl.
func (r *Redis) CheckAndSet(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	ok, err := r.client.SetNX(ctx, r.prefix+jti, 1, ttl).Result()
	if err != nil {
		return false, err
	}

	return ok, nil
}
