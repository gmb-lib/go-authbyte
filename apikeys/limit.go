package apikeys

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// Limiter decides whether a caller may make one more attempt now and, if not, how long until it may.
type Limiter interface {
	Allow(caller string) (ok bool, retryAfter time.Duration)
}

// LimitConfig tunes a MemoryLimiter.
type LimitConfig struct {
	// Attempts is how many attempts a caller may make in one Window; it may make them at once.
	Attempts int
	// Window is the time in which a caller's Attempts are given back, one share at a time.
	Window time.Duration
	// MaxCallers bounds how many callers are tracked one by one; callers beyond it share one
	// allowance of Attempts until tracked callers' allowances are whole again and they are forgotten.
	MaxCallers int
	// Now is the limiter's clock; nil means time.Now. Only tests set it.
	Now func() time.Time
}

// DefaultLimitConfig is the limit a Verifier applies when it is given none: 60 attempts a minute
// for each of up to 10,000 callers.
func DefaultLimitConfig() LimitConfig {
	return LimitConfig{Attempts: 60, Window: time.Minute, MaxCallers: 10_000}
}

// MemoryLimiter limits attempts per caller in this process. It keeps one time per caller (the
// generic cell rate algorithm): a caller may make Attempts at once, then one more each
// Window/Attempts. Its memory is bounded by MaxCallers, each kept by a digest of its name so a long
// name costs no more than a short one, and a flood of new callers costs no more than one shared
// allowance.
type MemoryLimiter struct {
	mu        sync.Mutex
	interval  time.Duration
	tolerance time.Duration
	max       int
	now       func() time.Time
	due       map[[sha256.Size]byte]time.Time
	overflow  time.Time
	swept     time.Time
}

// NewMemoryLimiter checks c and returns its limiter.
func NewMemoryLimiter(c LimitConfig) (*MemoryLimiter, error) {
	if c.Attempts < 1 || c.Window <= 0 || c.MaxCallers < 1 {
		return nil, errors.New("apikeys: a limit needs at least one attempt, a positive window and room for one caller")
	}

	interval := c.Window / time.Duration(c.Attempts)
	if interval <= 0 {
		return nil, errors.New("apikeys: a limit's window is too short for its attempts")
	}

	if c.Now == nil {
		c.Now = time.Now
	}

	return &MemoryLimiter{
		interval:  interval,
		tolerance: c.Window - interval,
		max:       c.MaxCallers,
		now:       c.Now,
		due:       map[[sha256.Size]byte]time.Time{},
	}, nil
}

// Allow counts one attempt by caller.
func (l *MemoryLimiter) Allow(caller string) (bool, time.Duration) {
	id := sha256.Sum256([]byte(caller))

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	due, tracked := l.due[id]
	if !tracked && len(l.due) >= l.max {
		l.sweep(now)

		if len(l.due) >= l.max {
			return l.take(&l.overflow, now)
		}
	}

	ok, after := l.take(&due, now)
	l.due[id] = due

	return ok, after
}

// take spends one attempt from the allowance whose next attempt is due at *due.
func (l *MemoryLimiter) take(due *time.Time, now time.Time) (bool, time.Duration) {
	t := *due
	if t.Before(now) {
		t = now
	}

	if wait := t.Sub(now) - l.tolerance; wait > 0 {
		return false, wait
	}

	*due = t.Add(l.interval)

	return true, 0
}

// sweep forgets callers whose allowance is whole again (forgetting them changes nothing), at most
// once per attempt's share of the window, so a flood does not make every attempt walk the table.
func (l *MemoryLimiter) sweep(now time.Time) {
	if now.Sub(l.swept) < l.interval {
		return
	}

	l.swept = now

	for id, due := range l.due {
		if !due.After(now) {
			delete(l.due, id)
		}
	}
}

func (l *MemoryLimiter) callers() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.due)
}
