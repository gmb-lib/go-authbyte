package apikeys

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newCachedFixture(t *testing.T, c *clock, size int) *fixture {
	t.Helper()

	return newFixture(t, VerifierConfig{CacheTTL: time.Minute, CacheSize: size, Now: c.now})
}

func TestCachedKeySkipsTheDeriveButNotTheLookup(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newCachedFixture(t, c, 16)
	k := f.mint(t)
	f.store.put(k)

	if _, err := f.v.Verify(context.Background(), "caller", k.Key.Reveal()); err != nil {
		t.Fatal(err)
	}

	derives, lookups := f.derive.count(), f.store.lookups()

	if _, err := f.v.Verify(context.Background(), "caller", k.Key.Reveal()); err != nil {
		t.Fatalf("second check: %v", err)
	}

	if f.derive.count() != derives {
		t.Fatal("a cached key derived again")
	}

	if f.store.lookups() != lookups+1 {
		t.Fatal("a cached key skipped its lookup")
	}

	if _, err := f.v.Verify(context.Background(), "caller", mutateSecret(t, f.scheme, k.Key.Reveal())); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a wrong secret beside a cached key: got %v, want ErrInvalid", err)
	}

	if f.derive.count() != derives+1 {
		t.Fatal("a wrong secret beside a cached key did not pay its derive")
	}
}

func TestCacheNeverOutlivesTheStoredString(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newCachedFixture(t, c, 16)

	k := f.mint(t)
	f.store.put(k)
	_, _ = f.v.Verify(context.Background(), "caller", k.Key.Reveal())

	// Regenerated: the old key is gone from the store.
	next := f.mint(t)
	f.store.replace(k, next)

	if _, err := f.v.Verify(context.Background(), "caller", k.Key.Reveal()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a regenerated key from the cache: got %v, want ErrInvalid", err)
	}

	// Revoked: removed from the store.
	_, _ = f.v.Verify(context.Background(), "caller", next.Key.Reveal())
	delete(f.store.rows, next.Lookup)

	if _, err := f.v.Verify(context.Background(), "caller", next.Key.Reveal()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a revoked key from the cache: got %v, want ErrInvalid", err)
	}

	// Rehashed: the same key under a new stored string derives again.
	third := f.mint(t)
	f.store.put(third)
	_, _ = f.v.Verify(context.Background(), "caller", third.Key.Reveal())

	f.store.rows[third.Lookup] = storedAt(t, f.scheme, third, DefaultParams())
	before := f.derive.count()

	if _, err := f.v.Verify(context.Background(), "caller", third.Key.Reveal()); err != nil {
		t.Fatalf("a rehashed key: %v", err)
	}

	if f.derive.count() != before+1 {
		t.Fatal("a key under a new stored string was answered from the cache")
	}
}

func TestCacheEntriesExpireAndStayWithinTheSize(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newCachedFixture(t, c, 4)

	k := f.mint(t)
	f.store.put(k)
	_, _ = f.v.Verify(context.Background(), "caller", k.Key.Reveal())

	c.t = c.t.Add(time.Minute - time.Nanosecond)
	before := f.derive.count()
	_, _ = f.v.Verify(context.Background(), "caller", k.Key.Reveal())

	if f.derive.count() != before {
		t.Fatal("an entry within its lifetime derived again")
	}

	c.t = c.t.Add(time.Nanosecond)
	_, _ = f.v.Verify(context.Background(), "caller", k.Key.Reveal())

	if f.derive.count() != before+1 {
		t.Fatal("an entry at the end of its lifetime was still used")
	}

	for range 10 {
		m := f.mint(t)
		f.store.put(m)
		_, _ = f.v.Verify(context.Background(), "caller", m.Key.Reveal())
	}

	if n := f.v.cache.len(); n > 4 {
		t.Fatalf("the cache holds %d entries, its size is 4", n)
	}
}

func TestCacheIsOffByDefault(t *testing.T) {
	f := newFixture(t, VerifierConfig{})
	k := f.mint(t)
	f.store.put(k)

	_, _ = f.v.Verify(context.Background(), "caller", k.Key.Reveal())
	before := f.derive.count()
	_, _ = f.v.Verify(context.Background(), "caller", k.Key.Reveal())

	if f.derive.count() != before+1 {
		t.Fatal("a verifier built without a cache answered from one")
	}
}
