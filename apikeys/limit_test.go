package apikeys

import (
	"strconv"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestLimiter(t *testing.T, attempts, maxCallers int, c *clock) *MemoryLimiter {
	t.Helper()

	l, err := NewMemoryLimiter(LimitConfig{
		Attempts:   attempts,
		Window:     time.Minute,
		MaxCallers: maxCallers,
		Now:        c.now,
	})
	if err != nil {
		t.Fatalf("NewMemoryLimiter: %v", err)
	}

	return l
}

func TestLimiterAllowsTheLimitThenRefusesUntilTheNextWindow(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := newTestLimiter(t, 5, 100, c)

	for i := 1; i <= 5; i++ {
		if ok, _ := l.Allow("caller-a"); !ok {
			t.Fatalf("attempt %d of 5 refused", i)
		}
	}

	ok, after := l.Allow("caller-a")
	if ok {
		t.Fatal("attempt 6 of 5 allowed")
	}

	if after != 12*time.Second {
		t.Fatalf("retry after %v, want 12s (one attempt's share of the window)", after)
	}

	if ok, _ := l.Allow("caller-b"); !ok {
		t.Fatal("another caller limited by caller-a's attempts")
	}

	c.t = c.t.Add(time.Minute)

	for i := 1; i <= 5; i++ {
		if ok, _ := l.Allow("caller-a"); !ok {
			t.Fatalf("next window: attempt %d of 5 refused", i)
		}
	}

	if ok, _ := l.Allow("caller-a"); ok {
		t.Fatal("next window: attempt 6 of 5 allowed")
	}
}

func TestLimiterGivesBackOneAttemptPerShareOfTheWindow(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := newTestLimiter(t, 5, 100, c)

	for range 5 {
		l.Allow("caller-a")
	}

	c.t = c.t.Add(12*time.Second - time.Nanosecond)
	if ok, _ := l.Allow("caller-a"); ok {
		t.Fatal("allowed a nanosecond before the attempt was given back")
	}

	c.t = c.t.Add(time.Nanosecond)
	if ok, _ := l.Allow("caller-a"); !ok {
		t.Fatal("refused once the attempt was given back")
	}

	if ok, _ := l.Allow("caller-a"); ok {
		t.Fatal("allowed two attempts for one share of the window")
	}
}

func TestLimiterMemoryStaysBoundedUnderManyCallers(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := newTestLimiter(t, 5, 1000, c)

	allowed := 0

	for i := range 100_000 {
		if ok, _ := l.Allow("caller-" + strconv.Itoa(i)); ok {
			allowed++
		}
	}

	if n := l.callers(); n > 1000 {
		t.Fatalf("limiter holds %d callers, bound is 1000", n)
	}

	// The first 1000 callers are tracked one each; every caller after them shares one overflow
	// allowance of 5 attempts, so the number of checks a flood of new callers can cause is bounded.
	if allowed != 1000+5 {
		t.Fatalf("allowed %d attempts, want 1005 (1000 tracked callers + 5 overflow)", allowed)
	}
}

func TestLimiterForgetsCallersWhoseAllowanceIsWhole(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := newTestLimiter(t, 5, 10, c)

	for i := range 10 {
		l.Allow("old-" + strconv.Itoa(i))
	}

	c.t = c.t.Add(time.Minute)

	for i := range 10 {
		if ok, _ := l.Allow("new-" + strconv.Itoa(i)); !ok {
			t.Fatalf("new caller %d refused although every old caller's allowance is whole again", i)
		}
	}

	if n := l.callers(); n > 10 {
		t.Fatalf("limiter holds %d callers, bound is 10", n)
	}
}

func TestNewMemoryLimiterRefusesAnUnusableConfig(t *testing.T) {
	for name, cfg := range map[string]LimitConfig{
		"zero attempts":    {Attempts: 0, Window: time.Minute, MaxCallers: 10},
		"negative window":  {Attempts: 5, Window: -time.Second, MaxCallers: 10},
		"zero window":      {Attempts: 5, Window: 0, MaxCallers: 10},
		"zero max callers": {Attempts: 5, Window: time.Minute, MaxCallers: 0},
	} {
		if _, err := NewMemoryLimiter(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDefaultLimitConfigIsUsable(t *testing.T) {
	if _, err := NewMemoryLimiter(DefaultLimitConfig()); err != nil {
		t.Fatalf("the default limit config is refused: %v", err)
	}
}
