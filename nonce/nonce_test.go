package nonce

import (
	"testing"
	"time"
)

func TestIssueVerify(t *testing.T) {
	i, err := New(5 * time.Minute)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	n := i.Issue()
	if n == "" {
		t.Fatal("expected a nonce")
	}

	if err := i.Verify(n, time.Second); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyEmpty(t *testing.T) {
	i, _ := New(time.Minute)
	if err := i.Verify("", 0); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	i, _ := New(time.Minute)
	n := i.Issue()

	if err := i.Verify(n+"x", 0); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid for tampered nonce, got %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	i, _ := New(time.Minute)

	base := time.Now()
	i.now = func() time.Time { return base }
	n := i.Issue()

	i.now = func() time.Time { return base.Add(2 * time.Minute) }
	if err := i.Verify(n, 0); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid for expired nonce, got %v", err)
	}
}

func TestVerifyForeignKey(t *testing.T) {
	a, _ := New(time.Minute)
	b, _ := New(time.Minute)

	n := a.Issue()
	if err := b.Verify(n, 0); err != ErrInvalid {
		t.Fatalf("nonce from another issuer must not verify, got %v", err)
	}
}
