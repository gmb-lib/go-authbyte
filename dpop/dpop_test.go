package dpop

import (
	"testing"
	"time"
)

const (
	testMethod = "POST"
	testURL    = "https://auth.example/token"
)

func mustProof(t *testing.T, accessToken, nonce string) (string, string) {
	t.Helper()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tp, err := Thumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	proof, err := GenerateProof(key, testMethod, testURL, accessToken, nonce)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	return proof, tp
}

func baseOpts() VerifyOptions {
	return VerifyOptions{
		Method: testMethod,
		URL:    testURL,
		MaxAge: 60 * time.Second,
		Leeway: 5 * time.Second,
	}
}

func TestVerifyRoundTrip(t *testing.T) {
	proof, tp := mustProof(t, "access-token-123", "nonce-1")

	opt := baseOpts()
	opt.AccessToken = "access-token-123"

	res, err := Verify(proof, opt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Thumbprint != tp {
		t.Fatalf("thumbprint mismatch: got %q want %q", res.Thumbprint, tp)
	}
	if res.Nonce != "nonce-1" {
		t.Fatalf("nonce mismatch: got %q", res.Nonce)
	}
	if res.JTI == "" {
		t.Fatal("expected a jti")
	}
}

func TestVerifyWrongMethod(t *testing.T) {
	proof, _ := mustProof(t, "", "")

	opt := baseOpts()
	opt.Method = "GET"

	if _, err := Verify(proof, opt); err != ErrMethod {
		t.Fatalf("expected ErrMethod, got %v", err)
	}
}

func TestVerifyWrongURL(t *testing.T) {
	proof, _ := mustProof(t, "", "")

	opt := baseOpts()
	opt.URL = "https://evil.example/token"

	if _, err := Verify(proof, opt); err != ErrURL {
		t.Fatalf("expected ErrURL, got %v", err)
	}
}

func TestVerifyURLIgnoresQuery(t *testing.T) {
	proof, _ := mustProof(t, "", "")

	opt := baseOpts()
	opt.URL = testURL + "?foo=bar#frag"

	if _, err := Verify(proof, opt); err != nil {
		t.Fatalf("query/fragment should be ignored: %v", err)
	}
}

func TestVerifyATHMismatch(t *testing.T) {
	proof, _ := mustProof(t, "real-token", "")

	opt := baseOpts()
	opt.AccessToken = "different-token"

	if _, err := Verify(proof, opt); err != ErrATH {
		t.Fatalf("expected ErrATH, got %v", err)
	}
}

func TestVerifyMissingNonce(t *testing.T) {
	proof, _ := mustProof(t, "", "")

	opt := baseOpts()
	opt.RequireNonce = true

	if _, err := Verify(proof, opt); err != ErrMissingNonce {
		t.Fatalf("expected ErrMissingNonce, got %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	proof, _ := mustProof(t, "", "")

	opt := baseOpts()
	opt.now = func() time.Time { return time.Now().Add(10 * time.Minute) }

	if _, err := Verify(proof, opt); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	proof, _ := mustProof(t, "", "")

	// Flip a character in the signature segment.
	tampered := proof[:len(proof)-3] + "AAA"

	if _, err := Verify(tampered, baseOpts()); err == nil {
		t.Fatal("expected verification to fail on tampered signature")
	}
}
