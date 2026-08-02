package asclient

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/gmb-lib/go-authbyte/dpop"
)

// GenerateKey returns a fresh per-session key for the calling service to hold and
// prove possession of on every server-side call in that session.
func GenerateKey() (*ecdsa.PrivateKey, error) { return dpop.GenerateKey() }

// PKCE returns a fresh proof-key verifier and its challenge [IETF RFC 7636 §4].
// The verifier stays with the calling service; only the challenge travels in the
// browser redirect, so an intercepted authorization code cannot be redeemed
// without it.
func PKCE() (verifier, challenge string, err error) {
	verifier, err = randomToken(48)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))

	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// RandomToken returns a URL-safe random token of the given byte length. Used for
// the anti-forgery state, session ids, and per-session anti-forgery tokens.
func RandomToken(n int) (string, error) { return randomToken(n) }

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
