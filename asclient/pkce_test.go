package asclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/go-quicktest/qt"
)

// TestPKCEChallengeMatchesVerifier proves the returned challenge is the S256
// (base64url, unpadded) digest of the verifier [IETF RFC 7636 §4.2] — a mismatch
// here would make every login fail at the Auth Service's check.
func TestPKCEChallengeMatchesVerifier(t *testing.T) {
	verifier, challenge, err := PKCE()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(verifier != ""))

	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	qt.Check(t, qt.Equals(challenge, want))

	// Two calls never reuse a verifier.
	verifier2, _, err := PKCE()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(verifier != verifier2))
}

func TestRandomTokenIsURLSafeAndUnique(t *testing.T) {
	a, err := RandomToken(32)
	qt.Assert(t, qt.IsNil(err))
	b, err := RandomToken(32)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.IsTrue(a != ""))
	qt.Check(t, qt.IsTrue(a != b))

	// Round-trips through the URL-safe, unpadded alphabet it produces.
	_, err = base64.RawURLEncoding.DecodeString(a)
	qt.Check(t, qt.IsNil(err))
}

func TestGenerateKeyProducesUsableECDSAKey(t *testing.T) {
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(key))

	// Usable for signing, the purpose it is generated for.
	digest := sha256.Sum256([]byte("test"))
	sig, err := key.Sign(rand.Reader, digest[:], nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(len(sig) > 0))
}
