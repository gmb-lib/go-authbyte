package asclient

import (
	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/golang-jwt/jwt/v5"
)

// ParseUnverified decodes a token this service was just issued, without verifying
// its signature, into the shared claim model.
//
// Not verifying is deliberate and bounded: the token arrived over a trusted
// server-side channel in direct response to this service's own token request, and
// what is read from it never grants anything — it labels a session the calling
// service already holds (which user this is, which cache entry the delegated token
// belongs to). Anything that authorizes must verify instead; that is the inbound
// gate's job, not this function's.
func ParseUnverified(token string) (*claims.Claims, error) {
	var cl claims.Claims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &cl); err != nil {
		return nil, err
	}

	return &cl, nil
}

// SubjectFromToken reads the subject a token was issued for — the identity this
// service acts on behalf of downstream, and the delegated-token cache key.
// Returns "" when the token cannot be read.
func SubjectFromToken(token string) string {
	cl, err := ParseUnverified(token)
	if err != nil {
		return ""
	}

	return cl.Subject
}

// SerialFromToken reads the identity code a token carries (the serial number
// claim) — the code that names the legal person, so a caller can be matched to a
// record keyed on it. Returns "" when the claim is absent.
func SerialFromToken(token string) string {
	cl, err := ParseUnverified(token)
	if err != nil {
		return ""
	}

	return cl.SerialNumber
}

// LoginBindingFromToken reads the login method and assurance level a token is
// bound to and returns them as one compact discriminator, for scoping an
// on-behalf delegated-token cache. A delegated token bakes these claims in, so a
// cache keyed on the stable subject must vary with them — otherwise a re-login as
// the same person by a different method reuses a token carrying the old method.
// Returns "" when neither claim is readable, and the caller then falls back to
// subject-only keying.
func LoginBindingFromToken(token string) string {
	cl, err := ParseUnverified(token)
	if err != nil {
		return ""
	}
	if cl.LoginMethod == "" && cl.LoA == "" {
		return ""
	}

	return "lm:" + cl.LoginMethod + "|loa:" + cl.LoA
}
