package authclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gmb-lib/go-authbyte/claims"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

// issuerStub publishes one signing key, as an issuer's key set would, and mints
// tokens with it.
type issuerStub struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
}

func newIssuerStub(t *testing.T) *issuerStub {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	s := &issuerStub{key: key}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{KeyID: "k1", Key: &key.PublicKey, Algorithm: "ES256", Use: "sig"}},
		})
	}))
	t.Cleanup(s.srv.Close)

	return s
}

func (s *issuerStub) mint(t *testing.T, audiences ...string) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims.Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer:    s.srv.URL,
		Subject:   "sub:person",
		Audience:  audiences,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}})
	tok.Header["kid"] = "k1"

	signed, err := tok.SignedString(s.key)
	qt.Assert(t, qt.IsNil(err))

	return signed
}

func (s *issuerStub) client(t *testing.T, also ...string) *Client {
	t.Helper()

	c, err := New(&Configuration{
		IssuerURL:                s.srv.URL,
		JWKSURL:                  s.srv.URL,
		ServiceAudience:          "app-one",
		AlsoAcceptedAudiences:    also,
		JWKSCacheTTL:             time.Minute,
		ServiceTokenEarlyRefresh: time.Second,
		DPoPProofMaxAge:          time.Minute,
		DPoPReplayBackend:        ReplayBackendMemory,
	})
	qt.Assert(t, qt.IsNil(err))

	return c
}

// A service that serves several audiences, such as an authority answering every
// product's sign-in clients, accepts a token addressed to any one of them, and
// still refuses one addressed to none.
func TestAnInboundTokenMayTargetAnAlsoAcceptedAudience(t *testing.T) {
	s := newIssuerStub(t)
	c := s.client(t, "app-two", "app-three")
	ctx := context.Background()

	for _, aud := range [][]string{{"app-one"}, {"app-two"}, {"app-three"}, {"app-four", "app-two"}} {
		_, err := c.parseToken(ctx, s.mint(t, aud...))
		qt.Check(t, qt.IsNil(err), qt.Commentf("audience %v", aud))
	}

	_, err := c.parseToken(ctx, s.mint(t, "app-four"))
	qt.Check(t, qt.IsNotNil(err))
}

// Without the list, the service's own audience is the only one, as before.
func TestWithoutAlsoAcceptedAudiencesOnlyTheServiceAudienceIsAccepted(t *testing.T) {
	s := newIssuerStub(t)
	c := s.client(t)
	ctx := context.Background()

	_, err := c.parseToken(ctx, s.mint(t, "app-one"))
	qt.Check(t, qt.IsNil(err))

	_, err = c.parseToken(ctx, s.mint(t, "app-two"))
	qt.Check(t, qt.IsNotNil(err))
}

// An empty entry in the list never lets a token through on its own.
func TestAnEmptyAlsoAcceptedAudienceAcceptsNothing(t *testing.T) {
	s := newIssuerStub(t)
	c := s.client(t, "")
	ctx := context.Background()

	_, err := c.parseToken(ctx, s.mint(t, ""))
	qt.Check(t, qt.IsNotNil(err))

	// The parser refuses an audience that is only "", but not "" beside another value.
	_, err = c.parseToken(ctx, s.mint(t, "", "app-four"))
	qt.Check(t, qt.IsNotNil(err))
}
