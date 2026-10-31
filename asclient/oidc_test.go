package asclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://auth.example"

// A sign-in that asks for an ID token always says so (scope openid) and always
// sends the nonce the token must carry back; the rest travels only when asked.
func TestAnAuthorizationRequestAsksForAnIDToken(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	u, err := url.Parse(c.AuthorizationURL(AuthorizationRequest{CodeChallenge: "chal-1", State: "state-1", Nonce: "n-1"}))
	qt.Assert(t, qt.IsNil(err))
	q := u.Query()
	qt.Check(t, qt.Equals(u.Path, "/authorize"))
	qt.Check(t, qt.Equals(q.Get("scope"), "openid"))
	qt.Check(t, qt.Equals(q.Get("nonce"), "n-1"))
	qt.Check(t, qt.Equals(q.Get("code_challenge"), "chal-1"))
	qt.Check(t, qt.Equals(q.Get("state"), "state-1"))
	qt.Check(t, qt.Equals(q.Get("client_id"), "client-1"))
	qt.Check(t, qt.IsFalse(q.Has("prompt")))
	qt.Check(t, qt.IsFalse(q.Has("max_age")))
	qt.Check(t, qt.IsFalse(q.Has("acr_values")))

	zero := time.Duration(0)
	u, err = url.Parse(c.AuthorizationURL(AuthorizationRequest{
		CodeChallenge: "chal-1", State: "state-1", Nonce: "n-1",
		ACRValues: "eidScan eparakstsMobile", Prompt: "login", MaxAge: &zero,
	}))
	qt.Assert(t, qt.IsNil(err))
	q = u.Query()
	qt.Check(t, qt.Equals(q.Get("acr_values"), "eidScan eparakstsMobile"))
	qt.Check(t, qt.Equals(q.Get("prompt"), "login"))
	qt.Check(t, qt.Equals(q.Get("max_age"), "0"))

	hour := time.Hour
	u, err = url.Parse(c.AuthorizationURL(AuthorizationRequest{CodeChallenge: "c", State: "s", Nonce: "n", MaxAge: &hour}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Query().Get("max_age"), "3600"))
}

// The browser's return must name the authority the sign-in went to, or the code
// in it is never redeemed.
func TestTheBrowsersReturnMustNameTheIssuer(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback", WithIssuer(testIssuer))

	qt.Check(t, qt.IsNil(c.CheckIssuer(testIssuer)))
	qt.Check(t, qt.ErrorIs(c.CheckIssuer("https://evil.example"), ErrIssuer))
	qt.Check(t, qt.ErrorIs(c.CheckIssuer(""), ErrIssuer))
	qt.Check(t, qt.ErrorIs(c.CheckIssuer(testIssuer+"/"), ErrIssuer))

	unset := New("https://public", "https://internal", "client-1", "https://app/callback")
	qt.Check(t, qt.ErrorIs(unset.CheckIssuer(testIssuer), ErrIssuer))
}

// idTokenAuthority is a stub authority that answers a code exchange with an ID
// token the test shapes, and publishes the key it signs with.
type idTokenAuthority struct {
	key     *ecdsa.PrivateKey
	kid     string
	idToken string // the answer's id_token; "" leaves it out
	revoked int    // revocations received
}

func newIDTokenAuthority(t *testing.T) (*idTokenAuthority, *httptest.Server) {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	a := &idTokenAuthority{key: k, kid: "k-1"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{{KeyID: a.kid, Key: &a.key.PublicKey, Algorithm: "ES256", Use: "sig"}},
			})
		case "/token":
			body := map[string]any{"access_token": "a", "token_type": "DPoP", "expires_in": 300, "refresh_token": "r"}
			if a.idToken != "" {
				body["id_token"] = a.idToken
			}
			_ = json.NewEncoder(w).Encode(body)
		case "/revoke":
			a.revoked++
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	return a, srv
}

func (a *idTokenAuthority) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = a.kid
	s, err := tok.SignedString(a.key)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func goodIDClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":       testIssuer,
		"sub":       "sub:01J0000000000000000000000",
		"aud":       "client-1",
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
		"nonce":     "n-1",
		"auth_time": now.Add(-10 * time.Second).Unix(),
		"acr":       "eparakstsMobile",
		"amr":       []string{"mfa"},
		"sid":       "sid-1",
	}
}

// A sign-in is accepted only when its ID token proves it: from this issuer, for
// this client alone, unexpired, signed by a key the authority publishes, carrying
// the nonce sent and, when an age was asked, the time the person authenticated.
// Every other answer is refused and returns no tokens.
func TestASignInIsAcceptedOnlyWithAnIDTokenThatProvesIt(t *testing.T) {
	now := time.Now()
	minute := time.Minute

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	tests := []struct {
		name   string
		token  func(a *idTokenAuthority) string
		check  IDTokenCheck
		accept bool
	}{
		{name: "a token that proves the sign-in", accept: true,
			token: func(a *idTokenAuthority) string { return a.sign(t, goodIDClaims(now)) }},
		{name: "an age asked and met", accept: true, check: IDTokenCheck{MaxAge: &minute, Started: now},
			token: func(a *idTokenAuthority) string { return a.sign(t, goodIDClaims(now)) }},
		{name: "another issuer",
			token: func(a *idTokenAuthority) string {
				c := goodIDClaims(now)
				c["iss"] = "https://evil.example"
				return a.sign(t, c)
			}},
		{name: "another client",
			token: func(a *idTokenAuthority) string { c := goodIDClaims(now); c["aud"] = "client-2"; return a.sign(t, c) }},
		{name: "this client beside another audience",
			token: func(a *idTokenAuthority) string {
				c := goodIDClaims(now)
				c["aud"] = []string{"client-1", "portal-api"}

				return a.sign(t, c)
			}},
		{name: "expired",
			token: func(a *idTokenAuthority) string {
				c := goodIDClaims(now)
				c["exp"] = now.Add(-time.Minute).Unix()
				return a.sign(t, c)
			}},
		{name: "signed by a key the authority does not publish",
			token: func(a *idTokenAuthority) string {
				tok := jwt.NewWithClaims(jwt.SigningMethodES256, goodIDClaims(now))
				tok.Header["kid"] = a.kid
				s, err := tok.SignedString(otherKey)
				qt.Assert(t, qt.IsNil(err))

				return s
			}},
		{name: "alg none",
			token: func(*idTokenAuthority) string {
				s, err := jwt.NewWithClaims(jwt.SigningMethodNone, goodIDClaims(now)).SignedString(jwt.UnsafeAllowNoneSignatureType)
				qt.Assert(t, qt.IsNil(err))

				return s
			}},
		{name: "alg HS256",
			token: func(*idTokenAuthority) string {
				tok := jwt.NewWithClaims(jwt.SigningMethodHS256, goodIDClaims(now))
				tok.Header["kid"] = "k-1"
				s, err := tok.SignedString([]byte("client-secret-used-as-a-mac-key"))
				qt.Assert(t, qt.IsNil(err))

				return s
			}},
		{name: "no nonce",
			token: func(a *idTokenAuthority) string { c := goodIDClaims(now); delete(c, "nonce"); return a.sign(t, c) }},
		{name: "another nonce",
			token: func(a *idTokenAuthority) string { c := goodIDClaims(now); c["nonce"] = "n-2"; return a.sign(t, c) }},
		{name: "an age asked and no auth_time", check: IDTokenCheck{MaxAge: &minute, Started: now},
			token: func(a *idTokenAuthority) string { c := goodIDClaims(now); delete(c, "auth_time"); return a.sign(t, c) }},
		{name: "an age asked and the authentication older than it", check: IDTokenCheck{MaxAge: &minute, Started: now},
			token: func(a *idTokenAuthority) string {
				c := goodIDClaims(now)
				c["auth_time"] = now.Add(-10 * time.Minute).Unix()

				return a.sign(t, c)
			}},
		{name: "no id_token in the answer",
			token: func(*idTokenAuthority) string { return "" }},
		{name: "the method asked met", accept: true, check: IDTokenCheck{ACRValues: "eidScan eparakstsMobile"},
			token: func(a *idTokenAuthority) string { return a.sign(t, goodIDClaims(now)) }},
		{name: "another method than the ones asked", check: IDTokenCheck{ACRValues: "eidScan"},
			token: func(a *idTokenAuthority) string { return a.sign(t, goodIDClaims(now)) }},
		{name: "no subject",
			token: func(a *idTokenAuthority) string { c := goodIDClaims(now); delete(c, "sub"); return a.sign(t, c) }},
		{name: "no issue time",
			token: func(a *idTokenAuthority) string { c := goodIDClaims(now); delete(c, "iat"); return a.sign(t, c) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, srv := newIDTokenAuthority(t)
			a.idToken = tt.token(a)
			c := New("https://public", srv.URL, "client-1", "https://app/callback", WithIssuer(testIssuer))
			key, err := GenerateKey()
			qt.Assert(t, qt.IsNil(err))

			check := tt.check
			check.Nonce = "n-1"
			tokens, id, err := c.ExchangeSignIn(context.Background(), key, "code-1", "verifier-1", check)

			if tt.accept {
				qt.Assert(t, qt.IsNil(err))
				qt.Check(t, qt.Equals(tokens.AccessToken, "a"))
				qt.Check(t, qt.Equals(id.Subject, "sub:01J0000000000000000000000"))
				qt.Check(t, qt.Equals(id.ACR, "eparakstsMobile"))
				qt.Check(t, qt.DeepEquals(id.AMR, []string{"mfa"}))
				qt.Check(t, qt.Equals(id.SessionID, "sid-1"))
				qt.Check(t, qt.Equals(id.AuthTime.Unix(), now.Add(-10*time.Second).Unix()))

				qt.Check(t, qt.Equals(a.revoked, 0))

				return
			}
			qt.Check(t, qt.ErrorIs(err, ErrIDToken))
			qt.Check(t, qt.IsNil(tokens))
			qt.Check(t, qt.IsNil(id))
			// The session the refused exchange opened is ended at once.
			qt.Check(t, qt.Equals(a.revoked, 1))
		})
	}
}

// The check needs what it checks against: a client that names no issuer, or a
// call that names no nonce, refuses rather than accepting anything.
func TestASignInCheckWithoutItsInputsRefuses(t *testing.T) {
	now := time.Now()
	a, srv := newIDTokenAuthority(t)
	a.idToken = a.sign(t, goodIDClaims(now))
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))

	noIssuer := New("https://public", srv.URL, "client-1", "https://app/callback")
	_, _, err = noIssuer.ExchangeSignIn(context.Background(), key, "code-1", "verifier-1", IDTokenCheck{Nonce: "n-1"})
	qt.Check(t, qt.ErrorIs(err, ErrIDToken))

	c := New("https://public", srv.URL, "client-1", "https://app/callback", WithIssuer(testIssuer))
	_, _, err = c.ExchangeSignIn(context.Background(), key, "code-1", "verifier-1", IDTokenCheck{})
	qt.Check(t, qt.ErrorIs(err, ErrIDToken))
}

// A card sign-in that asks for an ID token says so to the card door too, with
// the nonce the token must carry back.
func TestTheCardChallengeCarriesTheNonce(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"card-challenge","state":"flow-1"}`))
	}))
	t.Cleanup(srv.Close)
	c := New("https://public", srv.URL, "client-1", "https://app/callback")

	challenge, flow, err := c.WebEIDChallengeWithNonce(context.Background(), "chal-1", "state-1", "n-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(challenge, "card-challenge"))
	qt.Check(t, qt.Equals(flow, "flow-1"))
	qt.Check(t, qt.Equals(got.Get("scope"), "openid"))
	qt.Check(t, qt.Equals(got.Get("nonce"), "n-1"))

	_, _, err = c.WebEIDChallenge(context.Background(), "chal-1", "state-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(got.Has("scope")))
	qt.Check(t, qt.IsFalse(got.Has("nonce")))
}
