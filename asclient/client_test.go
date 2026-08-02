package asclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gmb-lib/go-platform-kit/propagation"
	"github.com/go-quicktest/qt"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// TestAuthorizeURLAlwaysForcesLogin proves every authorization redirect carries
// prompt=login — dropping it would let a live upstream single-sign-on session
// silently answer with a different login method than the one requested, and the
// login method carries authorization weight.
func TestAuthorizeURLAlwaysForcesLogin(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	raw := c.AuthorizeURL("chal-1", "state-1", "")
	u, err := url.Parse(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Scheme+"://"+u.Host, "https://public"))
	qt.Check(t, qt.Equals(u.Path, "/authorize"))

	q := u.Query()
	qt.Check(t, qt.Equals(q.Get("client_id"), "client-1"))
	qt.Check(t, qt.Equals(q.Get("response_type"), "code"))
	qt.Check(t, qt.Equals(q.Get("code_challenge"), "chal-1"))
	qt.Check(t, qt.Equals(q.Get("code_challenge_method"), "S256"))
	qt.Check(t, qt.Equals(q.Get("redirect_uri"), "https://app/callback"))
	qt.Check(t, qt.Equals(q.Get("state"), "state-1"))
	qt.Check(t, qt.Equals(q.Get("prompt"), "login"))
	qt.Check(t, qt.Equals(q.Get("acr_values"), ""))
}

// TestAuthorizeURLIncludesACRValuesWhenRequested proves a requested login method
// rides along as acr_values, and is omitted entirely when not requested (rather
// than sent empty).
func TestAuthorizeURLIncludesACRValuesWhenRequested(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	u, err := url.Parse(c.AuthorizeURL("chal-1", "state-1", "eidScan"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Query().Get("acr_values"), "eidScan"))

	u, err = url.Parse(c.AuthorizeURL("chal-1", "state-1", ""))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(u.Query().Has("acr_values")))
}

// TestLogoutURLIncludesSidOnlyWhenPresent proves the front-channel logout redirect
// carries the upstream session handle when known, and omits it (rather than
// sending it empty) for a non-federated login with no upstream session.
func TestLogoutURLIncludesSidOnlyWhenPresent(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	u, err := url.Parse(c.LogoutURL("https://app/login", "refresh-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Path, "/logout"))
	qt.Check(t, qt.Equals(u.Query().Get("client_id"), "client-1"))
	qt.Check(t, qt.Equals(u.Query().Get("redirect_uri"), "https://app/login"))
	qt.Check(t, qt.Equals(u.Query().Get("sid"), "refresh-1"))

	u, err = url.Parse(c.LogoutURL("https://app/login", ""))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(u.Query().Has("sid")))
}

// TestTrailingSlashesAreTrimmed proves a base address configured with a trailing
// slash cannot produce a double-slash path — the proof binds the URL it calls, so
// a mismatch between what is called and what the Auth Service reconstructs is an
// authentication failure, not a cosmetic one.
func TestTrailingSlashesAreTrimmed(t *testing.T) {
	c := New("https://public/", "https://internal/", "client-1", "https://app/callback")

	qt.Check(t, qt.IsTrue(strings.HasPrefix(c.AuthorizeURL("c", "s", ""), "https://public/authorize?")))
	qt.Check(t, qt.Equals(c.internalURL, "https://internal"))
}

// TestExchangeCodeSendsFormAndProof proves the code redemption posts the
// authorization-code grant as a form with the verifier — the PKCE half the browser
// never saw — and carries a proof of possession of the session key.
func TestExchangeCodeSendsFormAndProof(t *testing.T) {
	type captured struct {
		contentType string
		hasProof    bool
		form        url.Values
	}
	capt := make(chan captured, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capt <- captured{
			contentType: r.Header.Get("Content-Type"),
			hasProof:    r.Header.Get("DPoP") != "",
			form:        r.PostForm,
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP","expires_in":300,"refresh_token":"rt"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.URL, "client-1", "https://app/callback")
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))

	tokens, err := c.ExchangeCode(context.Background(), key, "code-1", "verifier-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(tokens.AccessToken, "at"))
	qt.Check(t, qt.Equals(tokens.RefreshToken, "rt"))

	got := <-capt
	qt.Check(t, qt.Equals(got.contentType, "application/x-www-form-urlencoded"))
	qt.Check(t, qt.IsTrue(got.hasProof))
	qt.Check(t, qt.Equals(got.form.Get("grant_type"), "authorization_code"))
	qt.Check(t, qt.Equals(got.form.Get("code"), "code-1"))
	qt.Check(t, qt.Equals(got.form.Get("code_verifier"), "verifier-1"))
	qt.Check(t, qt.Equals(got.form.Get("client_id"), "client-1"))
	qt.Check(t, qt.Equals(got.form.Get("redirect_uri"), "https://app/callback"))
}

// TestProofRetriesWithServerNonce proves the one behaviour a login silently
// depends on: when the Auth Service refuses a proof and hands back a nonce, the
// call is retried once with that nonce inside the proof. Without the retry every
// nonce-requiring deployment would fail its first token exchange, and the failure
// would look like a bad credential rather than a missing nonce.
func TestProofRetriesWithServerNonce(t *testing.T) {
	nonces := make(chan string, 2)

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonces <- proofNonce(t, r.Header.Get("DPoP"))
		calls++
		if calls == 1 {
			w.Header().Set("DPoP-Nonce", "server-nonce-1")
			w.WriteHeader(http.StatusUnauthorized)

			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.URL, "client-1", "https://app/callback")
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))

	tokens, err := c.Refresh(context.Background(), key, "rt")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(tokens.AccessToken, "at"))

	qt.Check(t, qt.Equals(<-nonces, ""))               // first attempt: no nonce known yet
	qt.Check(t, qt.Equals(<-nonces, "server-nonce-1")) // retry echoes the server's nonce
}

// TestUnauthorizedWithoutNonceIsNotRetried proves a plain rejection is reported as
// it stands: only a nonce challenge earns a second attempt, so a genuinely bad
// credential fails once instead of doubling every failed login.
func TestUnauthorizedWithoutNonceIsNotRetried(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"err:request:unauthorized"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.URL, "client-1", "https://app/callback")
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))

	_, err = c.Refresh(context.Background(), key, "rt")

	var asErr *Error
	qt.Assert(t, qt.ErrorAs(err, &asErr))
	qt.Check(t, qt.Equals(asErr.Status, http.StatusUnauthorized))
	qt.Check(t, qt.IsTrue(strings.Contains(asErr.Body, "err:request:unauthorized")))
	qt.Check(t, qt.Equals(calls, 1))
}

// TestIdentityBindsAccessToken proves the identity read presents the token as a
// sender-constrained credential and binds it into the proof, rather than sending
// it as a bearer token any holder could replay.
func TestIdentityBindsAccessToken(t *testing.T) {
	authz := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"u1","name":"A B","loa":"high","login_method":"webEid"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.URL, "client-1", "https://app/callback")
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))

	id, err := c.Identity(context.Background(), key, "access-token")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(id.Subject, "u1"))
	qt.Check(t, qt.Equals(id.LoginMethod, "webEid"))
	qt.Check(t, qt.Equals(<-authz, "DPoP access-token"))
}

// TestDefaultClientIsTraced proves the login hops carry a tracing transport
// without the caller asking: dropping it would silently take the token and
// identity calls out of the traces, and a missing span is not a failure anyone
// notices at the time.
func TestDefaultClientIsTraced(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	_, ok := c.httpc.Transport.(*otelhttp.Transport)
	qt.Check(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(c.httpc.Timeout, DefaultTimeout))
}

// TestWithHTTPClientIsHonoured proves a caller can supply its own client (its own
// timeout or transport) and that a nil one leaves the default in place.
func TestWithHTTPClientIsHonoured(t *testing.T) {
	own := &http.Client{}

	c := New("https://public", "https://internal", "client-1", "https://app/callback", WithHTTPClient(own))
	qt.Check(t, qt.Equals(c.httpc, own))

	def := New("https://public", "https://internal", "client-1", "https://app/callback", WithHTTPClient(nil))
	_, ok := def.httpc.Transport.(*otelhttp.Transport)
	qt.Check(t, qt.IsTrue(ok))
}

// TestOutboundCarriesCorrelationID proves both call paths — the plain card-login
// hop and the proof-carrying token/identity hop — forward the correlation id from
// the request context, so the login and token exchange are joinable to the
// originating request in the logs. It also proves the header is omitted entirely
// (not sent empty) when the context carries no id. The channel gives a
// happens-before between the handler and the assertions so the test is race-clean.
func TestOutboundCarriesCorrelationID(t *testing.T) {
	corrCh := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Header.Values canonicalizes the key; a direct map lookup would miss.
		if vals := r.Header.Values(propagation.HeaderCorrelationID); len(vals) > 0 {
			corrCh <- vals[0]
		} else {
			corrCh <- "<absent>"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"n","state":"s","sub":"u1"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.URL, "client-1", "https://app/callback")

	// plainDo path (card-login challenge) forwards the id on the context.
	ctx := propagation.WithCorrelationID(context.Background(), "corr-xyz")
	_, _, err := c.WebEIDChallenge(ctx, "chal", "state")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(<-corrCh, "corr-xyz"))

	// dpopDo path (identity, proof of possession) forwards it too.
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	_, err = c.Identity(ctx, key, "access-token")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(<-corrCh, "corr-xyz"))

	// No id on the context → the header is omitted, never sent empty.
	_, _, err = c.WebEIDChallenge(context.Background(), "chal", "state")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(<-corrCh, "<absent>"))
}

func TestErrorMessageCarriesStatus(t *testing.T) {
	e := &Error{Status: 409, Body: `{"code":"conflict"}`}
	qt.Check(t, qt.Equals(e.Error(), "auth service responded 409"))
}

// proofNonce reads the nonce a proof echoes, without verifying the proof — the
// test only needs to know which nonce the client put in it.
func proofNonce(t *testing.T, proof string) string {
	t.Helper()

	parts := strings.Split(proof, ".")
	qt.Assert(t, qt.Equals(len(parts), 3))

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	qt.Assert(t, qt.IsNil(err))

	var c struct {
		Nonce string `json:"nonce"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(payload, &c)))

	return c.Nonce
}
