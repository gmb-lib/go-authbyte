package asclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-quicktest/qt"
)

// seen is what the stub Auth Service received on one call.
type seen struct {
	path          string
	basicID       string
	basicSecret   string
	hasBasic      bool
	authorization string
	form          url.Values
	body          map[string]any
}

func recordingAuthService(t *testing.T) (*httptest.Server, <-chan seen) {
	t.Helper()

	calls := make(chan seen, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := seen{path: r.URL.Path, authorization: r.Header.Get("Authorization")}
		s.basicID, s.basicSecret, s.hasBasic = r.BasicAuth()

		if r.Header.Get("Content-Type") == "application/json" {
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &s.body)
		} else {
			_ = r.ParseForm()
			s.form = r.PostForm
		}
		calls <- s

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"DPoP","expires_in":300,"refresh_token":"r"}`))
	}))
	t.Cleanup(srv.Close)

	return srv, calls
}

// A confidential client proves itself at every call it makes as itself: by HTTP
// Basic where the request carries no access token (the token endpoint and
// revocation), and in the body of the step-up, whose Authorization header
// carries the person's access token. The secret never travels in the form.
func TestAConfidentialClientProvesItselfAtEveryCall(t *testing.T) {
	srv, calls := recordingAuthService(t)
	c := New("https://public", srv.URL, "client-1", "https://app/callback", WithClientSecret("s3cret"))
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	ctx := context.Background()

	_, err = c.ExchangeCode(ctx, key, "code-1", "verifier-1")
	qt.Assert(t, qt.IsNil(err))
	_, err = c.Refresh(ctx, key, "refresh-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(c.Revoke(ctx, key, "refresh-1")))

	for _, path := range []string{"/token", "/token", "/revoke"} {
		got := <-calls
		qt.Check(t, qt.Equals(got.path, path))
		qt.Check(t, qt.IsTrue(got.hasBasic), qt.Commentf("%s carries no HTTP Basic credentials", path))
		qt.Check(t, qt.Equals(got.basicID, "client-1"))
		qt.Check(t, qt.Equals(got.basicSecret, "s3cret"))
		qt.Check(t, qt.Equals(got.form.Get("client_secret"), ""), qt.Commentf("%s sends the secret in the form too", path))
	}

	_, _, err = c.StepUp(ctx, key, "access-1", StepUpRequest{RefreshToken: "refresh-1", ClientID: "client-1", Method: "webEid"})
	qt.Assert(t, qt.IsNil(err))

	got := <-calls
	qt.Check(t, qt.Equals(got.path, "/step-up"))
	qt.Check(t, qt.Equals(got.authorization, "DPoP access-1"))
	qt.Check(t, qt.Equals(got.body["client_secret"], any("s3cret")))
	qt.Check(t, qt.Equals(got.body["client_id"], any("client-1")))
	qt.Check(t, qt.Equals(got.body["refresh_token"], any("refresh-1")))
}

// The client id and the secret are each form-encoded before the Basic encoding
// [RFC 6749 §2.3.1], so a colon in either cannot move the boundary between them.
func TestTheBasicCredentialsAreFormEncoded(t *testing.T) {
	srv, calls := recordingAuthService(t)
	c := New("https://public", srv.URL, "svc:edge", "https://app/callback", WithClientSecret("a b:c"))
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))

	_, err = c.Refresh(context.Background(), key, "refresh-1")
	qt.Assert(t, qt.IsNil(err))

	got := <-calls
	qt.Check(t, qt.Equals(got.basicID, "svc%3Aedge"))
	qt.Check(t, qt.Equals(got.basicSecret, "a+b%3Ac"))
}

// A public client has no secret and sends none, as before.
func TestAPublicClientSendsNoSecret(t *testing.T) {
	srv, calls := recordingAuthService(t)
	c := New("https://public", srv.URL, "client-1", "https://app/callback")
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	ctx := context.Background()

	_, err = c.Refresh(ctx, key, "refresh-1")
	qt.Assert(t, qt.IsNil(err))
	got := <-calls
	qt.Check(t, qt.IsFalse(got.hasBasic))
	qt.Check(t, qt.Equals(got.authorization, ""))

	_, _, err = c.StepUp(ctx, key, "access-1", StepUpRequest{RefreshToken: "refresh-1", ClientID: "client-1", Method: "webEid"})
	qt.Assert(t, qt.IsNil(err))
	got = <-calls
	_, has := got.body["client_secret"]
	qt.Check(t, qt.IsFalse(has))
}
