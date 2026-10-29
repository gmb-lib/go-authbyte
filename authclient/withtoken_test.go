package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/dpop"
)

// seen is what a stub resource received on one request.
type seen struct {
	path, authorization, proof, body string
}

// resourceStub records every request and answers each with the next of the given
// answers; a request to the token endpoint is recorded as such and refused.
func resourceStub(t *testing.T, answers ...func(w http.ResponseWriter)) (*httptest.Server, func() []seen) {
	t.Helper()

	var (
		mu   sync.Mutex
		got  []seen
		next int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, r.ContentLength)
		if r.ContentLength > 0 {
			_, _ = r.Body.Read(raw)
		}

		mu.Lock()
		got = append(got, seen{path: r.URL.Path, authorization: r.Header.Get(headerAuthorization), proof: r.Header.Get(headerDPoP), body: string(raw)})
		i := next
		next++
		mu.Unlock()

		if strings.HasSuffix(r.URL.Path, "/token") || i >= len(answers) {
			w.WriteHeader(http.StatusTeapot)

			return
		}
		answers[i](w)
	}))
	t.Cleanup(srv.Close)

	return srv, func() []seen {
		mu.Lock()
		defer mu.Unlock()

		return append([]seen(nil), got...)
	}
}

func answerOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// The thumbprint a caller stamps into a token it mints for this client is the
// thumbprint of the key this client signs its proofs with.
func TestTheThumbprintIsThatOfTheClientsProofKey(t *testing.T) {
	c := newTestClient(t, "http://issuer.invalid")

	want, err := dpop.Thumbprint(&c.dpopKey.PublicKey)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(c.Thumbprint(), want))
	qt.Check(t, qt.Not(qt.Equals(c.Thumbprint(), "")))
}

// A token the caller holds is sent as it is, with a fresh proof of this client's
// key bound to that token, the method and the address: and no token is fetched.
func TestDoWithTokenSendsTheGivenTokenWithAProofOfTheClientsKey(t *testing.T) {
	srv, requests := resourceStub(t, answerOK)
	c := newTestClient(t, srv.URL)
	url := srv.URL + "/api/v1/sign-in/memberships"

	res, err := c.DoWithToken(context.Background(), "svc:rolebyte", "minted-token", http.MethodPost, url, nil, []byte(`{}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.StatusCode, http.StatusOK))
	qt.Check(t, qt.Equals(string(res.Body), `{"ok":true}`))

	got := requests()
	qt.Assert(t, qt.HasLen(got, 1), qt.Commentf("one request to the resource, none to the token endpoint: %+v", got))
	qt.Check(t, qt.Equals(got[0].authorization, "DPoP minted-token"))
	qt.Check(t, qt.Equals(got[0].body, `{}`))

	proof, err := dpop.Verify(got[0].proof, dpop.VerifyOptions{
		Method: http.MethodPost, URL: url, AccessToken: "minted-token", MaxAge: time.Minute,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(proof.Thumbprint, c.Thumbprint()))
}

// The resource's nonce challenge is answered once, with a new proof carrying the
// nonce, and the answer after it is the one returned.
func TestDoWithTokenAnswersANonceChallenge(t *testing.T) {
	challenge := func(w http.ResponseWriter) {
		w.Header().Set(headerDPoPNonce, "resource-nonce")
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv, requests := resourceStub(t, challenge, answerOK)
	c := newTestClient(t, srv.URL)
	url := srv.URL + "/api/v1/sign-in/claims"

	res, err := c.DoWithToken(context.Background(), "svc:rolebyte", "minted-token", http.MethodPost, url, nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.StatusCode, http.StatusOK))

	got := requests()
	qt.Assert(t, qt.HasLen(got, 2))
	proof, err := dpop.Verify(got[1].proof, dpop.VerifyOptions{
		Method: http.MethodPost, URL: url, AccessToken: "minted-token", MaxAge: time.Minute, RequireNonce: true,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(proof.Nonce, "resource-nonce"))
}

// An answer that is not a success is returned as it came, for the caller to
// read: it is a decision about the request, not a failure to make it.
func TestDoWithTokenReturnsARefusalAsTheAnswer(t *testing.T) {
	forbidden := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"err:request:forbidden"}`))
	}
	srv, _ := resourceStub(t, forbidden)
	c := newTestClient(t, srv.URL)

	res, err := c.DoWithToken(context.Background(), "svc:rolebyte", "minted-token", http.MethodPost, srv.URL+"/x", nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.StatusCode, http.StatusForbidden))
	qt.Check(t, qt.Equals(string(res.Body), `{"code":"err:request:forbidden"}`))
}

// No token, no call: an empty token is a fault of the caller's, refused before
// anything is sent.
func TestDoWithTokenRefusesAnEmptyToken(t *testing.T) {
	srv, requests := resourceStub(t, answerOK)
	c := newTestClient(t, srv.URL)

	_, err := c.DoWithToken(context.Background(), "svc:rolebyte", " ", http.MethodPost, srv.URL+"/x", nil, nil)
	qt.Check(t, qt.ErrorMatches(err, `.*token is empty.*`))
	qt.Check(t, qt.HasLen(requests(), 0))
}
