package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/apikeys"
	"github.com/gmb-lib/go-authbyte/dpop"
)

// keyStub is a token endpoint that records each exchange's form and proof and answers with the next
// of the given answers, the last one repeated.
type keyStub struct {
	server  *httptest.Server
	mu      sync.Mutex
	forms   []map[string]string
	proofs  []string
	answers []func(w http.ResponseWriter)
}

func newKeyStub(t *testing.T, answers ...func(w http.ResponseWriter)) *keyStub {
	t.Helper()

	s := &keyStub{answers: answers}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		got := map[string]string{}
		for k := range r.PostForm {
			got[k] = r.PostForm.Get(k)
		}

		s.mu.Lock()
		s.forms = append(s.forms, got)
		s.proofs = append(s.proofs, r.Header.Get(headerDPoP))
		i := min(len(s.forms), len(s.answers)) - 1
		s.mu.Unlock()

		s.answers[i](w)
	}))
	t.Cleanup(s.server.Close)

	return s
}

func (s *keyStub) seen() ([]map[string]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]map[string]string(nil), s.forms...), append([]string(nil), s.proofs...)
}

func answerPass(token string, expiresIn int) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "DPoP", "expires_in": expiresIn})
	}
}

func presentedKey(t *testing.T) apikeys.Secret {
	t.Helper()

	s, err := apikeys.NewScheme(apikeys.Config{Scheme: "tk"})
	qt.Assert(t, qt.IsNil(err))
	m, err := s.Mint()
	qt.Assert(t, qt.IsNil(err))
	key, err := s.Presented(m.Key.Reveal())
	qt.Assert(t, qt.IsNil(err))

	return key
}

// The exchange names the key and its type, the audience and the scope, and authenticates as this
// client with a proof of its own key: the token that comes back is bound to the key DoWithToken signs
// with.
func TestExchangeKeySendsTheKeyAsItsOwnTypeWithAProofOfTheClientsKey(t *testing.T) {
	stub := newKeyStub(t, answerPass("the-pass", 600))
	c := newTestClient(t, stub.server.URL)
	key := presentedKey(t)

	tok, ttl, err := c.ExchangeKey(context.Background(), "svc:api", "a:view b:edit", key)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(tok, "the-pass"))
	qt.Check(t, qt.Equals(ttl, 600*time.Second))

	forms, proofs := stub.seen()
	qt.Assert(t, qt.HasLen(forms, 1))
	qt.Check(t, qt.DeepEquals(forms[0], map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"client_id":          "svc:caller",
		"client_secret":      "secret",
		"audience":           "svc:api",
		"scope":              "a:view b:edit",
		"subject_token":      key.Reveal(),
		"subject_token_type": "urn:gmb:params:oauth:token-type:api-key",
	}))

	proof, err := dpop.Verify(proofs[0], dpop.VerifyOptions{
		Method: http.MethodPost, URL: stub.server.URL + "/token", MaxAge: time.Minute,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(proof.Thumbprint, c.Thumbprint()))
}

// Nothing is cached: each call is an exchange, so a key taken away is refused at the next one.
func TestExchangeKeyCachesNothing(t *testing.T) {
	stub := newKeyStub(t, answerPass("first", 600), answerPass("second", 600))
	c := newTestClient(t, stub.server.URL)
	key := presentedKey(t)

	first, _, err := c.ExchangeKey(context.Background(), "svc:api", "a:view", key)
	qt.Assert(t, qt.IsNil(err))
	second, _, err := c.ExchangeKey(context.Background(), "svc:api", "a:view", key)
	qt.Assert(t, qt.IsNil(err))

	forms, _ := stub.seen()
	qt.Check(t, qt.HasLen(forms, 2))
	qt.Check(t, qt.Equals(first, "first"))
	qt.Check(t, qt.Equals(second, "second"))
}

// A key refused, and a refusal for load: each is an answer at the token hop, and the second says when
// to ask again.
func TestExchangeKeyReturnsARefusalWithItsRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		retryAfter string
	}{
		{"the key refused", http.StatusBadRequest, ""},
		{"too many attempts", http.StatusTooManyRequests, "7"},
		{"too many checks at once", http.StatusServiceUnavailable, "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newKeyStub(t, func(w http.ResponseWriter) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			})

			_, _, err := newTestClient(t, stub.server.URL).ExchangeKey(context.Background(), "svc:api", "a:view", presentedKey(t))

			var refused *Error
			qt.Assert(t, qt.IsTrue(errors.As(err, &refused)))
			qt.Check(t, qt.Equals(refused.Hop, HopToken))
			qt.Check(t, qt.Equals(refused.Status, tc.status))
			qt.Check(t, qt.Equals(refused.RetryAfter, tc.retryAfter))
		})
	}
}

// The authority's nonce challenge is answered once, as for every exchange.
func TestExchangeKeyAnswersANonceChallenge(t *testing.T) {
	stub := newKeyStub(t, func(w http.ResponseWriter) {
		w.Header().Set(headerDPoPNonce, "n-1")
		w.WriteHeader(http.StatusUnauthorized)
	}, answerPass("the-pass", 60))

	c := newTestClient(t, stub.server.URL)

	tok, _, err := c.ExchangeKey(context.Background(), "svc:api", "a:view", presentedKey(t))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(tok, "the-pass"))

	_, proofs := stub.seen()
	qt.Assert(t, qt.HasLen(proofs, 2))
	proof, err := dpop.Verify(proofs[1], dpop.VerifyOptions{
		Method: http.MethodPost, URL: stub.server.URL + "/token", MaxAge: time.Minute, RequireNonce: true,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(proof.Nonce, "n-1"))
	qt.Check(t, qt.Equals(proof.Thumbprint, c.Thumbprint()))
}

// An empty key is refused before anything is sent: an exchange naming no subject would be a request
// for this client's own grant.
func TestExchangeKeyRefusesAnEmptyKey(t *testing.T) {
	stub := newKeyStub(t, answerPass("the-pass", 60))

	_, _, err := newTestClient(t, stub.server.URL).ExchangeKey(context.Background(), "svc:api", "a:view", apikeys.Secret{})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsFalse(strings.Contains(err.Error(), "the-pass")))

	forms, _ := stub.seen()
	qt.Check(t, qt.HasLen(forms, 0))
}
