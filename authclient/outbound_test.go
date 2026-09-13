package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-quicktest/qt"
)

// tokenStub serves the token endpoint with a fixed answer, so a test can say
// exactly what the auth service said and assert what the caller could learn
// from it.
func tokenStub(status int, header map[string]string, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// A refusal is an answer, and the caller has to be able to read it. Until the
// status and the body are on the error value itself they exist only inside a
// message string, so every caller reports "the service is unavailable" for a
// request that was in fact answered — truthfully, and with something the person
// could have acted on.
func TestATokenRefusalIsReadableByTheCaller(t *testing.T) {
	const body = `{"code":"err:membership:notMember","title":"Forbidden"}`

	srv := tokenStub(http.StatusForbidden, map[string]string{"Content-Type": "application/problem+json"}, body)
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).AcquireServiceToken(context.Background(), "svc:target", "things:read")

	var refused *Error
	qt.Assert(t, qt.IsTrue(errors.As(err, &refused)))
	qt.Assert(t, qt.Equals(refused.Status, http.StatusForbidden))
	qt.Assert(t, qt.Equals(refused.Body, body))
	qt.Assert(t, qt.Equals(refused.Hop, HopToken))
}

// The on-behalf lane presents the person's own token, so a refusal there is an
// answer about *them* — the one an edge most needs to relay rather than replace.
func TestADelegatedExchangeRefusalIsReadableToo(t *testing.T) {
	const body = `{"code":"err:grant:notPermitted"}`

	srv := tokenStub(http.StatusForbidden, nil, body)
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).AcquireDelegatedToken(context.Background(),
		"svc:target", "projects:log", "PNOLV-010180-15097", "the-persons-token")

	var refused *Error
	qt.Assert(t, qt.IsTrue(errors.As(err, &refused)))
	qt.Assert(t, qt.Equals(refused.Status, http.StatusForbidden))
	qt.Assert(t, qt.Equals(refused.Body, body))
}

// The half that costs something: a request that was never answered is NOT a
// refusal, and must not be readable as one. A suite that proves only the case
// above passes just as well against a client that types every failure alike —
// which would tell a caller it was refused when nothing ever heard it.
func TestAFailureToReachTheServiceIsNotARefusal(t *testing.T) {
	srv := tokenStub(http.StatusOK, nil, "")
	c := newTestClient(t, srv.URL)
	srv.Close() // nothing is listening at that address any more

	_, err := c.AcquireServiceToken(context.Background(), "svc:target", "things:read")

	qt.Assert(t, qt.IsNotNil(err))

	var refused *Error
	qt.Assert(t, qt.IsFalse(errors.As(err, &refused)))
}

// An answer that is not a token but is not a refusal either — a 200 carrying
// something that is not a token response — is a broken service, not a decision
// about the caller, and must not read as one.
func TestAnUnreadableTokenAnswerIsNotARefusal(t *testing.T) {
	srv := tokenStub(http.StatusOK, map[string]string{"Content-Type": "application/json"}, "not json at all")
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).AcquireServiceToken(context.Background(), "svc:target", "things:read")

	qt.Assert(t, qt.IsNotNil(err))

	var refused *Error
	qt.Assert(t, qt.IsFalse(errors.As(err, &refused)))
}

// The server asking for a nonce answers 401 as well, and it is not a refusal at
// all — it is one half of a handshake the client completes by itself. If that
// 401 were reported as a refusal, every caller would see an authorization
// failure on a request that then succeeds.
func TestANonceChallengeIsAnsweredRatherThanReportedAsARefusal(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set(headerDPoPNonce, "server-nonce")
			w.WriteHeader(http.StatusUnauthorized)

			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 300})
	}))
	defer srv.Close()

	tok, err := newTestClient(t, srv.URL).AcquireServiceToken(context.Background(), "svc:target", "things:read")

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(tok, "tok"))
	qt.Assert(t, qt.Equals(attempts.Load(), int32(2)))
}

// …and the mirror of it: a 401 with no nonce to answer IS a refusal. An expired
// or unaccepted credential and a nonce handshake are the same status, and a
// caller that cannot tell them apart cannot act on either.
func TestAnUnauthorizedWithNoChallengeIsARefusal(t *testing.T) {
	srv := tokenStub(http.StatusUnauthorized, nil, `{"code":"err:request:unauthorized"}`)
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).AcquireServiceToken(context.Background(), "svc:target", "things:read")

	var refused *Error
	qt.Assert(t, qt.IsTrue(errors.As(err, &refused)))
	qt.Assert(t, qt.Equals(refused.Status, http.StatusUnauthorized))
}

// What the error SAYS must not repeat what the service sent. The body can carry
// an upstream's own wording, and an error message is written to logs by callers
// who never chose to publish it — so the message states the fact, and the body
// stays a field the caller reads deliberately.
func TestTheMessageStatesTheFactWithoutRepeatingTheBody(t *testing.T) {
	err := &Error{Hop: HopToken, Status: http.StatusForbidden, Body: `{"detail":"a secret of some kind"}`}

	qt.Assert(t, qt.IsFalse(strings.Contains(err.Error(), "secret")))
	qt.Assert(t, qt.StringContains(err.Error(), "403"))
}
