package authclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

// The reason a request was refused must reach this service's log and NOT the
// caller. If it ever leaks outward, a caller learns which check it failed and can
// walk a forged token toward acceptance one guess at a time.
func TestRefusalNeverCarriesTheReasonOutward(t *testing.T) {
	err := refuse(errUnauthorized, "token rejected", errors.New("token is expired by 3m21s"))

	qt.Assert(t, qt.IsFalse(strings.Contains(err.Error(), "expired")))
	qt.Assert(t, qt.IsFalse(strings.Contains(err.Error(), "token rejected")))
	qt.Assert(t, qt.Equals(err.Error(), errUnauthorized.Error()))
}

// …while the service itself can still read it, which is the whole point: an
// expired service token and a forged one used to be the same log line.
func TestRefusalCarriesTheReasonInward(t *testing.T) {
	cause := errors.New("audience mismatch")
	err := refuse(errUnauthorized, "token rejected", cause)

	var rf refusal
	qt.Assert(t, qt.IsTrue(errors.As(err, &rf)))
	qt.Assert(t, qt.Equals(rf.reason, "token rejected"))
	qt.Assert(t, qt.ErrorIs(rf.cause, cause))
}

// Wrapping must not cost the caller-facing classification: a DPoP refusal still
// has to be recognised as one, or the client stops being told to fix its proof.
func TestRefusalKeepsTheDPoPClassification(t *testing.T) {
	err := refuse(errInvalidDPoP, "DPoP proof did not verify", nil)

	var de dpopError
	qt.Assert(t, qt.IsTrue(errors.As(err, &de)))
	qt.Assert(t, qt.Equals(de.code, "invalid_dpop_proof"))

	// And a plain 401 must NOT be mistaken for a DPoP one.
	var de2 dpopError
	qt.Assert(t, qt.IsFalse(errors.As(refuse(errUnauthorized, "no token on the request", nil), &de2)))
}

// A refusal with no underlying error is ordinary — several checks fail on their
// own terms — and must not panic or invent a cause.
func TestRefusalToleratesNoCause(t *testing.T) {
	var rf refusal
	qt.Assert(t, qt.IsTrue(errors.As(refuse(errInvalidDPoP, "replay", nil), &rf)))
	qt.Assert(t, qt.IsNil(rf.cause))
}
