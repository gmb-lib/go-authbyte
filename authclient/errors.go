package authclient

import (
	corehttp "azugo.io/core/http"
	"github.com/valyala/fasthttp"
)

// dpopError is a 401 that additionally signals a DPoP-specific WWW-Authenticate
// error code to the client.
type dpopError struct {
	code string
}

func (dpopError) Error() string { return "invalid dpop proof" }

// StatusCode implements the response status interface.
func (dpopError) StatusCode() int { return fasthttp.StatusUnauthorized }

var (
	// errUnauthorized is a plain 401 (bad/missing token).
	errUnauthorized = corehttp.UnauthorizedError{}
	// errInvalidDPoP is a 401 with error="invalid_dpop_proof".
	errInvalidDPoP = dpopError{code: "invalid_dpop_proof"}
)

// refusal pairs the 401 the caller gets with the reason this service refused.
//
// The wire answer must not say which check failed — telling a caller whether it
// was the signature, the audience or the clock hands an attacker half the answer
// — but a service that cannot say it *anywhere* cannot be diagnosed either. So
// the reason travels inward, to this service's own log, and never outward.
type refusal struct {
	public error  // what the caller is told
	reason string // what this service knows
	cause  error  // the underlying error, when there is one
}

func (r refusal) Error() string { return r.public.Error() }

// Unwrap exposes the public error, so the caller-facing classification (a plain
// 401 vs a DPoP-coded one) still works through errors.As.
func (r refusal) Unwrap() error { return r.public }

// refuse wraps a public 401 with the reason behind it. cause may be nil.
func refuse(public error, reason string, cause error) error {
	return refusal{public: public, reason: reason, cause: cause}
}
