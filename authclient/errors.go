package authclient

import (
	"fmt"

	corehttp "azugo.io/core/http"
	"github.com/valyala/fasthttp"
)

// Hop names which call answered, for the outbound helpers below. One helper
// call makes two: it asks the auth service for a token, then presents that
// token to the target service. The same status means different things at each —
// the first is about this service's own standing, the second about the request
// it went on to make — and the caller cannot tell them apart from the call
// site, because it made one call. So the answer says which one it came from.
type Hop string

const (
	// HopToken is the call to the auth service's token endpoint.
	HopToken Hop = "token"
	// HopResource is the call to the target service, carrying the token.
	HopResource Hop = "resource"
)

// Error is a non-2xx answer to one of those calls: the service was reached, it
// understood the request, and it answered. That is a decision about the
// request, not a failure to make it — and the difference is the whole reason
// this type exists. A caller that cannot tell the two apart has to report the
// worse of them, so a person who was given a true, actionable answer is told
// instead that something is broken.
//
// It satisfies error, so existing handling keeps working unchanged; a caller
// that wants the answer reaches it with errors.As:
//
//	var refused *authclient.Error
//	if errors.As(err, &refused) && refused.Status < 500 {
//	    // the request was refused, and refused.Body carries the reason
//	}
//
// A request that was never answered — the service unreachable, the connection
// lost, the deadline passed — is NOT this type. Body is the answer's body as it
// arrived, up to the client's read limit; it is the sender's own words, so
// treat it as data and decide deliberately what, if anything, to pass on.
type Error struct {
	// Hop is which of the two calls answered.
	Hop Hop
	// Status is the HTTP status it answered with.
	Status int
	// Body is the answer's body, unparsed.
	Body string
}

// Error states the fact and nothing else. The body can carry another service's
// own wording, and an error message ends up in logs kept by callers who never
// chose to publish it — so it stays in its field, where reading it is a
// decision.
func (e *Error) Error() string {
	return fmt.Sprintf("auth-client: the %s call responded %d", e.Hop, e.Status)
}

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
