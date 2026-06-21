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
