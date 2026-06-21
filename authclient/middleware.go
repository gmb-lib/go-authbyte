package authclient

import (
	"errors"
	"strings"

	"azugo.io/azugo"
)

// Inbound header names.
const (
	headerAuthorization = "Authorization"
	headerDPoP          = "DPoP"
	headerDPoPNonce     = "DPoP-Nonce"
	headerWWWAuth       = "WWW-Authenticate"
)

// Authenticate returns middleware that requires a valid DPoP-bound token. On
// any validation failure it returns the appropriate 401/403 and stops the
// chain; a missing/stale nonce yields a 401 carrying a fresh DPoP-Nonce so the
// caller can transparently retry.
func (c *Client) Authenticate() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if !c.handle(ctx) {
				return
			}

			next(ctx)
		}
	}
}

// TryAuthenticate behaves like Authenticate when an Authorization header is
// present, but lets anonymous requests through untouched.
func (c *Client) TryAuthenticate() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if ctx.Header.Get(headerAuthorization) == "" {
				next(ctx)

				return
			}

			if !c.handle(ctx) {
				return
			}

			next(ctx)
		}
	}
}

// handle runs validation and writes any error/challenge response. It returns
// true when the request should proceed to the next handler.
func (c *Client) handle(ctx *azugo.Context) bool {
	tokenStr := bearerToken(ctx.Header.Get(headerAuthorization))

	res, err := c.validate(ctx, tokenStr)
	if err != nil {
		ctx.Error(err)

		var de dpopError
		if errors.As(err, &de) {
			ctx.Header.Set(headerWWWAuth, `DPoP error="`+de.code+`"`)
		}

		return false
	}

	if res.needNonce {
		ctx.Error(errUnauthorized)
		ctx.Header.Set(headerDPoPNonce, res.nonceToSend)
		ctx.Header.Set(headerWWWAuth, `DPoP error="use_dpop_nonce"`)

		return false
	}

	ctx.SetUser(res.user)

	return true
}

// bearerToken strips a "DPoP" or "Bearer" auth scheme prefix, returning the
// raw token. It is lenient: a bare token with no scheme is returned as-is.
func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}

	if scheme, tok, ok := strings.Cut(header, " "); ok {
		switch strings.ToLower(scheme) {
		case "dpop", "bearer":
			return strings.TrimSpace(tok)
		}
	}

	return header
}
