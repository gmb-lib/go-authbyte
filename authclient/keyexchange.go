package authclient

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/gmb-lib/go-authbyte/apikeys"
)

// ExchangeKey exchanges an API key a caller presented to this service for a token toward audience
// [RFC 8693 §2.1]: this client authenticates with its own credentials and DPoP proof, as for every
// exchange, and names the key's type, apikeys.TokenType, so the authority checks it as a key. The token
// is bound to this client's key, so DoWithToken presents it.
//
// It answers the token and the lifetime the authority gave it, and caches nothing: how long a token made
// from a key may be reused is the calling service's decision, as the key can be taken away at any
// moment. A refusal is an *Error at HopToken, its RetryAfter set when the authority refused for load.
func (c *Client) ExchangeKey(ctx context.Context, audience, scope string, key apikeys.Secret) (string, time.Duration, error) {
	if key.Reveal() == "" {
		return "", 0, errors.New("auth-client: the key is empty")
	}

	form := url.Values{}
	form.Set("grant_type", grantTokenExchange)
	form.Set("client_id", c.cfg.ServiceClientID)
	form.Set("client_secret", c.cfg.ServiceClientSecret)
	form.Set("audience", audience)
	form.Set("subject_token", key.Reveal())
	form.Set("subject_token_type", apikeys.TokenType)
	if scope != "" {
		form.Set("scope", scope)
	}

	return c.postTokenForm(ctx, form)
}
