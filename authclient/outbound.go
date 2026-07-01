package authclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/dpop"
	"github.com/gmb-lib/go-platform-kit/propagation"

	"azugo.io/azugo"
)

// RFC 8693 token exchange: the grant + the access-token type URI used for the
// subject token, when acquiring a token that acts on behalf of a user.
const (
	grantTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// tokenResponse is the OAuth2 token-endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// AcquireServiceToken returns a DPoP-bound service token for the given target
// audience and scope, minting one via client-credentials if none is cached or
// the cached one is near expiry. Tokens are cached per (audience, scope) and
// refreshed early (ServiceTokenEarlyRefresh before exp).
func (c *Client) AcquireServiceToken(ctx context.Context, audience, scope string) (string, error) {
	key := audience + "|" + scope

	c.mu.Lock()
	if t, ok := c.tokens[key]; ok && time.Until(t.exp) > c.cfg.ServiceTokenEarlyRefresh {
		tok := t.token
		c.mu.Unlock()

		return tok, nil
	}
	c.mu.Unlock()

	tok, ttl, err := c.requestServiceToken(ctx, audience, scope)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.tokens[key] = &cachedToken{token: tok, exp: time.Now().Add(ttl)}
	c.mu.Unlock()

	return tok, nil
}

// AcquireDelegatedToken returns a DPoP-bound token that acts on behalf of the
// end user (subjectSub) toward the target audience + scope, minting one via RFC
// 8693 token exchange (presenting subjectToken) if none is cached or the cached
// one is near expiry. Tokens are cached per (audience, scope, subject): the
// minted token is bound to this service's own key, so it stays reusable across
// different subject tokens for the same user until it expires.
func (c *Client) AcquireDelegatedToken(ctx context.Context, audience, scope, subjectSub, subjectToken string) (string, error) {
	key := "obo|" + audience + "|" + scope + "|" + subjectSub

	c.mu.Lock()
	if t, ok := c.tokens[key]; ok && time.Until(t.exp) > c.cfg.ServiceTokenEarlyRefresh {
		tok := t.token
		c.mu.Unlock()

		return tok, nil
	}
	c.mu.Unlock()

	tok, ttl, err := c.requestDelegatedToken(ctx, audience, scope, subjectToken)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.tokens[key] = &cachedToken{token: tok, exp: time.Now().Add(ttl)}
	c.mu.Unlock()

	return tok, nil
}

// requestServiceToken performs the client-credentials hop against the auth
// service /token endpoint, handling the DPoP-Nonce challenge transparently.
func (c *Client) requestServiceToken(ctx context.Context, audience, scope string) (string, time.Duration, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.cfg.ServiceClientID)
	form.Set("client_secret", c.cfg.ServiceClientSecret)
	form.Set("audience", audience)
	if scope != "" {
		form.Set("scope", scope)
	}

	return c.postTokenForm(ctx, form)
}

// requestDelegatedToken performs the RFC 8693 token-exchange hop: this service
// (authenticating with its own client credentials + DPoP key) exchanges the
// presented user subject token for a token that acts on the user's behalf
// toward the audience.
func (c *Client) requestDelegatedToken(ctx context.Context, audience, scope, subjectToken string) (string, time.Duration, error) {
	form := url.Values{}
	form.Set("grant_type", grantTokenExchange)
	form.Set("client_id", c.cfg.ServiceClientID)
	form.Set("client_secret", c.cfg.ServiceClientSecret)
	form.Set("audience", audience)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeAccessToken)
	if scope != "" {
		form.Set("scope", scope)
	}

	return c.postTokenForm(ctx, form)
}

// postTokenForm posts a form to the auth service /token endpoint, attaching a
// fresh DPoP proof and retrying once on a server DPoP-Nonce challenge, and
// returns the issued token + its lifetime.
func (c *Client) postTokenForm(ctx context.Context, form url.Values) (string, time.Duration, error) {
	var serverNonce string

	for attempt := 0; attempt < 2; attempt++ {
		proof, err := dpop.GenerateProof(c.dpopKey, http.MethodPost, c.tokenURL, "", serverNonce)
		if err != nil {
			return "", 0, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(headerDPoP, proof)

		resp, err := c.httpc.Do(req)
		if err != nil {
			return "", 0, fmt.Errorf("auth-client: token request failed: %w", err)
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			if n := resp.Header.Get(headerDPoPNonce); n != "" && attempt == 0 {
				serverNonce = n

				continue
			}
		}

		if resp.StatusCode/100 != 2 {
			return "", 0, fmt.Errorf("auth-client: token endpoint returned %d: %s", resp.StatusCode, body)
		}

		var tr tokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			return "", 0, fmt.Errorf("auth-client: invalid token response: %w", err)
		}

		return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
	}

	return "", 0, fmt.Errorf("auth-client: token endpoint did not satisfy nonce challenge")
}

// GetJSON performs a DPoP-bound, service-token-authenticated GET to fullURL on
// behalf of this service, unmarshalling a JSON response into v. The DPoP-Nonce
// challenge from the target resource is handled transparently.
func (c *Client) GetJSON(ctx *azugo.Context, audience, scope, fullURL string, v any) error {
	token, err := c.AcquireServiceToken(ctx, audience, scope)
	if err != nil {
		return err
	}

	body, err := c.doWithDPoP(ctx, audience, token, http.MethodGet, fullURL, nil)
	if err != nil {
		return err
	}

	if len(body) > 0 && v != nil {
		return json.Unmarshal(body, v)
	}

	return nil
}

// PostJSON performs a DPoP-bound, service-token-authenticated POST of a JSON
// body to fullURL, unmarshalling a JSON response into out (may be nil).
func (c *Client) PostJSON(ctx *azugo.Context, audience, scope, fullURL string, in, out any) error {
	reqBody, err := json.Marshal(in)
	if err != nil {
		return err
	}

	token, err := c.AcquireServiceToken(ctx, audience, scope)
	if err != nil {
		return err
	}

	body, err := c.doWithDPoP(ctx, audience, token, http.MethodPost, fullURL, reqBody)
	if err != nil {
		return err
	}

	if len(body) > 0 && out != nil {
		return json.Unmarshal(body, out)
	}

	return nil
}

// GetJSONOnBehalf is GetJSON acting on behalf of the end user (subjectSub),
// using a delegated token obtained by exchanging subjectToken (RFC 8693). The
// callee owner-filters on the user subject exactly as for a direct user call.
func (c *Client) GetJSONOnBehalf(ctx *azugo.Context, audience, scope, subjectSub, subjectToken, fullURL string, v any) error {
	tok, err := c.AcquireDelegatedToken(ctx, audience, scope, subjectSub, subjectToken)
	if err != nil {
		return err
	}

	body, err := c.doWithDPoP(ctx, audience, tok, http.MethodGet, fullURL, nil)
	if err != nil {
		return err
	}

	if len(body) > 0 && v != nil {
		return json.Unmarshal(body, v)
	}

	return nil
}

// PostJSONOnBehalf is PostJSON acting on behalf of the end user (subjectSub),
// using a delegated token obtained by exchanging subjectToken (RFC 8693).
func (c *Client) PostJSONOnBehalf(ctx *azugo.Context, audience, scope, subjectSub, subjectToken, fullURL string, in, out any) error {
	reqBody, err := json.Marshal(in)
	if err != nil {
		return err
	}

	tok, err := c.AcquireDelegatedToken(ctx, audience, scope, subjectSub, subjectToken)
	if err != nil {
		return err
	}

	body, err := c.doWithDPoP(ctx, audience, tok, http.MethodPost, fullURL, reqBody)
	if err != nil {
		return err
	}

	if len(body) > 0 && out != nil {
		return json.Unmarshal(body, out)
	}

	return nil
}

// doWithDPoP issues the request through the framework HTTP client (preserving
// tracing/deadlines), attaching the given token and a fresh DPoP proof, and
// retries once on a resource DPoP-Nonce challenge. nonceKey scopes the cached
// resource nonce (the target audience).
func (c *Client) doWithDPoP(ctx *azugo.Context, nonceKey, token, method, fullURL string, body []byte) ([]byte, error) {
	hc := ctx.HTTPClient()
	method = strings.ToUpper(method)

	for attempt := 0; attempt < 2; attempt++ {
		proof, err := dpop.GenerateProof(c.dpopKey, method, fullURL, token, c.resourceNonce(nonceKey))
		if err != nil {
			return nil, err
		}

		req := hc.NewRequest()
		if err := req.SetRequestURL(fullURL); err != nil {
			hc.ReleaseRequest(req)

			return nil, err
		}
		req.Header.SetMethod(method)
		req.Header.Set(headerAuthorization, "DPoP "+token)
		req.Header.Set(headerDPoP, proof)
		// Carry the correlation id across the hop (the framework client sets
		// traceparent automatically; the correlation id is ours to attach).
		if cid := propagation.CorrelationID(ctx); cid != "" {
			req.Header.Set(propagation.HeaderCorrelationID, cid)
		}
		if body != nil {
			req.SetBodyRaw(body)
			req.Header.SetContentType("application/json")
		}

		resp := hc.NewResponse()
		derr := hc.Do(req, resp)

		status := resp.StatusCode()
		challengeNonce := string(resp.Header.Peek(headerDPoPNonce))
		respBody, _ := resp.BodyUncompressed()
		out := append([]byte(nil), respBody...)

		hc.ReleaseRequest(req)
		hc.ReleaseResponse(resp)

		if derr != nil {
			return nil, derr
		}

		if status == http.StatusUnauthorized && challengeNonce != "" && attempt == 0 {
			c.setResourceNonce(nonceKey, challengeNonce)

			continue
		}

		if status/100 != 2 {
			return nil, fmt.Errorf("auth-client: %s %s returned %d", method, fullURL, status)
		}

		return out, nil
	}

	return nil, fmt.Errorf("auth-client: %s %s failed after nonce retry", method, fullURL)
}

func (c *Client) resourceNonce(audience string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.nonces[audience]
}

func (c *Client) setResourceNonce(audience, nonce string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nonces[audience] = nonce
}
