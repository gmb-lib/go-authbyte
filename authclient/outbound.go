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

	"azugo.io/azugo"
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
	body, err := c.doWithDPoP(ctx, audience, scope, http.MethodGet, fullURL, nil)
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

	body, err := c.doWithDPoP(ctx, audience, scope, http.MethodPost, fullURL, reqBody)
	if err != nil {
		return err
	}

	if len(body) > 0 && out != nil {
		return json.Unmarshal(body, out)
	}

	return nil
}

// doWithDPoP issues the request through the framework HTTP client (preserving
// tracing/deadlines), attaching the service token and a fresh DPoP proof, and
// retries once on a resource DPoP-Nonce challenge.
func (c *Client) doWithDPoP(ctx *azugo.Context, audience, scope, method, fullURL string, body []byte) ([]byte, error) {
	token, err := c.AcquireServiceToken(ctx, audience, scope)
	if err != nil {
		return nil, err
	}

	hc := ctx.HTTPClient()
	method = strings.ToUpper(method)

	for attempt := 0; attempt < 2; attempt++ {
		proof, err := dpop.GenerateProof(c.dpopKey, method, fullURL, token, c.resourceNonce(audience))
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
			c.setResourceNonce(audience, challengeNonce)

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
