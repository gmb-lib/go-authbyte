package authclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gmb-lib/go-authbyte/dpop"
)

// BackgroundResponse is the result of a background (non-request-scoped)
// service-to-service call made via DoService.
type BackgroundResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// DoService performs a DPoP-bound, service-token-authenticated request to
// fullURL from a background context — the counterpart of the request-scoped
// GetJSON/PostJSON for callers that have no *azugo.Context (e.g. a core.Tasker
// background job such as the web-eid engine's trust-bundle sync). It acquires
// and caches the service token for (audience, scope), attaches a fresh DPoP
// proof, transparently retries once on a resource DPoP-Nonce challenge, and
// returns the raw status/headers/body so the caller can act on a 304 / ETag
// itself. It uses the client's own net/http transport (not the framework
// request client).
func (c *Client) DoService(ctx context.Context, audience, scope, method, fullURL string, reqHeader http.Header, body []byte) (*BackgroundResponse, error) {
	token, err := c.AcquireServiceToken(ctx, audience, scope)
	if err != nil {
		return nil, err
	}

	method = strings.ToUpper(method)

	for attempt := 0; attempt < 2; attempt++ {
		proof, err := dpop.GenerateProof(c.dpopKey, method, fullURL, token, c.resourceNonce(audience))
		if err != nil {
			return nil, err
		}

		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
		if err != nil {
			return nil, err
		}
		for k, vs := range reqHeader {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		req.Header.Set(headerAuthorization, "DPoP "+token)
		req.Header.Set(headerDPoP, proof)
		if body != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("auth-client: %s %s: %w", method, fullURL, err)
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<24))
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			if n := resp.Header.Get(headerDPoPNonce); n != "" && attempt == 0 {
				c.setResourceNonce(audience, n)

				continue
			}
		}

		return &BackgroundResponse{
			StatusCode: resp.StatusCode,
			Header:     resp.Header.Clone(),
			Body:       respBody,
		}, nil
	}

	return nil, fmt.Errorf("auth-client: %s %s failed after nonce retry", method, fullURL)
}
