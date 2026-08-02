// Package asclient drives the Auth Service from a confidential back-end on a
// user's behalf: it builds the browser authorization redirect, redeems the
// authorization code for a sender-constraint-bound token, refreshes it, reads the
// user's identity, drives a card login, and requests a step-up. Every server-side
// call proves possession of a per-session key, retrying once on a fresh server
// nonce.
//
// This is the back-end half of a browser login. The key it proves belongs to one
// user session and is held by the calling service — the browser never sees a
// token, a key or a secret. Sender-constraint proof generation itself comes from
// the dpop package; only the authorization-code orchestration lives here.
package asclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/dpop"
	"github.com/gmb-lib/go-platform-kit/propagation"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// DefaultTimeout bounds each call to the Auth Service when a caller supplies no
// HTTP client of its own.
const DefaultTimeout = 30 * time.Second

// Client is a confidential back-end client of the Auth Service. The browser-facing
// authorization redirect uses the public address; the server-side token, identity,
// and step-up calls use the in-network address, which is also the proof URL bound
// into each of those calls (so it matches what the Auth Service reconstructs).
type Client struct {
	publicURL   string // browser-facing authorization redirect
	internalURL string // server-side calls + proof URL
	clientID    string
	redirectURI string
	httpc       *http.Client
}

// Option adjusts a Client at construction.
type Option func(*Client)

// WithHTTPClient replaces the default HTTP client — for a caller that needs its
// own timeout or transport. Supplying one replaces the tracing wrapper too, so
// instrument it if these hops should stay in the traces.
func WithHTTPClient(httpc *http.Client) Option {
	return func(c *Client) {
		if httpc != nil {
			c.httpc = httpc
		}
	}
}

// New returns a client. publicURL is where the browser is sent to authorize;
// internalURL is where this service reaches the Auth Service and the address bound
// into each proof. They may be equal when no reverse proxy sits between them.
func New(publicURL, internalURL, clientID, redirectURI string, opts ...Option) *Client {
	c := &Client{
		publicURL:   strings.TrimSuffix(publicURL, "/"),
		internalURL: strings.TrimSuffix(internalURL, "/"),
		clientID:    clientID,
		redirectURI: redirectURI,
		// Traced by default: each hop opens a client span and carries the trace
		// context on, so a login is one trace across the caller and the authority.
		// The wrapper is inert when no exporter is configured.
		httpc: &http.Client{
			Timeout:   DefaultTimeout,
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		},
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Tokens is the Auth Service token response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// Identity is the logged-in user's identity, including which flows the login
// method permits (a deployment that binds flows to login strength reads it; one
// that does not may ignore the field).
type Identity struct {
	Subject        string   `json:"sub"`
	Name           string   `json:"name"`
	GivenName      string   `json:"given_name"`
	FamilyName     string   `json:"family_name"`
	SerialNumber   string   `json:"serial_number"`
	LoA            string   `json:"loa"`
	LoginMethod    string   `json:"login_method"`
	Scopes         []string `json:"scopes"`
	PermittedFlows []string `json:"permitted_flows"`
}

// StepUpRequest asks the Auth Service to elevate an existing session to a
// stronger login method.
type StepUpRequest struct {
	SessionID     string `json:"session_id"`
	ClientID      string `json:"client_id"`
	Method        string `json:"method"`
	CodeChallenge string `json:"code_challenge"`
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
}

// AuthorizeURL builds the browser-facing authorization redirect for the
// authorization-code flow. acrValues, when set, asks the Auth Service to force a
// specific login method.
//
// prompt=login forces a fresh authentication: without it the identity provider can
// answer the request from a still-live single-sign-on session and silently return
// that session's login method, ignoring the requested acr_values — so asking for a
// card login while a mobile session lingers would log the user in as mobile.
// Because the login method carries authorization weight, the requested method must
// always win, so every login re-authenticates rather than riding an existing
// upstream session.
func (c *Client) AuthorizeURL(challenge, state, acrValues string) string {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("response_type", "code")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("redirect_uri", c.redirectURI)
	q.Set("state", state)
	q.Set("prompt", "login")
	if acrValues != "" {
		q.Set("acr_values", acrValues)
	}

	return c.publicURL + "/authorize?" + q.Encode()
}

// LogoutURL builds the browser-facing front-channel logout redirect on the Auth
// Service. The browser must navigate here (a top-level redirect) so the Auth
// Service can, for a federated login, bounce on through the upstream logout and
// clear its single-sign-on cookie before landing back on redirectURI; a
// server-side call could not clear a cookie that lives in the browser on the
// identity provider's domain. sid is the upstream session handle (the session's
// refresh token) so the Auth Service can resolve the login method and terminate
// its own session. redirectURI must be registered for this client.
func (c *Client) LogoutURL(redirectURI, sid string) string {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", redirectURI)
	if sid != "" {
		q.Set("sid", sid)
	}

	return c.publicURL + "/logout?" + q.Encode()
}

// ExchangeCode redeems an authorization code for a token bound to key.
func (c *Client) ExchangeCode(ctx context.Context, key *ecdsa.PrivateKey, code, verifier string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", c.clientID)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", c.redirectURI)

	return c.tokenRequest(ctx, key, form)
}

// Refresh re-issues a token within the session, proving possession of the same
// key the original token was bound to.
func (c *Client) Refresh(ctx context.Context, key *ecdsa.PrivateKey, refreshToken string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.clientID)

	return c.tokenRequest(ctx, key, form)
}

func (c *Client) tokenRequest(ctx context.Context, key *ecdsa.PrivateKey, form url.Values) (*Tokens, error) {
	body, status, err := c.dpopDo(ctx, key, http.MethodPost, "/token", "",
		"application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &Error{Status: status, Body: string(body)}
	}

	var t Tokens
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("asclient: decode token response: %w", err)
	}

	return &t, nil
}

// Identity reads the logged-in user's identity, proving possession of key.
func (c *Client) Identity(ctx context.Context, key *ecdsa.PrivateKey, accessToken string) (*Identity, error) {
	body, status, err := c.dpopDo(ctx, key, http.MethodGet, "/identity", accessToken, "", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &Error{Status: status, Body: string(body)}
	}

	var id Identity
	if err := json.Unmarshal(body, &id); err != nil {
		return nil, fmt.Errorf("asclient: decode identity response: %w", err)
	}

	return &id, nil
}

// WebEIDChallenge begins an ID-card login: it requests a card challenge and the
// flow handle to complete it with. No proof of possession is made yet — the
// per-session key is proven only at the final token exchange. Returns the card
// challenge nonce (the browser signs it with the card) and the flow handle.
func (c *Client) WebEIDChallenge(ctx context.Context, codeChallenge, state string) (nonce, flow string, err error) {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("redirect_uri", c.redirectURI)
	q.Set("state", state)

	body, status, err := c.plainDo(ctx, http.MethodGet, "/webeid/challenge?"+q.Encode(), "", nil)
	if err != nil {
		return "", "", err
	}
	if status != http.StatusOK {
		return "", "", &Error{Status: status, Body: string(body)}
	}

	var out struct {
		Nonce string `json:"nonce"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("asclient: decode challenge response: %w", err)
	}

	return out.Nonce, out.State, nil
}

// WebEIDLogin submits the card authentication token for a flow and returns the
// authorization code to redeem at the token endpoint. The token is opaque here
// and forwarded verbatim.
func (c *Client) WebEIDLogin(ctx context.Context, flow string, authToken json.RawMessage) (code string, err error) {
	reqBody, err := json.Marshal(struct {
		State     string          `json:"state"`
		AuthToken json.RawMessage `json:"authToken"`
	}{State: flow, AuthToken: authToken})
	if err != nil {
		return "", err
	}

	body, status, err := c.plainDo(ctx, http.MethodPost, "/webeid/login", "application/json", reqBody)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", &Error{Status: status, Body: string(body)}
	}

	var out struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("asclient: decode login response: %w", err)
	}

	return out.Code, nil
}

// StepUp asks the Auth Service to elevate the session. The response is relayed to
// the caller verbatim: either a redirect to a stronger login or a card-signing
// challenge.
func (c *Client) StepUp(ctx context.Context, key *ecdsa.PrivateKey, accessToken string, req StepUpRequest) (json.RawMessage, int, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, 0, err
	}
	body, status, err := c.dpopDo(ctx, key, http.MethodPost, "/step-up", accessToken, "application/json", reqBody)
	if err != nil {
		return nil, 0, err
	}

	return json.RawMessage(body), status, nil
}

// setCorrelation attaches the correlation id (when the context carries one) so the
// Auth Service logs this hop under the same id as the originating request. The
// instrumented transport injects the trace context automatically; the correlation
// id is the one header a client sets itself.
func setCorrelation(ctx context.Context, req *http.Request) {
	if cid := propagation.CorrelationID(ctx); cid != "" {
		req.Header.Set(propagation.HeaderCorrelationID, cid)
	}
}

// dpopDo performs a request to the Auth Service carrying a fresh proof of
// possession of key, retrying once when the Auth Service asks for a server nonce.
func (c *Client) dpopDo(ctx context.Context, key *ecdsa.PrivateKey, method, path, accessToken, contentType string, body []byte) ([]byte, int, error) {
	fullURL := c.internalURL + path
	var nonce string

	for attempt := 0; attempt < 2; attempt++ {
		proof, err := dpop.GenerateProof(key, method, fullURL, accessToken, nonce)
		if err != nil {
			return nil, 0, fmt.Errorf("asclient: generate proof: %w", err)
		}

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("DPoP", proof)
		if accessToken != "" {
			req.Header.Set("Authorization", "DPoP "+accessToken)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		setCorrelation(ctx, req)

		resp, err := c.httpc.Do(req)
		if err != nil {
			return nil, 0, err
		}
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, 0, readErr
		}

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			if n := resp.Header.Get("DPoP-Nonce"); n != "" {
				nonce = n

				continue
			}
		}

		return respBody, resp.StatusCode, nil
	}

	return nil, 0, errors.New("asclient: proof request failed after nonce retry")
}

// plainDo performs a request to the Auth Service with no proof of possession (the
// card-login challenge + login hops, which are proven later at the token
// exchange). path may carry a query string.
func (c *Client) plainDo(ctx context.Context, method, path, contentType string, body []byte) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.internalURL+path, reader)
	if err != nil {
		return nil, 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	setCorrelation(ctx, req)

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	respBody, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, 0, readErr
	}

	return respBody, resp.StatusCode, nil
}

// Error is a non-2xx response from the Auth Service.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("auth service responded %d", e.Status)
}
