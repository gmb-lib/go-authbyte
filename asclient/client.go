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
	"github.com/gmb-lib/go-authbyte/jwks"
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
	publicURL    string // browser-facing authorization redirect
	internalURL  string // server-side calls + proof URL
	clientID     string
	clientSecret string // empty for a public client
	redirectURI  string
	httpc        *http.Client
	issuer       string       // the issuer a sign-in's answers must name; empty until WithIssuer
	keys         *jwks.Client // the Auth Service's published signing keys, for ID tokens
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

// WithClientSecret makes the client confidential: it proves itself with secret
// at every call it makes as itself (the code exchange, a refresh, a revocation
// and a step-up). Without it the client is public and sends no secret.
func WithClientSecret(secret string) Option {
	return func(c *Client) {
		c.clientSecret = secret
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
	// Built after the options, so the keys are fetched through the caller's own
	// HTTP client when it supplied one. Nothing is fetched until an ID token
	// names a key.
	c.keys = jwks.New(c.internalURL+"/.well-known/jwks.json", jwksCacheTTL, jwks.WithHTTPClient(c.httpc))

	return c
}

// Tokens is the Auth Service token response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	// IDToken is the sign-in's ID token, answered only to a sign-in that asked
	// for one (AuthorizationURL). Check it with ExchangeSignIn, never read it
	// unchecked.
	IDToken string `json:"id_token,omitempty"`
	// Capabilities is the signing-capability set the Auth Service captured at
	// login. It comes only with a code exchange, never with a refresh, and only
	// when the login captured one: nil means "unknown", never "none". The
	// certificates in it carry personal data — keep it with the session it
	// belongs to, and never log it.
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// Capabilities is the signing-capability set of a logged-in session: the signing
// identity the session's login method uses, its certificate, the paired
// authentication certificate, and the organisation seals the person may sign
// with. Every field is optional.
type Capabilities struct {
	SignIdentityID     string `json:"sign_identity_id,omitempty"`
	SigningCertificate string `json:"signing_certificate,omitempty"`
	AuthCertificate    string `json:"auth_certificate,omitempty"`
	Seals              []Seal `json:"seals,omitempty"`
	// SealsKnown says the seal list is authoritative: with it set, an empty list
	// means the person verifiably holds no seals rather than "unknown".
	SealsKnown bool `json:"seals_known,omitempty"`
}

// Seal is one organisation seal: the identity id a signing request selects it
// by, the display name a picker shows, and its certificate.
type Seal struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Certificate string `json:"certificate,omitempty"`
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
// stronger login method. The session is named by its refresh token, together with
// the client the token was issued to.
type StepUpRequest struct {
	RefreshToken  string `json:"refresh_token"`
	ClientID      string `json:"client_id"`
	Method        string `json:"method"`
	CodeChallenge string `json:"code_challenge"`
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
}

// AuthorizeURL builds the browser-facing authorization redirect for the
// authorization-code flow, asking for no ID token. acrValues, when set, names the
// sign-in methods the person may use, in the Auth Service's own method names.
//
// It asks for no fresh sign-in: the Auth Service refuses a sign-in completed with
// a method the request did not name, whatever an upstream session answered, so
// the requested method still wins. A caller that needs a fresh sign-in, or an ID
// token, uses AuthorizationURL.
func (c *Client) AuthorizeURL(challenge, state, acrValues string) string {
	return c.publicURL + "/authorize?" + c.authorizeQuery(challenge, state, acrValues).Encode()
}

// authorizeQuery is the part of an authorization request every sign-in sends.
func (c *Client) authorizeQuery(challenge, state, acrValues string) url.Values {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("response_type", "code")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("redirect_uri", c.redirectURI)
	q.Set("state", state)
	if acrValues != "" {
		q.Set("acr_values", acrValues)
	}

	return q
}

// BrowserLogoutURL builds the browser's leg of a sign-out: the front-channel
// logout redirect on the Auth Service. The browser must navigate here (a top-level
// redirect) so the Auth Service can, for a federated login, bounce on through the
// upstream logout and clear its single-sign-on cookie before landing back on
// redirectURI; a server-side call could not clear a cookie that lives in the
// browser on the identity provider's domain. loginMethod is the method the
// session was signed in with, which decides whether that bounce happens; it is
// left out when empty. The address carries no value that names the session,
// because a browser address is kept in history and logs: end the session with
// Revoke first. redirectURI must be registered for this client.
func (c *Client) BrowserLogoutURL(redirectURI, loginMethod string) string {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", redirectURI)
	if loginMethod != "" {
		q.Set("login_method", loginMethod)
	}

	return c.publicURL + "/logout?" + q.Encode()
}

// Revoke ends the session at the Auth Service, server to server [RFC 7009]: it
// presents the session's refresh token as this client, with a proof of
// possession of the session key. The Auth Service answers success also for a
// token it no longer holds; an *Error carries any refusal (another client's
// token, a proof of another key) or an outage.
func (c *Client) Revoke(ctx context.Context, key *ecdsa.PrivateKey, refreshToken string) error {
	form := url.Values{}
	form.Set("token", refreshToken)
	form.Set("token_type_hint", "refresh_token")
	form.Set("client_id", c.clientID)

	body, status, err := c.dpopDo(ctx, key, http.MethodPost, "/revoke", "",
		"application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &Error{Status: status, Body: string(body)}
	}

	return nil
}

// ExchangeCode redeems an authorization code for a token bound to key. A step-up's
// exchange answers no refresh token (RefreshToken is empty): keep the one the
// session holds.
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
	return c.webEIDChallenge(ctx, codeChallenge, state, "")
}

// WebEIDChallengeWithNonce begins an ID-card login that asks for an ID token, as
// AuthorizationURL does for a redirect: the token the code is exchanged for
// carries idTokenNonce back. Redeem the code with ExchangeSignIn.
func (c *Client) WebEIDChallengeWithNonce(ctx context.Context, codeChallenge, state, idTokenNonce string) (nonce, flow string, err error) {
	return c.webEIDChallenge(ctx, codeChallenge, state, idTokenNonce)
}

func (c *Client) webEIDChallenge(ctx context.Context, codeChallenge, state, idTokenNonce string) (nonce, flow string, err error) {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("redirect_uri", c.redirectURI)
	q.Set("state", state)
	if idTokenNonce != "" {
		q.Set("scope", scopeOpenID)
		q.Set("nonce", idTokenNonce)
	}

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
// challenge. A confidential client's secret travels in the body, since the
// Authorization header carries the person's access token.
func (c *Client) StepUp(ctx context.Context, key *ecdsa.PrivateKey, accessToken string, req StepUpRequest) (json.RawMessage, int, error) {
	reqBody, err := json.Marshal(struct {
		StepUpRequest
		ClientSecret string `json:"client_secret,omitempty"`
	}{req, c.clientSecret})
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
		} else if c.clientSecret != "" {
			// A call without the person's token is one the client makes as itself, so a
			// confidential client proves itself by HTTP Basic, each part form-encoded
			// first [RFC 6749 §2.3.1].
			req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret))
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
