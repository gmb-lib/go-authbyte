package asclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	scopeOpenID = "openid"
	// jwksCacheTTL is how long the Auth Service's published keys are kept before
	// they are fetched again; a key it rotates in is fetched at once on first
	// sight of its kid, whatever this says.
	jwksCacheTTL = 15 * time.Minute
	// clockSkew is the leeway allowed between this service's clock and the Auth
	// Service's when reading the times an ID token names.
	clockSkew = 30 * time.Second
	// idTokenAlg is the one algorithm the Auth Service signs ID tokens with. Any
	// other, "none" and the MAC algorithms included, is refused.
	idTokenAlg = "ES256"
)

var (
	// ErrIssuer is a browser's return that does not name the issuer this client
	// expects: its code must not be redeemed [RFC 9207 §2.4].
	ErrIssuer = errors.New("asclient: the authorization response does not name the expected issuer")
	// ErrIDToken is a sign-in whose ID token is missing or does not prove it: no
	// tokens are returned, so no session may be established.
	ErrIDToken = errors.New("asclient: the ID token does not prove this sign-in")
)

// WithIssuer names the Auth Service's issuer identifier, exactly as its discovery
// document states it. A sign-in's checks compare against it: the browser's return
// (CheckIssuer) and the ID token (ExchangeSignIn). Without it both refuse.
func WithIssuer(issuer string) Option {
	return func(c *Client) {
		c.issuer = issuer
	}
}

// AuthorizationRequest is one sign-in to begin. Nonce is required: a value kept
// with this sign-in and nowhere else, which the ID token must carry back. The
// rest is optional.
type AuthorizationRequest struct {
	CodeChallenge string
	State         string
	Nonce         string
	// ACRValues names the sign-in methods the person may use, space-separated in
	// order of preference, in the Auth Service's own method names.
	ACRValues string
	// Prompt is "login" for a fresh sign-in, "none" for one that must not show
	// the person anything, or "select_account".
	Prompt string
	// MaxAge, when set, is the oldest sign-in the caller accepts; zero asks for a
	// fresh one. Pass the same value to ExchangeSignIn.
	MaxAge *time.Duration
}

// AuthorizationURL builds the browser-facing authorization redirect for a sign-in
// that asks for an ID token [OIDC Core §3.1.2.1]. Redeem the code it returns with
// ExchangeSignIn, after CheckIssuer.
func (c *Client) AuthorizationURL(req AuthorizationRequest) string {
	q := c.authorizeQuery(req.CodeChallenge, req.State, req.ACRValues)
	q.Set("scope", scopeOpenID)
	q.Set("nonce", req.Nonce)
	if req.Prompt != "" {
		q.Set("prompt", req.Prompt)
	}
	if req.MaxAge != nil {
		q.Set("max_age", strconv.FormatInt(int64(*req.MaxAge/time.Second), 10))
	}

	return c.publicURL + "/authorize?" + q.Encode()
}

// CheckIssuer checks the iss parameter of the browser's return from the Auth
// Service, its code or its error alike, before anything in it is used. It must be
// present and equal the issuer named with WithIssuer [RFC 9207 §2.4]; otherwise
// the return is refused with ErrIssuer, and an error in it must not be taken as
// the Auth Service's.
func (c *Client) CheckIssuer(iss string) error {
	if c.issuer == "" {
		return fmt.Errorf("%w: this client names no issuer (WithIssuer)", ErrIssuer)
	}
	if iss != c.issuer {
		return ErrIssuer
	}

	return nil
}

// IDTokenCheck is what a sign-in's ID token is checked against: the nonce sent
// with the request, and the MaxAge it asked, if any, with the moment the sign-in
// began (now, when zero).
type IDTokenCheck struct {
	Nonce   string
	MaxAge  *time.Duration
	Started time.Time
	// ACRValues are the methods the request named (AuthorizationRequest.ACRValues);
	// when set, the method met must be one of them.
	ACRValues string
}

// IDToken is what a checked ID token says about the sign-in.
type IDToken struct {
	// Subject is the person, the same subject the access token names.
	Subject string
	// AuthTime is when the person proved who they are; zero when the Auth
	// Service could not know it (it is always set when MaxAge was asked).
	AuthTime time.Time
	// ACR is the sign-in method met, in the Auth Service's own method names.
	ACR string
	// AMR lists the means of authentication used, as registered values [RFC 8176 §2].
	AMR []string
	// SessionID is the Auth Service's public name for the sign-in session.
	SessionID string
}

// idTokenClaims are the claims an ID token carries [OIDC Core §2].
type idTokenClaims struct {
	jwt.RegisteredClaims
	Nonce    string           `json:"nonce,omitempty"`
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	ACR      string           `json:"acr,omitempty"`
	AMR      []string         `json:"amr,omitempty"`
	SID      string           `json:"sid,omitempty"`
}

// ExchangeSignIn redeems a sign-in's authorization code, as ExchangeCode does,
// and checks the ID token in the answer [OIDC Core §3.1.3.7]: issued by the
// issuer named with WithIssuer, for this client and no other audience, naming a
// subject and its issue time, unexpired, signed with ES256 by a key the Auth
// Service publishes, carrying check.Nonce, met by one of check.ACRValues when
// set, and, when check.MaxAge is set, naming an authentication no older than it.
// An answer without an ID token, or with one that fails any check, returns
// ErrIDToken and no tokens, and the session the exchange opened is revoked:
// establish no session from it. A failed exchange returns its own error, as
// ExchangeCode does.
func (c *Client) ExchangeSignIn(ctx context.Context, key *ecdsa.PrivateKey, code, verifier string, check IDTokenCheck) (*Tokens, *IDToken, error) {
	if c.issuer == "" {
		return nil, nil, fmt.Errorf("%w: this client names no issuer (WithIssuer)", ErrIDToken)
	}
	if check.Nonce == "" {
		return nil, nil, fmt.Errorf("%w: no nonce to check it against", ErrIDToken)
	}

	t, err := c.ExchangeCode(ctx, key, code, verifier)
	if err != nil {
		return nil, nil, err
	}

	id, err := c.checkIDToken(ctx, t.IDToken, check)
	if err != nil {
		// The exchange opened a session at the Auth Service that nothing will
		// use: end it now rather than leave it to expire. Best effort; the
		// refusal stands whatever the revocation answers.
		if t.RefreshToken != "" {
			_ = c.Revoke(ctx, key, t.RefreshToken)
		}

		return nil, nil, err
	}

	return t, id, nil
}

func (c *Client) checkIDToken(ctx context.Context, raw string, check IDTokenCheck) (*IDToken, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: the answer carries none", ErrIDToken)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{idTokenAlg}),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.clientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkew),
	)

	var cl idTokenClaims
	if _, err := parser.ParseWithClaims(raw, &cl, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)

		return c.keys.Key(ctx, kid)
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDToken, err)
	}

	// The client must be the token's only audience: one naming another as well
	// was minted for someone this client does not trust [OIDC Core §3.1.3.7].
	if len(cl.Audience) != 1 {
		return nil, fmt.Errorf("%w: it names audiences beside this client", ErrIDToken)
	}
	// Both are REQUIRED [OIDC Core §2]; a token without the person names nobody.
	if cl.Subject == "" || cl.IssuedAt == nil {
		return nil, fmt.Errorf("%w: it names no subject or no issue time", ErrIDToken)
	}
	// The method met must be one the request named [OIDC Core §3.1.3.7].
	if check.ACRValues != "" && !slices.Contains(strings.Fields(check.ACRValues), cl.ACR) {
		return nil, fmt.Errorf("%w: it was met by a method the request did not name", ErrIDToken)
	}
	if cl.Nonce == "" || subtle.ConstantTimeCompare([]byte(cl.Nonce), []byte(check.Nonce)) != 1 {
		return nil, fmt.Errorf("%w: it does not carry the nonce this sign-in sent", ErrIDToken)
	}

	id := &IDToken{Subject: cl.Subject, ACR: cl.ACR, AMR: cl.AMR, SessionID: cl.SID}
	if cl.AuthTime != nil {
		id.AuthTime = cl.AuthTime.Time
	}

	if check.MaxAge != nil {
		if id.AuthTime.IsZero() {
			return nil, fmt.Errorf("%w: an age was asked and it names no authentication time", ErrIDToken)
		}
		started := check.Started
		if started.IsZero() {
			started = time.Now()
		}
		if id.AuthTime.Before(started.Add(-*check.MaxAge - clockSkew)) {
			return nil, fmt.Errorf("%w: the authentication is older than the age asked", ErrIDToken)
		}
	}

	return id, nil
}
