// Package dpop implements RFC 9449 DPoP proof generation and verification.
//
// A DPoP proof is a short-lived JWT, signed by the holder's private key, that
// proves possession of the key an access/service token is bound to. The proof
// carries the HTTP method+URI it is valid for, a unique jti, an iat, the
// access-token hash (ath), and the holder's public JWK in its header. This
// package performs the cryptographic and structural checks; policy checks
// (cnf.jkt match, jti replay, nonce validity) are the caller's responsibility.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// HeaderType is the required `typ` header value for DPoP proofs.
const HeaderType = "dpop+jwt"

// Errors returned by Verify.
var (
	ErrMalformed    = errors.New("malformed dpop proof")
	ErrType         = errors.New("dpop proof has wrong typ header")
	ErrKey          = errors.New("dpop proof has missing or invalid jwk header")
	ErrSignature    = errors.New("dpop proof signature verification failed")
	ErrMethod       = errors.New("dpop proof htm does not match request method")
	ErrURL          = errors.New("dpop proof htu does not match request uri")
	ErrATH          = errors.New("dpop proof ath does not match access token")
	ErrExpired      = errors.New("dpop proof is expired or issued in the future")
	ErrMissingNonce = errors.New("dpop proof is missing a nonce")
)

// proofClaims is the DPoP proof JWT body. RegisteredClaims supplies jti (ID)
// and iat (IssuedAt).
type proofClaims struct {
	jwt.RegisteredClaims

	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// GenerateKey creates a fresh P-256 DPoP keypair. DPoP keys are per-holder and
// ephemeral; the private key never leaves the process.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Thumbprint returns the RFC 7638 JWK SHA-256 thumbprint (base64url, no
// padding) of a public key — the value carried in a token's cnf.jkt.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// AccessTokenHash returns the base64url(SHA-256(token)) used as the `ath`
// claim.
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateProof builds and signs a DPoP proof for a single outbound request.
// accessToken may be empty (e.g. the initial token-endpoint hop has no access
// token yet); nonce may be empty when the server has not yet issued a
// challenge.
func GenerateProof(key *ecdsa.PrivateKey, method, requestURL, accessToken, nonce string) (string, error) {
	htu, err := normalizeHTU(requestURL)
	if err != nil {
		return "", err
	}

	jti, err := randomID()
	if err != nil {
		return "", err
	}

	c := proofClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		HTM:   strings.ToUpper(method),
		HTU:   htu,
		Nonce: nonce,
	}
	if accessToken != "" {
		c.ATH = AccessTokenHash(accessToken)
	}

	jwkHeader, err := publicJWKHeader(&key.PublicKey)
	if err != nil {
		return "", err
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	tok.Header["typ"] = HeaderType
	tok.Header["jwk"] = jwkHeader

	return tok.SignedString(key)
}

// Result is the validated content of a DPoP proof.
type Result struct {
	// Thumbprint is the JWK thumbprint of the proof's signing key — compare it
	// to the token's cnf.jkt.
	Thumbprint string
	// JTI is the proof's unique id — feed it to a replay cache.
	JTI string
	// Nonce is the server nonce echoed by the proof, if any.
	Nonce string
}

// VerifyOptions configures proof verification.
type VerifyOptions struct {
	// Method and URL of the actual request the proof accompanies.
	Method string
	URL    string
	// AccessToken, when non-empty, requires the proof's `ath` to match it.
	AccessToken string
	// MaxAge is the maximum accepted proof age (iat.. now).
	MaxAge time.Duration
	// Leeway tolerated on the age window for clock skew.
	Leeway time.Duration
	// RequireNonce, when true, fails proofs that carry no nonce. The caller
	// still validates the nonce value itself.
	RequireNonce bool

	now func() time.Time
}

// Verify checks the proof's signature against its embedded public JWK and
// validates typ, htm, htu, ath and freshness. On success it returns the key
// thumbprint, jti and nonce for the caller's policy checks.
func Verify(proof string, opt VerifyOptions) (*Result, error) {
	if opt.now == nil {
		opt.now = time.Now
	}

	var (
		claims     proofClaims
		thumbprint string
	)

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
	)

	_, err := parser.ParseWithClaims(proof, &claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != HeaderType {
			return nil, ErrType
		}

		pub, tp, err := keyFromHeader(t.Header)
		if err != nil {
			return nil, err
		}

		thumbprint = tp

		return pub, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrType), errors.Is(err, ErrKey):
			return nil, err
		default:
			return nil, fmt.Errorf("%w: %w", ErrSignature, err)
		}
	}

	if !strings.EqualFold(claims.HTM, opt.Method) {
		return nil, ErrMethod
	}

	wantHTU, err := normalizeHTU(opt.URL)
	if err != nil {
		return nil, err
	}
	if claims.HTU != wantHTU {
		return nil, ErrURL
	}

	if opt.AccessToken != "" && claims.ATH != AccessTokenHash(opt.AccessToken) {
		return nil, ErrATH
	}

	if claims.IssuedAt == nil {
		return nil, ErrExpired
	}

	iat := claims.IssuedAt.Time
	now := opt.now()
	if now.Sub(iat) > opt.MaxAge+opt.Leeway || iat.Sub(now) > opt.Leeway {
		return nil, ErrExpired
	}

	if opt.RequireNonce && claims.Nonce == "" {
		return nil, ErrMissingNonce
	}

	return &Result{Thumbprint: thumbprint, JTI: claims.ID, Nonce: claims.Nonce}, nil
}

// keyFromHeader extracts the public key and its thumbprint from a proof's `jwk`
// header.
func keyFromHeader(header map[string]any) (crypto.PublicKey, string, error) {
	raw, ok := header["jwk"]
	if !ok {
		return nil, "", ErrKey
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return nil, "", ErrKey
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, "", ErrKey
	}

	// The header MUST carry a public key only.
	if !jwk.IsPublic() {
		return nil, "", ErrKey
	}

	if _, ok := jwk.Key.(*ecdsa.PublicKey); !ok {
		return nil, "", ErrKey
	}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, "", ErrKey
	}

	return jwk.Key, base64.RawURLEncoding.EncodeToString(tp), nil
}

// publicJWKHeader renders a public key as the map form embedded in a proof
// header.
func publicJWKHeader(pub *ecdsa.PublicKey) (map[string]any, error) {
	data, err := (&jose.JSONWebKey{Key: pub}).MarshalJSON()
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	return m, nil
}

// normalizeHTU strips query and fragment, per RFC 9449 §4.3.
func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	u.RawQuery = ""
	u.Fragment = ""

	return u.String(), nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
