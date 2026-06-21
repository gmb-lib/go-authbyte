package authclient

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/gmb-lib/go-authbyte/dpop"
	"github.com/gmb-lib/go-authbyte/jwks"
	"github.com/gmb-lib/go-authbyte/nonce"
	"github.com/gmb-lib/go-authbyte/replay"

	"azugo.io/azugo"
	"azugo.io/azugo/user"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Client is the in-process auth-client. One instance per service holds the
// cached JWKS, the jti replay store, the server-nonce issuer, this service's
// own ephemeral DPoP key, and a per-audience cache of acquired service tokens.
type Client struct {
	cfg    *Configuration
	jwks   *jwks.Client
	replay replay.Store
	nonce  *nonce.Issuer

	// dpopKey is this service's own DPoP key, used to sign proofs on outbound
	// calls. Ephemeral and per-pod.
	dpopKey *ecdsa.PrivateKey

	tokenURL string
	httpc    *http.Client

	mu     sync.Mutex
	tokens map[string]*cachedToken
	// nonces caches the most recent server DPoP-Nonce per target audience for
	// outbound calls, so a steady stream of calls avoids the challenge round-trip.
	nonces map[string]string
}

type cachedToken struct {
	token string
	exp   time.Time
}

// Options configures construction of a Client.
type Options struct {
	// Redis is required when the replay backend is redis. If nil and the
	// backend is redis, the client builds one from Configuration.RedisURL.
	Redis redis.UniversalClient
}

// New constructs an auth-client from configuration.
func New(cfg *Configuration, opts ...Options) (*Client, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	jwksURL := cfg.JWKSURL
	if jwksURL == "" {
		jwksURL = strings.TrimSuffix(cfg.IssuerURL, "/") + "/.well-known/jwks.json"
	}

	store, err := newReplayStore(cfg, opt.Redis)
	if err != nil {
		return nil, err
	}

	var ni *nonce.Issuer
	if cfg.DPoPNonceEnabled {
		ni, err = nonce.New(cfg.DPoPNonceTTL)
		if err != nil {
			return nil, err
		}
	}

	dpopKey, err := dpop.GenerateKey()
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:      cfg,
		jwks:     jwks.New(jwksURL, cfg.JWKSCacheTTL),
		replay:   store,
		nonce:    ni,
		dpopKey:  dpopKey,
		tokenURL: strings.TrimSuffix(cfg.IssuerURL, "/") + "/token",
		// otel-instrumented transport so outbound S2S calls (service-token mint,
		// DoService background DPoP requests, PostJSON) appear as client spans and
		// propagate trace context to the callee. No-op when tracing is inert.
		httpc:  &http.Client{Timeout: 15 * time.Second, Transport: otelhttp.NewTransport(http.DefaultTransport)},
		tokens: make(map[string]*cachedToken),
		nonces: make(map[string]string),
	}, nil
}

func newReplayStore(cfg *Configuration, rc redis.UniversalClient) (replay.Store, error) {
	switch cfg.DPoPReplayBackend {
	case ReplayBackendRedis:
		if rc == nil {
			opts, err := redis.ParseURL(cfg.RedisURL)
			if err != nil {
				return nil, fmt.Errorf("auth-client: invalid redis url: %w", err)
			}

			rc = redis.NewClient(opts)
		}

		return replay.NewRedis(rc), nil
	case ReplayBackendMemory, "":
		return replay.NewMemory(), nil
	default:
		return nil, fmt.Errorf("auth-client: unknown replay backend %q", cfg.DPoPReplayBackend)
	}
}

// authResult is the outcome of validating one request.
type authResult struct {
	user        azugo.User
	needNonce   bool // issue a DPoP-Nonce challenge
	nonceToSend string
}

// validate runs the full inbound validation pipeline for the request, returning
// either an authenticated user, a nonce challenge, or an error.
func (c *Client) validate(ctx *azugo.Context, tokenStr string) (*authResult, error) {
	cl, err := c.parseToken(ctx, tokenStr)
	if err != nil {
		return nil, err
	}

	bound := cl.Thumbprint() != ""
	if !bound && c.cfg.RequireDPoP {
		return nil, errInvalidDPoP
	}

	if bound {
		res, derr := dpop.Verify(ctx.Header.Get("DPoP"), dpop.VerifyOptions{
			Method:       ctx.Method(),
			URL:          requestURL(ctx),
			AccessToken:  tokenStr,
			MaxAge:       c.cfg.DPoPProofMaxAge,
			Leeway:       c.cfg.TokenClockSkewLeeway,
			RequireNonce: c.cfg.DPoPNonceEnabled,
		})
		if derr != nil {
			// A missing nonce is recoverable: challenge the caller.
			if c.cfg.DPoPNonceEnabled && errors.Is(derr, dpop.ErrMissingNonce) {
				return c.challenge(), nil
			}

			return nil, errInvalidDPoP
		}

		// Confirm the proof key is the one the token is bound to.
		if res.Thumbprint != cl.Thumbprint() {
			return nil, errInvalidDPoP
		}

		// Validate the server nonce; a bad/stale nonce earns a fresh challenge.
		if c.cfg.DPoPNonceEnabled {
			if err := c.nonce.Verify(res.Nonce, c.cfg.TokenClockSkewLeeway); err != nil {
				return c.challenge(), nil
			}
		}

		// Reject replays.
		first, rerr := c.replay.CheckAndSet(ctx, res.JTI, c.cfg.DPoPProofMaxAge+c.cfg.TokenClockSkewLeeway)
		if rerr != nil {
			return nil, fmt.Errorf("auth-client: replay store: %w", rerr)
		}
		if !first {
			return nil, errInvalidDPoP
		}
	}

	return &authResult{user: user.New(cl.ToUserClaims())}, nil
}

func (c *Client) challenge() *authResult {
	return &authResult{needNonce: true, nonceToSend: c.nonce.Issue()}
}

// parseToken verifies the access/service token's signature against the cached
// JWKS and checks iss, aud and temporal claims.
func (c *Client) parseToken(ctx context.Context, tokenStr string) (*claims.Claims, error) {
	if tokenStr == "" {
		return nil, errUnauthorized
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(c.cfg.IssuerURL),
		jwt.WithAudience(c.cfg.ServiceAudience),
		jwt.WithLeeway(c.cfg.TokenClockSkewLeeway),
		jwt.WithExpirationRequired(),
	)

	var cl claims.Claims

	_, err := parser.ParseWithClaims(tokenStr, &cl, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)

		return c.jwks.Key(ctx, kid)
	})
	if err != nil {
		return nil, errUnauthorized
	}

	return &cl, nil
}

// requestURL reconstructs the absolute request URL for DPoP htu matching,
// honouring gateway-set X-Forwarded-Proto / X-Forwarded-Host so the htu matches
// the public URL the caller signed its proof for when TLS terminates at the
// edge rather than the pod. The gateway must strip these from client traffic.
func requestURL(ctx *azugo.Context) string {
	scheme := "http"
	if ctx.IsTLS() {
		scheme = "https"
	}
	if p := firstForwardedValue(ctx.Header.Get("X-Forwarded-Proto")); p != "" {
		scheme = p
	}

	host := ctx.Host()
	if h := firstForwardedValue(ctx.Header.Get("X-Forwarded-Host")); h != "" {
		host = h
	}

	return scheme + "://" + host + ctx.Path()
}

// firstForwardedValue returns the first, trimmed value of a possibly
// comma-separated forwarded header.
func firstForwardedValue(v string) string {
	if v == "" {
		return ""
	}

	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}

	return strings.TrimSpace(v)
}
