# go-authbyte — auth client library

The in-process **`go-authbyte`** auth client library for eIDAS signing services. Compiled into
every backend service — and into the auth authority itself, to guard its own
endpoints.

Module: `github.com/gmb-lib/go-authbyte`. Companion to the
`authbyte-core` authority.

It does three jobs. The first two are on the hot path with **no per-request call
home** (JWKS and service tokens are cached); the third runs only at login:

1. **Inbound** — Azugo middleware that validates the access/service token
   (signature via cached JWKS, `iss`, `aud`, `exp`/`nbf`), verifies the
   **DPoP proof** (signature, `cnf.jkt` match, `htm`/`htu`, `ath`, jti replay,
   server nonce), and populates `ctx.User()`.
2. **Outbound** — acquires this service's own DPoP-bound **service token** via
   client-credentials (cached per audience, early-refreshed) and attaches it
   plus a fresh DPoP proof to service-to-service calls, handling the
   `DPoP-Nonce` challenge transparently. It can also act **on behalf of the
   logged-in user**: it exchanges that user's token for a delegated one
   (RFC 8693 token exchange) so the callee owner-filters on the user subject
   exactly as it would for a direct user call. Delegated tokens are cached per
   `(audience, scope, subject)` and bound to this service's own key.
3. **Confidential browser login** (`asclient`) — for a back-end that logs a user
   in and holds their tokens: the authorization-code flow with PKCE, over a key
   generated per user session, so the browser never holds a token or a secret.

## Usage

### Inbound (protect routes)

```go
ac, err := authclient.New(cfg) // cfg bound from the service's Azugo Configuration
// ...
g := app.Group("/documents")
g.Use(ac.Authenticate())       // requires a valid DPoP-bound token
// or ac.TryAuthenticate() to allow anonymous through

func (r *router) get(ctx *azugo.Context) {
    if !ctx.User().HasScopeLevel("documents", "read") {
        ctx.Error(corehttp.ForbiddenError{}); return
    }
    // ctx.User().ID(), .ClaimValue("login_method"), ...
}
```

### Outbound (service-to-service)

```go
// Acquire + attach automatically, with transparent nonce retry:
var doc DocumentDTO
err := ac.GetJSON(ctx, "svc:document", "documents:read",
    "http://document:8080/documents/"+id, &doc)
```

### Outbound on behalf of a user (RFC 8693)

When a service composes a downstream call *for the logged-in user* (e.g.
fetching that user's document), pass the user's subject and inbound token; the
client mints a delegated token via token exchange and the callee sees the user
as the subject:

```go
// inboundToken is the user's raw access token (the request's Authorization
// bearer); ctx.User().ID() is its subject.
var doc DocumentDTO
err := ac.GetJSONOnBehalf(ctx, "svc:document", "documents:read",
    ctx.User().ID(), inboundToken,
    "http://document:8080/documents/"+id, &doc)
```

`PostJSONOnBehalf` (request context) and `DoServiceOnBehalf` (background, no
request context) are the on-behalf-of counterparts of `PostJSON` and
`DoService`. The delegated token carries an `act` claim recording the
delegation chain; `claims.Claims.Delegated()` reports whether a received token
was minted on behalf of its subject.

Outbound calls run under a 15s overall timeout by default. For operations that
legitimately outlast it — e.g. a long-term-archival document validation, where
the upstream work alone can take tens of seconds — use the per-call variants
`DoServiceWithTimeout` / `DoServiceOnBehalfWithTimeout`: the token acquisition
still runs under the default (it must be fast), and only the resource call runs
under the caller's ceiling.

### Browser login from a confidential back-end (`asclient`)

The third job, for a back-end that logs a *browser user* in and holds the tokens
on their behalf (a BFF): it drives the authorization-code flow with PKCE, and every
server-side hop proves possession of a key that belongs to that one session, with
the `DPoP-Nonce` challenge retried transparently. The browser never receives a
token, a key or a secret — it holds only the calling service's own session cookie.

Its calls are traced out of the box (client spans + trace context propagation), so
a login reads as one trace across the caller and the authority. `WithHTTPClient`
overrides the client when a caller needs its own timeout or transport — and then
owns instrumenting it.

```go
as := asclient.New(publicURL, internalURL, clientID, redirectURI)

// 1. Start: one key + one PKCE pair per session, then send the browser off.
key, _ := asclient.GenerateKey()
verifier, challenge, _ := asclient.PKCE()
state, _ := asclient.RandomToken(32)
redirect := as.AuthorizeURL(challenge, state, "") // acr_values forces a method

// 2. Callback: redeem the code, proving possession of that session's key.
tokens, err := as.ExchangeCode(ctx, key, code, verifier)

// 3. Later: refresh, read the identity, or elevate the session.
tokens, err = as.Refresh(ctx, key, tokens.RefreshToken)
id, err := as.Identity(ctx, key, tokens.AccessToken)
```

`WebEIDChallenge` / `WebEIDLogin` drive an ID-card login (the card challenge is
answered in the browser; the session key is proven at the token exchange), and
`StepUp` asks the authority to elevate an existing session to a stronger method.
`ParseUnverified` reads a token this service was just issued into the shared claim
model — for labelling the session it already holds, never for authorizing anything.

## Packages

```
asclient/     Confidential authorization-code browser login (PKCE + per-session proof)
authclient/   Configuration, Client, Azugo middleware, outbound calls
claims/       Shared JWT claim model (user + service + delegated tokens; `act`)
dpop/         RFC 9449 proof generation & verification, JWK thumbprint
jwks/         Caching JWKS client (TTL + unknown-kid refresh)
nonce/        Stateless HMAC server nonce (DPoP-Nonce)
replay/       jti replay cache — memory (default) or redis
```

## Configuration

Bound as a sub-configuration of each consuming service. Typically only the
issuer URL, this service's audience, and its client id/secret are set per
service; everything else defaults safely.

| Env | Default | Purpose |
|---|---|---|
| `AUTH_ISSUER_URL` | — | Trust anchor; JWKS/discovery source; expected `iss`. |
| `AUTH_JWKS_URL` | derived | Override JWKS location. |
| `AUTH_JWKS_CACHE_TTL` | `10m` | Public-key cache lifetime. A token whose `kid` is not cached triggers one out-of-band fetch regardless of this TTL, so a rotated signing key is picked up without restarting the service; repeat unknown kids are rate-limited (30s) so they cannot be used to generate traffic at the issuer. |
| `SERVICE_AUDIENCE` | — | This service's own `aud`. |
| `SERVICE_CLIENT_ID` / `SERVICE_CLIENT_SECRET` (`_FILE`) | — | Outbound client-credentials. |
| `SERVICE_TOKEN_EARLY_REFRESH` | `30s` | Refresh own token before exp. |
| `DPOP_PROOF_MAX_AGE` | `60s` | Inbound proof age window. |
| `TOKEN_CLOCK_SKEW_LEEWAY` | `30s` | Leeway on exp/iat/proof age. |
| `DPOP_REPLAY_BACKEND` | `memory` | `memory` (per-pod) or `redis`. |
| `REDIS_URL` | — | Required when backend is redis. |
| `DPOP_NONCE_ENABLED` | `true` | Require + issue `DPoP-Nonce`. |
| `DPOP_NONCE_TTL` | `5m` | Issued nonce lifetime. |
| `REQUIRE_DPOP` | `true` | Enforce DPoP on inbound. |

## Tests

```bash
go test ./...
```

DPoP proof round-trip and tamper/expiry/ath/nonce rejection
([`dpop`](dpop/dpop_test.go)) and the stateless nonce
([`nonce`](nonce/nonce_test.go)) are covered. The end-to-end token+JWKS path is
exercised from the `authbyte-core` issuer tests.
