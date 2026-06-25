# go-authbyte — auth client library

The in-process **`go-authbyte`** auth client library for eIDAS signing services. Compiled into
every backend service — and into the auth authority itself, to guard its own
endpoints.

Module: `github.com/gmb-lib/go-authbyte`. Companion to the
`authbyte-core` authority.

It does two jobs, both on the hot path with **no per-request call home** (JWKS
and service tokens are cached):

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

## Packages

```
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
| `AUTH_JWKS_CACHE_TTL` | `10m` | Public-key cache lifetime. |
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
