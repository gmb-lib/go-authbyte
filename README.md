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

It also carries one piece of shared vocabulary: **`identitycode`**, the single
place a signatory's identity code is turned into the form it is stored, compared
and shown in. Every service that holds such a code has to agree on that form
exactly, or the same person arriving two ways becomes two people. It calls
nothing and needs no configuration.

## Install

```sh
go get github.com/gmb-lib/go-authbyte
```

See [`CHANGELOG.md`](./CHANGELOG.md) for what each release changed, and what it means for code that
already uses this library, before you bump.

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

**When the gate refuses**, the caller gets an undifferentiated `401` — it is never told which check
failed, because that would let it walk a bad token toward acceptance one guess at a time. The service
itself is told: each refusal logs `refused a request at the auth gate` at `warn` with a `reason` and
the underlying error, so an expired service token, a wrong audience and a replayed proof are
distinguishable in your own logs. A missing or stale DPoP nonce is not a refusal — it is answered
`401` with a fresh `DPoP-Nonce`, which the outbound client below retries transparently.

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

**When the auth service refuses**, the answer is readable rather than only
loggable. A refusal and an unreachable service are different events — one is a
decision about your request, the other a failure to make it — and a caller that
cannot tell them apart has to report the worse of the two:

```go
_, err := ac.AcquireDelegatedToken(ctx, audience, scope, subject, subjectToken)

var refused *authclient.Error
if errors.As(err, &refused) && refused.Status < 500 {
    // Answered and declined: refused.Body carries the sender's own words.
    return relay(refused.Status, refused.Body)
}
// Anything else is a failure to reach the service at all.
```

`Error.Hop` says which call answered: `HopToken` the ask to the token endpoint,
`HopResource` the call that carries the token on to the target service. One
helper call makes both, so the call site alone cannot tell them apart. The error
satisfies `error`, so existing handling is unaffected and reading the answer is
opt-in; its message states the status only, and the body stays in its field
because it is another service's wording and may describe the person the call was
made for.

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

### One spelling of an identity code (`identitycode`)

A signatory's identity code arrives written several ways — with the identity type
and country a certificate or an identity provider puts on it, with the separator
dropped, as a person writes their national code, or in the `LV/LV/…` shape a
cross-border login carries. Canonicalise before storing and before comparing, and
all of them are one person:

```go
stored, err := identitycode.Canonical(rawFromCertificate, "")     // "PNOLV-XXXXXXXXXXX"
stored, err = identitycode.Canonical(typedCode, chosenCountry)    // the same value
shown := identitycode.Display(stored)                             // "XXXXXX-XXXXX"
```

`Display` is the spelling to put in front of a person: their own national code,
written the way their country writes it where that spelling is known, and
otherwise the **whole stored code**, prefix and all. It never drops the country or
the identity type — the same digits in two countries belong to two people, and an
organisation's register number is not a person's — so nothing it returns can
stand for more than one principal. What it returns can also be typed back in and
resolves to the same person.

The country argument is a **hint**, consulted only when the code names no country
of its own: the country chosen on the screen the code was typed into, the country
in the signing certificate, the country recorded for the system that sent it. A
country in the value always wins, and one that contradicts the hint is ignored
rather than being an error — a caller's software may or may not put the country on
the wire, and both have to work.

**The country is never guessed.** A bare code with no country available is refused
(`ErrCountryRequired`), because the same digits belong to different people in
different countries. The refusals are sentinel errors, comparable with
`errors.Is`, and none of them carries the offending code — an identity code is
personal data, and these errors reach service logs. Validation is shape only: a
typed code is a *reference* to a person, and what settles who signed is the
certificate they sign with, so a checksum rule written for one country's format
could only add ways to refuse a real foreign signatory.

`Key` is for comparing a value of unknown provenance without storing it; storing
always goes through `Canonical`.

**A code also says whether it belongs to a person or to an organisation.** The
identity types come in two lists, and a certificate carries them in two different
places — a natural person's code in the subject's `serialNumber`, a legal person's
in its `organizationIdentifier`:

```go
c, err := identitycode.Parse(stored)
if err == nil && !c.IsNaturalPerson() {
    // a trade-register number: a valid identity, and one no login answers to
}
```

Ask it wherever a code has to name somebody who will later authenticate — a party
expected to act, a slot waiting to be claimed. Nobody authenticates as an
organisation: its electronic seal is a signing method its people reach for after
identifying themselves, so a code naming an organisation is an identity no login
will ever answer to. `IsNaturalPerson` is false for anything the standard does not
place with a natural person, an unrecognised type included, because the question is
asked in order to refuse. The list is the standard's, not this package's, so it
already covers identity types this package does not yet recognise.

### One list of what a service checks (`permissions`)

A permission is one act on one feature of a service, such as removing a file
somebody else attached to a task. It travels on a token as a scope,
`<service>/<feature path>:<act>`, and a route checks it as an exact match, so
holding one act implies no other and nesting a feature under another grants
nothing. The service writes its permissions once; the same list is what the
membership register learns and what every route checks:

```go
var Permissions = permissions.MustNew("projects", "Project and workflow engine", []permissions.Permission{
    {Feature: "project", Act: "create", Description: "Register a project",
        Class: permissions.Ordinary, Plane: permissions.Tenant,
        Labels: map[string]string{"lv": "Reģistrēt projektu"}},
    {Feature: "task/comment", Act: "add", Description: "Comment on a task",
        Class: permissions.Ordinary, Plane: permissions.Object},
    {Feature: "setup", Act: "import", Description: "Apply a configuration file",
        Class: permissions.TenantConfiguration, Plane: permissions.Tenant},
})

var permCommentAdd = Permissions.Declared("task/comment", "add") // stops the service if undeclared

gate := Permissions.Gate(func(ctx *azugo.Context, required string) { /* record the refusal */ })
v1.Post("/tasks/{id}/comments", gate.OneOf(permissions.Levels("projects", "log", "write"), r.commentAdd, permCommentAdd))
v1.Get("/config", gate.Member(permissions.Levels("projects", "read"), r.configGet))
```

- **`Declared`** answers the permission a route checks and panics when the list
  does not declare it, so a check nobody can be given stops the service at load.
- **The route gate** passes a caller holding one of the permissions (`OneOf`) or
  all of them (`AllOf`), beside an optional coarser level — a rung of the
  service's own role ladder, or any check the service writes as a `Level`; pass
  `permissions.Level{}` for none. `Member` passes the level or any permission the
  service declares. A refusal is `403`, after the callback has been told what would
  have been enough. A handler that tells an act on the caller's own work from an
  act on anybody's reads `perm.HeldBy(ctx.User())`.
- **The register document**: `Section()` renders the list as the membership
  register's configuration section, and `Command()` is a `permissions` command
  that prints it, for a deployment to apply. The service makes no call to register
  itself.
- **Each permission says** its `Class` (whether it changes what others may do, or
  is a family of rights, one per field),
  its `Plane` (granted to the whole `Tenant`, on one `Object` the service
  owns, or to a position in the tenant's `Chart` of authority), its label per language (`Label(lang)` falls back to the description) and
  whether it is `Retired` — kept for the roles that already hold it, never handed
  out again. A permission is never removed from a list.
- **Seeds**: an ordinary permission on the object plane may name the roles the
  register creates with every new tenant that hold it (`Seeds: []string{"worker",
  "manager"}`), so a tenant starts with working roles; the tenant changes or
  deletes them like any other.
- **A family of rights, one per field** (`Class: permissions.PerField`): a
  service whose tenants add their own fields, and restrict who sees a field's
  values, declares one family per kind of field (`task:viewField`) on the object
  plane. A field's right is the family, `@`, the field's key and a generation the
  field counts up each time it is restricted — `projects/task:viewField@rate.2` —
  held only as a tick on a role placed on the service's objects, so it arrives in
  a placement's keys and never on a token. The bare family is the
  administrators', on their token, and means every field of the kind. The service
  checks it on each value it answers, so the test kit asks no route to accept it.
- **A library contributes its own** permissions: `MustNew(key, name, own,
  library.Permissions)` puts them under the service's key, and the library's
  routes check them through the same Set, so the same start check covers them.

The test kit holds the routes against the list, both ways:

```go
func TestPermissions(t *testing.T) {
    r := register(testApp(t)) // the service's routes, through its Gate
    permissionstest.Check(t, Permissions, r.gate)
}
```

It fails when a declared permission is checked by no route (a retired one or a
per-field family aside),
when a route checks one the list lacks, when a check naming an undeclared act does
not stop the service, when an act on your own work (`editOwn`) has no act on
anybody's (`edit`) beside it, and when the register document carries a property the
register would refuse.

### A copy of a tenant's roles, for roles placed on your own objects (`placement`)

A service that owns objects — a project, a register — can let a tenant put a
person on one of them with one of the tenant's roles. What the person may do there
is what the role carries in that service, and a check on every request should not
ask the membership register every time. So the service keeps a copy of the roles
beside its placements, and this package keeps the copy current and honest:

```go
reg, _ := placement.NewRegister(authClient, "http://membership:8080", "membership", "projects")
keeper, _ := placement.New(reg, myStore, placement.Config{}) // 10 s poll, 15 min trust window
go keeper.Run(ctx)

// On a request from a tenant this service has never read the roles of:
keeper.Wake(tenant)

// Wherever a placement is checked, a copy confirmed before this grants nothing:
since := keeper.TrustedSince()

// On the readiness check:
if err := keeper.Ready(); err != nil { /* degraded: placed keys grant nothing */ }
```

- **The poll** sends the version the service holds; while nothing changed the
  register answers `304` with no body, so asking every few seconds costs almost
  nothing. A changed answer goes to the service's `Store.Replace`, which replaces
  the copy **and the keys beside every placement of a changed role in one
  transaction**.
- **The trust window** is how long a confirmed copy counts. A role taken back in
  the register stops working here within the window even when the register cannot
  be reached; `Ready` names the tenants whose copy is past it.
- **The count**: after a cycle in which they changed, the service's placements per
  role go to the register, which then refuses to delete a role somebody is still
  placed in. An id it no longer knows comes back as an error for that tenant.
- **Only the service's own groups are copied**: `NewRegister(…, "projects")` keeps
  `projects/…` permissions and drops the rest. `Keys.Holds(perm)` checks a
  placement's keys with the same exact match the route gate uses.
- **The copy lives with the service's data**, behind the `Store` interface — five
  methods: the tenants it holds, a copy's version, replace, confirm, and counts.
  The register is reached as the service itself, a member of each tenant, holding
  `membership:definitions` and `membership:placements`.

### A copy of a tenant's chart of authority (`chart`)

A tenant may draw its own tree of positions and put its people in them, and a
service may let a person see what the people below them see — the projects of
everyone who reports to them — without joining any of them. The service reads that
from a copy of the tree, kept the way the roles' copy is kept:

```go
reg, _ := chart.NewRegister(authClient, "http://membership:8080", "membership")
keeper, _ := chart.New(reg, myStore, chart.Config{}) // 10 s poll, 15 min trust window
go keeper.Run(ctx)

keeper.Wake(tenant)          // a tenant this service has never read the chart of
since := keeper.TrustedSince() // a copy confirmed before this lifts nothing
if err := keeper.Ready(); err != nil { /* degraded: the chart lifts nothing */ }
```

- **The copy is a list**: for each person, everyone below them, all the way down,
  as subject keys (`Chart.Below`). Nobody is below themselves, and a person with
  nobody below has no entry.
- **Same discipline as the roles' copy**: the poll sends the version held and a
  `304` costs nothing, a changed answer replaces the copy in one `Store.Replace`,
  and a copy is trusted for one window after it was last confirmed. A person moved
  out of a position stops seeing through it within one interval, and when the
  register cannot be reached, within the window.
- **The store** has four methods: the tenants it holds, a copy's version, replace,
  confirm. The register is reached as the service itself, holding
  `membership:chart`; a tenant without a chart is answered as an empty one.
- **The permissions that read the copy** are declared on the third plane,
  `permissions.Chart`: held by a position, relative to the tree, ordinary in
  class, never ticked on a role or a user type and never seeded. The test kit's
  *declared is checked* rule skips them, since they are read from the viewer's
  reach rather than checked on a route.

## Packages

```
asclient/     Confidential authorization-code browser login (PKCE + per-session proof)
authclient/   Configuration, Client, Azugo middleware, outbound calls
chart/        A service's copy of who is below whom in a tenant's chart of authority
claims/       Shared JWT claim model (user + service + delegated tokens; `act`)
dpop/         RFC 9449 proof generation & verification, JWK thumbprint
identitycode/ One spelling of an identity code — store, compare, show
jwks/         Caching JWKS client (TTL + unknown-kid refresh)
nonce/        Stateless HMAC server nonce (DPoP-Nonce)
permissions/  One list of the acts a service enforces: declare, check on routes, register, test
placement/    A service's copy of a tenant's roles, for roles placed on its own objects
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

**TLS is selected by the URL scheme.** `rediss://…` connects over TLS; `redis://…` does not. `skip_verify=true` only relaxes certificate verification on a `rediss://` URL — on a `redis://` URL the client rejects it outright (`redis: unexpected option: skip_verify`) rather than silently upgrading the connection. Earlier Azugo versions did treat `skip_verify=true` as an implicit request for TLS; that side-effect is fixed from **Azugo v0.37** onwards, so a TLS endpoint must always be addressed as `rediss://`.

## Tests

```bash
go test ./...
```

DPoP proof round-trip and tamper/expiry/ath/nonce rejection
([`dpop`](dpop/dpop_test.go)), the stateless nonce
([`nonce`](nonce/nonce_test.go)) and every spelling of an identity code — for
**every identity type this library recognises**, crossed with the separator, no
separator and lower case ([`identitycode`](identitycode/identitycode_test.go),
with a fuzz target over the round trip a person makes when they retype what they
were shown) are covered. The end-to-end token+JWKS path is
exercised from the `authbyte-core` issuer tests.

## Contributing

Bug reports and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) names the gate a
change has to pass, what a change to this library needs, and the sign-off every commit carries.

Suspected vulnerabilities go through the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

## License

MIT — see [LICENSE](./LICENSE).
