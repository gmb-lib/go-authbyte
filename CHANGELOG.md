# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency — what changed, and what it means for code that already
uses it.

## Unreleased

### Changed

- **The inbound gate now says which check it refused on — in the service's own log, never on the
  wire.** A refused request answered `401` and logged one undifferentiated line, because the real
  reason was discarded: the JWT error naming expiry, audience, issuer, signature or an unknown key
  id was thrown away and replaced with a bare unauthorized, and the four separate DPoP failures
  (proof did not verify, proof key is not the token's key, replay, and a token that is not
  sender-constrained at all) all collapsed into one code. An expired service token and a forged one
  produced identical evidence, which makes a service dropping its own background writes effectively
  undiagnosable.

  Each refusal now carries a reason inward and the gate logs it at `warn` alongside the underlying
  error. **The response is unchanged** — same status, same body, same `WWW-Authenticate` — because
  telling a caller which check it failed hands an attacker half the answer; the reason is for the
  service that refused, not the one that was refused. Nothing to configure, and no behaviour change
  for a request that was going to be accepted.

  A `DPoP-Nonce` challenge is not affected: it is not a refusal but the protocol's own first-request
  handshake, and it stays on its existing path.

## v0.20.1

### Changed

- **`azugo.io/azugo` and `azugo.io/core` → v0.38.0, `github.com/gmb-lib/go-platform-kit` →
  v1.10.0.** No source change here: the platform-kit release is additive, and nothing in this
  library is affected by it.

  One thing in the framework release is worth knowing if you use azugo directly: `user.Basic`'s
  `MarshalJSON` **moved to a pointer receiver**, so marshalling a `Basic` *value* silently produces
  default field JSON instead of the custom form — no compile error. Nothing here holds that type by
  value.

### Notes

- The repository gained the open-source kit it was missing — `SECURITY.md`, `CONTRIBUTING.md`,
  a secret-scan configuration and the README sections pointing at them — plus this file.

---

The entries below were **reconstructed from git history** rather than written at the time, so they
say what each tag contains, not why it was decided.

## v0.20.0

- **New package `asclient`** — an OAuth 2.0 confidential-client for the browser login flow, with
  PKCE: `New(publicURL, internalURL, clientID, redirectURI, opts...)`, `WithHTTPClient`, and the
  `Tokens` / `Identity` results. Nothing else in the library changed shape to accommodate it.
- **New claim: `tenant`** (`claims.ClaimTenant`, `Claims.Tenant`). The organisation the user acts
  under, resolved at token issue; a deployment without a membership register mints no tenant. It is
  carried through on-behalf delegation like the identity code, so a multi-tenant resource service
  scopes by the tenant *from the token* rather than from request data.
- **The unknown-kid JWKS refresh is fixed, and rate-limited.** The refresh decision is now based on
  the cache version the miss was seen against, not on the cache's *age* — an unknown `kid`
  previously short-circuited on age, which meant a signing-key rotation was not picked up until the
  cache expired on its own. It now really does refetch, so rotation takes effect in flight. To stop
  that becoming a lever, an unrecognised `kid` costs at most one fetch per
  `DefaultMinRefreshInterval`, overridable with `jwks.WithMinRefreshInterval`.

  **If you are on v0.15.1 or earlier, this is the reason to bump.** Until this release, an inbound
  gate could keep rejecting tokens signed with a newly rotated key.

- **Versions v0.16.0 – v0.19.0 do not exist in this repository.** The repository was rebuilt and
  those four tags were not re-published; the changes they carried are contained in v0.20.0. A
  `go.mod` pinning one of them will not resolve — move to v0.20.0 or later.

## v0.15.1

- Documentation only: the Redis/Valkey TLS rule (`rediss://` selects TLS; `skip_verify` is not a
  switch that turns it on).

## v0.15.0

- **`Client.DoServiceWithTimeout` and `Client.DoServiceOnBehalfWithTimeout`** — the existing
  service-call and on-behalf-call shapes with an explicit per-call timeout, for a caller that must
  bound a hop itself rather than inherit the client's default.

## v0.14.1

- Documentation only.

## v0.14.0

- A type conversion at the DPoP verification call site, where the request method is handed to
  `dpop.Verify`. The value passed is the same request method; nothing changes for a caller.

## v0.13.0

- **The correlation id now rides outbound and background calls.** Both client paths set the
  correlation header from the calling context when one is present, so a callee logs under the same
  id as its caller instead of starting a new chain.

## v0.12.0

- **New claim: `serial_number`** (`claims.ClaimSerialNumber`, `Claims.SerialNumber`) — the eIDAS
  personal or legal identity code of the user (`PNOLV-…`), present on user tokens and carried
  through on-behalf delegation. It identifies the named party for non-repudiation, which is what
  lets a downstream service match a caller to, for example, an invited co-signer slot.

## v0.11.0

- **`Client.DoServiceOnBehalf`** — an arbitrary method/URL/body service call made on behalf of a
  subject, alongside the JSON-shaped helpers added in v0.10.0.

## v0.10.0

- **Delegated tokens (RFC 8693 token exchange).** `Client.AcquireDelegatedToken`, plus
  `GetJSONOnBehalf` and `PostJSONOnBehalf` for the common JSON hops; the `Actor` type and
  `Claims.Delegated()` for the receiving side, so a service can tell a delegated token from a
  direct one.

## v0.9.0 and earlier

- Not reconstructed. See the git history and the tag list.
