# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency — what changed, and what it means for code that already
uses it.

## v0.23.1

Dependency maintenance with one thing to act on: **this library now needs Go 1.27**. No source
changed here and nothing it does behaves differently.

### Changed

- **The module declares `go 1.27.0`** (was `1.26.6`), so your own module has to be on Go 1.27
  before it can build against this one. A dependency's `go` line does **not** make the go command
  fetch a newer toolchain for you — measured both ways: a consumer whose own `go` directive is
  lower stops with a `requires go >= 1.27.0 (running go 1.26.6)` error, and it stops there with
  `GOTOOLCHAIN` on its `auto` default just as it does under `local`. Raise your own `go` directive
  to `1.27.0` first; from there the go command downloads and uses the 1.27 toolchain by itself, so
  nobody has to install Go by hand. CI that reads `go-version-file: go.mod` follows the bump with
  no workflow edit — a workflow naming a Go version in the YAML needs that line changed.

### Notes

- **`github.com/gmb-lib/go-platform-kit` → v1.11.3** (was v1.11.2), which is itself a dependency
  release: it carries the same Go 1.27 requirement and no source change. Nothing this library takes
  from it moved.

- One indirect dependency moved and nothing here calls it: `github.com/molecule-man/go-brrr` →
  **v1.1.0**, the brotli implementation fasthttp pulls in. Relevant only if you audit dependencies
  or keep a bill of materials.

- The gate is green on the new set: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`, and
  `go test -race` across all seven packages with **0 races**; `govulncheck` finds nothing.

## v0.23.0

### Added — `identitycode` answers whether a code belongs to a person or to an organisation

`Code.IsNaturalPerson()` reports whether an identity code identifies a natural person. The standard
splits the identity types into two lists, and a certificate carries them in two different places: a
natural person's code in the subject's `serialNumber`, a legal person's in its
`organizationIdentifier`. That split decides what a code can be used for — wherever a code has to
name somebody who will later authenticate, only a natural person's code can ever be matched, because
nobody authenticates as an organisation. Its electronic seal is a signing method its people reach for
after identifying themselves.

```go
c, err := identitycode.Parse(stored)
if err == nil && !c.IsNaturalPerson() {
    // a trade-register number: a valid identity, and one no login will ever answer to
}
```

It is false for anything the standard does not place with a natural person — an unrecognised type and
a zero `Code` included — because the question is asked in order to refuse, and a caller that cannot
tell whose code it holds has to refuse.

**If your code keeps its own list of which identity types are people, this replaces it.** The list
here is the standard's rather than this package's: it names every natural-person type the standard
defines, including the ones `identitycode` does not yet recognise, so admitting a further type later
does not silently change the answer. The behaviour of every existing call is unchanged, which is why
this is an addition and nothing else.

### Added — the editions the citations resolve against are pinned

`SPECREFS.md` now lists the standards this library cites and the exact edition each claim was checked
against, so a bracketed citation in a comment is resolvable by a reader who has never seen this
repository. No code changed.

### Added — every identity type is exercised, in both spellings a prefixed code arrives in

`identitycode`'s test suite now crosses **all five** recognised identity types — `PNO`, `NTR`, `PAS`, `IDC`,
`TIN` — with the separator, without it, and in lower case, asserting the canonical value, `Parse`, `Key` and
`Display` on each. **No behaviour changed**: this is coverage, and a consumer needs no action.

It is worth an entry because of what it found: a tax number (`TIN`) had **no vector at all** in this suite,
and an identity card (`IDC`) appeared only in a display case — so a code arriving under either was untested
on the one path that decides who a person is. Removing `IDC` from the recognised set is caught by nothing
else in the suite, which is how the gap was measured rather than assumed. The store side of the same rule
carries the identical matrix.

## v0.22.0

### Fixed

- **`identitycode.Display` no longer drops the country and the identity type.** It returned the bare national
  identifier for every code except a Latvian personal number, so `PNOEE-…`, `PNOLT-…`, `NTREE-…`, `PASEE-…`
  and `IDCEE-…` holding the same digits all rendered as one identical string — a person, a foreign namesake
  and an organisation's register number, indistinguishable on screen. The country is part of the identity: the
  same digits in two countries belong to two people.

  Where a country's own way of writing the number is known, that spelling is unchanged — a Latvian personal
  number still reads `123456-78901`. Everywhere else `Display` now returns the code **exactly as stored**:

  ```go
  identitycode.Display("PNOLV-01018015097")   // "010180-15097"     (unchanged)
  identitycode.Display("PNOEE-23456789012")   // "PNOEE-23456789012"  (was "23456789012")
  identitycode.Display("NTRLV-34567890123")   // "NTRLV-34567890123"  (was "34567890123")
  ```

  **What it means for code that already uses it:** nothing renders differently for a Latvian personal number,
  which is the case the function was written for. Any other code now renders longer and carries its type
  prefix — a screen with a fixed-width field for it may need a look. A prefixed spelling was chosen over
  writing the country in front (`EE 23456789012`) deliberately: the canonicaliser reads a space or a hyphen as
  a separator, so a person retyping what they were shown would have had the country absorbed into the
  identifier and resolved to a **different key, with no error**. The stored spelling round-trips, and the fuzz
  test asserts it does.

## v0.21.0

### Added

- **New package `identitycode` — one spelling of an identity code, for storing, comparing and
  showing.** A signatory's identity code reaches a service written several ways: with the identity
  type and country a certificate or an identity provider puts on it (`PNOLV-123456-78901`), with
  the separator dropped (`PNOLV-12345678901`), as a person writes their national code
  (`123456-78901`), as a form sends it once the separator is gone (`12345678901`), or in the
  `LV/LV/123456-78901` shape a cross-border login carries. Compared as text those are five
  different people, and the one who signed a document under one spelling could not find it under
  another.

  `Canonical(raw, country)` returns the single spelling to store — the identity type, the country,
  a hyphen, and the national code with its separators removed, upper-cased — so identity can be
  compared with plain equality:

  ```go
  stored, err := identitycode.Canonical(" pnolv-123456-78901 ", "")  // "PNOLV-12345678901"
  stored, err = identitycode.Canonical("123456-78901", "LV")         // "PNOLV-12345678901"
  stored, err = identitycode.Canonical("12345678901", "LV")          // "PNOLV-12345678901"
  stored, err = identitycode.Canonical("LV/LV/123456-78901", "")     // "PNOLV-12345678901"

  identitycode.Display("PNOLV-12345678901")                          // "123456-78901"
  identitycode.Key(someValueOfUnknownProvenance)                     // the value to compare by
  ```

  `country` is a hint, and it is consulted **only** when the code names no country of its own — the
  country chosen on the screen it was typed into, the country in the signing certificate, the
  country recorded for the system that sent it. A country in the value always wins, and one that
  contradicts the hint is not an error: a caller's software may or may not put the country on the
  wire, and both have to work.

  **The country is never guessed.** A bare code with no country available is refused with
  `ErrCountryRequired` rather than filed under a default, because the same digits belong to
  different people in different countries and a wrong identity key is the wrong person's documents.
  The other refusals are `ErrEmpty`, `ErrCountryInvalid`, `ErrUnknownSemantics` (an identity type
  the package does not recognise — it recognises `PNO`, `NTR`, `PAS`, `IDC` and `TIN`),
  `ErrAmbiguous` (a code with no identity type that begins like one, which cannot be told from a
  code that has one) and `ErrMalformed`. Every one of them is a refusal instead of a guess: none
  carries the offending value, because an identity code is personal data and these errors reach
  service logs.

  Validation is shape only — no checksum, and no per-country length rule. A typed code is a
  reference to a person, and what settles who signed is the certificate they sign with, so a rule
  written for one country's format could only add ways to refuse a real foreign signatory.

  Nothing else in the library changed shape to accommodate the package, it calls nothing, and it
  needs no configuration.

### Changed

- **Dependencies moved up. No source change here, and none asked of you.** `azugo.io/azugo` and
  `azugo.io/core` → **v0.38.1**, `github.com/gmb-lib/go-platform-kit` → **v1.11.2**,
  `github.com/go-jose/go-jose/v4` → **v4.1.5**, `github.com/valyala/fasthttp` → **v1.74.0**. The
  gate is green on the new set: build, vet, `gofmt`, `go mod tidy -diff`, and `go test -race` across
  all seven packages with **0 races**, plus the fuzz target.

  `go-platform-kit` v1.11.2 is itself a dependency move with no source change of its own; its
  changelog covers what it carries, and the one item that reaches a running service is the next
  entry here.

- **The bump clears two `golang.org/x/crypto` advisories, and adds none.** It carries x/crypto from
  v0.55.0 to v0.57.0, which resolves **GO-2026-6354** and **GO-2026-6355** (both fixed upstream in
  v0.56.0). **GO-2026-5932** remains — it has no fixed version published, and it was already present
  on v0.55.0, so nothing new arrives with this release. `govulncheck` reports **0 vulnerabilities
  this library's code is affected by**, before and after: all three sit in required modules whose
  vulnerable paths are not called from here. Measured both ways — the same scan was run against the
  pre-bump tree to be sure the remaining advisory was carried forward rather than introduced.

- **The metrics endpoint no longer negotiates OpenMetrics** — an azugo change, and one that shows up
  in your monitoring rather than in your code. Up to azugo v0.38.0 a scraper sending
  `Accept: application/openmetrics-text` was answered with
  `Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8` and the `# EOF`
  terminator that format requires; from **v0.38.1** the endpoint always answers
  `Content-Type: text/plain; version=0.0.4; charset=utf-8` and writes no `# EOF`. Metric names,
  labels and values are unchanged. This library does not serve that endpoint — azugo does, in your
  service — but it arrives with this bump by two routes at once: this library requires azugo
  directly, and `go-platform-kit` v1.11.2 does too, binding azugo's metrics configuration for every
  service that uses it. **Check your scrape configuration before deploying** if it demands the OpenMetrics
  content type or uses `# EOF` to tell a complete scrape from a truncated one. The capability had
  been there since azugo v0.32.0.

- **What go-jose v4.1.5 changes for you: almost nothing, and here is why.** This library uses
  go-jose for exactly two things — `JSONWebKey` and `JSONWebKeySet`, so reading a JWK Set and
  taking key thumbprints. Token and DPoP-proof signatures are verified by `golang-jwt/jwt/v5`,
  restricted to `ES256`. Most of the release therefore lands in code this library never calls: a
  new curve check on go-jose's *own* ECDSA verification (`ES256` now requires a P-256 key, `ES384` a
  P-384 key, `ES512` a P-521 key), and empty-input plus CBC-HMAC key-size guards on its JWS and JWE
  parsing.

  What does touch the JWKS path is a rework of `JSONWebKey` unmarshalling: it now returns at the
  point of failure instead of assigning and checking afterwards. **The accept/reject outcome is
  unchanged** — the previous code already returned on that error immediately after its type switch,
  so no malformed key was ever accepted, and none is refused now that was not refused before.

  One API change is worth naming because it is a compile break rather than a behaviour one: the
  package variable **`RandReader` is now unexported**. Code that substituted it — typically a test
  injecting deterministic randomness — will not build against v4.1.5. Nothing in this library does,
  and nothing in any of its known consumers does either.

### Notes

- Repository hygiene, no effect on code that uses the library: a code of conduct was added, and the
  advisory DCO workflow was removed now that the check is enforced by the organisation's app and a
  branch ruleset.

## v0.20.2

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
