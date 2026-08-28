# Security policy

This library is the code that decides whether a request is allowed in. It validates access and
service tokens, verifies the DPoP proof that binds a token to the key that holds it, acquires this
service's own tokens, exchanges a user's token for a delegated one, and — in `asclient` — runs a
confidential browser login. Every authorization decision a consuming service makes reads the
identity this library put in front of it. A wrong answer here is not a bug in one endpoint; it is
that service's whole access-control boundary.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/gmb-lib/go-authbyte/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the configuration it needs, if it only appears under particular settings;
- whether you have told anyone else, and whether a disclosure date already binds you.

Please do not send us live tokens, keys or client secrets. A redacted token, or the shape of one,
is enough to explain almost any finding here.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

The unacceptable failure mode is a request admitted that should have been refused, or admitted as
somebody else. The classes that matter most:

- A token accepted whose signature, issuer, audience or validity window is wrong — including one
  verified against a key that is not the issuer's, or against a cached JWKS entry that is stale,
  poisoned, or refreshed from somewhere it should not be.
- A DPoP proof accepted that does not actually bind the request: a `cnf.jkt` that does not match the
  proof key, a wrong method or URL, a missing or incorrect access-token hash, a replayed proof
  identifier, or a server nonce that is issued but never enforced.
- The request context populated with a subject, tenant or scope set that the token does not carry —
  anything that makes a downstream authorization check read the wrong identity.
- A scope or level check that passes when it should not, in either direction: admitting a caller
  below the required level, or refusing one at or above it in a way that pushes a consumer to widen
  the gate.
- A delegated token issued or served for the wrong audience, scope or subject — a cache key that
  collides and hands one user's delegated token to a request made for another.
- This service's own client credentials, private key, or any token reaching a log line, an error
  body, a metric label, or an outbound request that was not its audience.
- In `asclient`: a login completing without the PKCE verifier, `state` or `nonce` being checked; a
  per-session key reused across sessions or users; a token or refresh token reaching the browser.

Denial of service and findings that need an already-compromised host or an already-authenticated
administrator are in scope but lower priority. Reports about outdated dependencies are welcome
where you can show the vulnerable path is actually reachable.

## Scope

This policy covers the code in this repository. It does not cover the authorization server whose
tokens it validates, the identity providers behind it, or the services that consume it — report
those to the parties that operate them. How a consuming application configures this library
(which audiences it trusts, which scopes it requires) is that application's responsibility; a
report that a *default* is unsafe is very much in scope.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward.
