# Normative references — pinned editions

The standards this library implements or cites, with the exact edition each claim in
the source was checked against. Citations in comments use the bracket form
`[ETSI EN 319 412-1 V1.7.1 §5.1.3]` — document, edition, clause — and resolve against
the editions pinned here. For a document that exists in a single edition, its number
is the pin: an IETF RFC is never revised in place, and a revision gets a new number.

| Source | Pinned edition | What it governs here |
|---|---|---|
| ETSI EN 319 412-1 | **V1.7.1** (May 2026) | The identity types an identity code can carry, and which of them belong to a natural person rather than to an organisation: the natural-person semantics (§5.1.3, carried in a certificate subject's `serialNumber`) and the legal-person semantics (§5.1.4, carried in its `organizationIdentifier`). `identitycode` recognises a subset of these and reads the natural/legal split from them. |
| IETF RFC 6749 | — | The OAuth 2.0 framework: how a confidential client authenticates with HTTP Basic, its id and secret form-encoded first (§2.3.1), as the client package does. |
| IETF RFC 7009 | — | Token revocation: the request the client package's `Revoke` sends. |
| IETF RFC 7519 | — | JSON Web Token: the audience claim an inbound token is checked against (§4.1.3). |
| IETF RFC 7636 | — | Proof Key for Code Exchange: the verifier and challenge the client package generates for an authorization-code flow. |
| IETF RFC 8176 | — | Authentication Method Reference values: the means of authentication an ID token's `amr` names (§2). |
| IETF RFC 9207 | — | Authorization server issuer identification: the `iss` parameter the client package checks on the browser's return (§2.4). |
| IETF RFC 9449 | — | OAuth 2.0 Demonstrating Proof of Possession: the proof the `dpop` package builds and verifies, including the HTTP URI it is bound to and the server-issued nonce. |
| OpenID Connect Core 1.0 | **incorporating errata set 2** (December 2023) | The ID token's claims (§2), the authentication request the client package builds (§3.1.2.1) and the checks it makes of an ID token (§3.1.3.7). |

When an edition here is superseded, re-check the citations naming the old edition
before bumping the pin — clause numbering moves between editions, so a citation can
keep resolving while pointing at different text.
