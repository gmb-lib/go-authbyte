# Normative references — pinned editions

The standards this library implements or cites, with the exact edition each claim in
the source was checked against. Citations in comments use the bracket form
`[ETSI EN 319 412-1 V1.7.1 §5.1.3]` — document, edition, clause — and resolve against
the editions pinned here. For a document that exists in a single edition, its number
is the pin: an IETF RFC is never revised in place, and a revision gets a new number.

| Source | Pinned edition | What it governs here |
|---|---|---|
| ETSI EN 319 412-1 | **V1.7.1** (May 2026) | The identity types an identity code can carry, and which of them belong to a natural person rather than to an organisation: the natural-person semantics (§5.1.3, carried in a certificate subject's `serialNumber`) and the legal-person semantics (§5.1.4, carried in its `organizationIdentifier`). `identitycode` recognises a subset of these and reads the natural/legal split from them. |
| IETF RFC 7636 | — | Proof Key for Code Exchange: the verifier and challenge the client package generates for an authorization-code flow. |
| IETF RFC 9449 | — | OAuth 2.0 Demonstrating Proof of Possession: the proof the `dpop` package builds and verifies, including the HTTP URI it is bound to and the server-issued nonce. |

When an edition here is superseded, re-check the citations naming the old edition
before bumping the pin — clause numbering moves between editions, so a citation can
keep resolving while pointing at different text.
