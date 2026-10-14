# ADR-0025: Cryptographic agility and algorithm identifiers

**Status**: Proposed
**Date**: 2026-10-15
**Depends-on**: ADR-0014, ADR-0017, ADR-0020, ADR-0021, ADR-0022

Review boundary: design and documentation only, plus an inventory test; nothing in `src/` changes, no independent cryptographic review, no external certification.

## Context

Every KYA signature is Ed25519 over `DOMAIN + canonical(payload)` and every digest is SHA-256 over KYA canonical JSON (`docs/CRYPTO-AGILITY.md` section 1). Records use exact-key validation, so unknown fields are rejected, and digest fields are bare 64-character hex. That is safe today, but it means a new algorithm or hash cannot be added as an optional field: a verifier would reject it, and an attacker who strips a new proof from a record must not be able to make an old verifier accept something weaker than policy intends. Evidence must stay verifiable after a change, and a retired algorithm leaves old evidence forgeable unless it was anchored or countersigned first (ADR-0020). Separately, `canonical()` is described in ADR-0022 as differing from RFC 8785 in formatting and ordering; testing (CRYPTO-AGILITY section 3) shows identical output for accepted inputs and differences only in the accepted input set.

## Decision

1. Adopt the algorithm-agility design in `docs/CRYPTO-AGILITY.md` section 2 as the plan of record. It is a plan; no behaviour changes now.
2. A new signature algorithm or a new hash enters only as a new schema version (`kya.<type>/v2`), never as an optional member of v1.
3. v2 signing inputs bind the algorithm identifier: `kya.<type>/v2\n<algorithm>\n` followed by canonical payload. Algorithm identifiers are exact strings from a spec table; unknown identifiers are refused and never negotiated.
4. v2 envelopes carry `proofs`, a list, so dual signing is possible. The relying party's policy, not the record, states `acceptedAlgorithms` and `requiredAlgorithms`; a record missing a required algorithm is refused (downgrade resistance).
5. v2 digests are labelled (`sha256:<hex>`) and computed over a domain label plus canonical bytes. v1 digests keep their meaning forever.
6. v1 verifiers, golden vectors and the Python subset stay in the tree as the archival reader. The domain-separation audit and the inventory test must be updated in the same change as any new prefix or algorithm.
7. KYA canonical JSON remains the canonical form for v1 and is documented as a strict subset of JCS output with named differences (unsafe integers, lone surrogates, reserved member names, resource limits). A claim of JCS conformance waits for a v2 canonicaliser, RFC 8785 vectors and an independent implementation run.
8. No algorithm is retired for new evidence until old evidence has been anchored or countersigned.

## Alternatives

Optional `algorithm` extension fields on v1: rejected, because strict validation would reject them and relaxing it weakens every parser. Algorithm negotiation by the signer: rejected, it enables downgrade. Switching to JOSE or COSE envelopes for all records: rejected for now, it would change every signed byte and the VC bridge already uses JWS only for export. Adding a post-quantum signature today: rejected, Node 22.19.0 on the author's machine does not expose one and the project has no runtime dependencies; see the post-quantum note. Adopting JCS immediately for v1: rejected. Output for accepted values already matches, but the safe-integer and lone-surrogate rules would have to change, which alters what v1 verifiers accept and requires re-verifying every golden vector; deferred to a v2 canonicaliser.

## Consequences

Positive: a reviewable path exists to introduce algorithms without invalidating evidence; the inventory is checked by CI so a new prefix or hash cannot appear undocumented; the RFC 8785 position is stated precisely. Costs: schemas double in number during a transition, policies grow algorithm fields, and every phase needs a requirement, vectors and an ADR. Open: the policy schema change, the v2 canonicaliser, anchoring (ADR-0020, still Proposed), and any real algorithm choice. ADR-0022's wording about formatting and ordering is inaccurate per the tests and should be corrected in a follow-up change. A wrong `v2` design is still possible; this ADR is Proposed so it can be revised before any code depends on it.

## Validation

`test/crypto-inventory.test.mjs` fails if a signing domain prefix, a hash or HMAC algorithm, a holdout label or a signing site without a prefix appears in `src/` without an entry in `docs/CRYPTO-AGILITY.md`, if a second proof algorithm identifier appears, or if the documented RFC 8785 comparison stops holding for the listed values. Not validated: an independent JCS implementation, any post-quantum implementation, and the v2 envelope itself.
