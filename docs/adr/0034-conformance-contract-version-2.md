# ADR-0034: Conformance contract version 2 (canonicalize, digest, verify-envelope, compare)

**Status**: Proposed
**Date**: 2026-10-18
**Depends-on**: ADR-0026, ADR-0016, ADR-0014

Review boundary: designed, implemented and tested by one project lane. The second implementation was written by a separate agent session from the specification text, but it is a same-team implementation, not independent review, and no outside implementation has run any vector.

## Context

The portable vectors (ADR-0026) pass 272 of 272 through the harness, yet only 37 of 247 requirements reach `pass` and 210 stay `not-run`. The cause is the contract, not the vectors: it has two operations, `assess` and `currency`, so a requirement that is about bytes, digests, envelopes or comparison cannot be tested without building a whole assessment around it. The ranked list in `docs/fixlane11-integration.md` puts `canonicalize` (KYA-INT-003 and the rest of KYA-INT-001), `compare` (KYA-BND-003) and a verify operation first among the requirements that need a new operation. The specification gave the intent of canonicalization but not the rules an implementer in another language needs (member order for non-BMP names, number formatting, the refused names, depth and size limits, escapes), did not say that digests are not domain separated, did not give the order in which an envelope is judged, and gave no list of comparison failures.

## Decision

Add four pure operations, each over behaviour the specification already makes normative or that this ADR writes into it first:

1. `canonicalize`: a JSON text to its canonical text and SHA-256, or a refusal. Normative text: "Canonical form and strict parsing".
2. `digest`: a named artifact (`manifest`, `scope`, `profile`, `policy`, `evidence-signing-input`, `incident-signing-input`) to its preimage and SHA-256, or a refusal when the value breaks its field rules. Normative text: "Digests and signing inputs". Domain separation applies to the two signing inputs only; record digests are plain canonical digests.
3. `verify-envelope`: an evidence or incident envelope to `valid` with the key ID, envelope digest and signing input digest, or `valid: false` with the code of the first failing step (eight codes in a fixed order). Validity is never trust. Normative text: "Envelope verification".
4. `compare`: two assessments to a comparison or the first of eight not-comparable reason codes; reports that fail their own checks are refused. Normative text: "Comparison of assessments".

Contract versioning. The contract becomes version 2. The envelope and result schema strings stay `kya.impl-input/v1` and `kya.impl-result/v1`, because the envelope shape is unchanged and an implementation that predates version 2 already answers an unknown operation with `unsupported`; changing the strings would make every existing implementation fail, not skip, the new vectors. The version is recorded in the vectors file (`kya.assessment-vectors/v2`, member `contract`). The 272 version 1 vectors keep their IDs and expected values byte for byte. One harness rule is extended: for a refusal vector of a version 2 operation, the exact `unsupported` reply for that operation is `not-run` rather than `fail`.

Clarifications written into the specification (each is behaviour the reference already had; none changes a result of a version 1 vector): the three refused member names, UTF-16 code unit ordering of member names, the number judgement after rounding and the safe integer bound, the shortest round-trip number form, lowercase escapes and literal U+007F, U+2028 and U+2029, an unpaired surrogate escape accepted and re-escaped, the depth rule, the one accepted public key spelling and RFC 8032 point rules inside the spec (previously only in the implementers guide), the verification step order, and the comparison rules including the evidence mode check and the shape checks on a report.

A library change follows from writing the comparison rule: `compareAssessments` now also requires the profile, evaluator and policy digests to be hashes, the scope ID, evidence mode, decision, `score.earned` and check entries to be well formed, so a resealed report that lacks one of those members is refused instead of comparing as equal by absence.

## Alternatives

- Bump the envelope schema to `kya.impl-input/v2`. Rejected: every existing implementation would exit non-zero on the new vectors and fail them, which mislabels an unimplemented operation as a bug.
- One `verify` operation covering reports, dossiers and credentials. Rejected as too large for one step; dossier and credential operations remain future work (see `docs/fixlane13-integration.md`).
- A `sign` operation. Rejected: signing needs a private key in the vector, and the published seeds are already enough for an implementer to check signing offline; verification is the interoperability surface.
- Return a refusal for a non-comparable pair or an invalid envelope. Rejected: any non-zero exit satisfies a refusal vector, so the reason would go untested.
- Change the reference to match whatever a second implementation does. Rejected: a disagreement is resolved by writing the rule into the specification with a test, never by editing an expected value.

## Consequences

- More of the standard is testable by a stranger: bytes, digests, signing inputs, envelope handling and comparison no longer need a full assessment fixture.
- Implementers owe four more operations. They may declare them unsupported and are then `not-run` for the requirements those vectors cite.
- The specification is longer and now carries rules the implementers guide used to hold.
- Same-team limits remain: the reference and the second implementation are both JavaScript and share a runtime, so number formatting and string escaping agree by construction. A non-JavaScript implementation is the real test of those rules.

## Validation

- `node scripts/run-vectors.mjs` against the reference adapter and the second implementation, with the counts recorded in `docs/IMPLEMENTERS-GUIDE.md` and `docs/fixlane13-integration.md`.
- `test/contract-operations.test.mjs`: operation behaviour, the version 1 byte compatibility, the unsupported rule for version 2 and the stated counts.
- The vector generator refuses to write when the reference disagrees with a hand-written claim for any new vector.
- Every disagreement between the reference and the second implementation is recorded in `interop/second-impl/AMBIGUITIES.md` with its resolution.
