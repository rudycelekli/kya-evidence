# ADR-0035: Conformance contract operations for credentials and score cards (verify-credential, verify-score-card, compare-score-cards)

**Status**: Proposed
**Date**: 2026-10-19
**Depends-on**: ADR-0034, ADR-0026, ADR-0022, ADR-0033

Review boundary: designed, implemented and tested by one project lane. The second implementation was written by a separate agent session from the specification text and the contract README, but it is a same-team implementation, not independent review, and no outside implementation has run any vector.

## Context

After contract version 2 (ADR-0034) the portable vectors cover assessment, currency, canonical form, digests, envelope verification and comparison, yet 219 of 258 registry requirements stay `not-run`. The ranked list in `docs/fixlane13-integration.md` named three groups that the contract cannot reach: the credential bridge (16 requirements, KYA-VCB), the capture requirements (19, KYA-CAP) and the score card requirements (14, KYA-SCR). The capture requirements describe a runtime cell, not a pure function of an input, and the dossier requirements need a size and rendering decision, so neither is the next step. The credential and score card rules are pure functions of their inputs, were written down only in `docs/VC-BRIDGE.md` and ADR-0033, and are not in the specification that implementers read.

## Decision

Add three pure operations and write their rules into `docs/SPECIFICATION.md` first ("Credential verification", "Score card verification"):

1. `verify-credential`: a `vc+jwt` assessment credential, a supplied time, expected issuers, an optional policy, status list tokens and an optional source report, to `valid` and the ordered list of error codes, the issuer trust level and the status of each entry. Codes only, never messages. The opening steps (21), the claim rules (6), the report binding, policy trust and the status list check are stated in an order, so the first failing step is observable.
2. `verify-score-card`: any JSON value to `valid`, the ordered problem codes, and for a valid card the headline score and card digest. The layout and the algorithms (seeded sfc32 generator, bootstrap, rounding, aggregates) are restated from ADR-0033 in the specification so that a reader does not need the ADR.
3. `compare-score-cards`: two values to a comparison or the reasons it is not allowed.

Contract versioning. The version number stays 2. No schema string changed (`kya.impl-input/v1`, `kya.impl-result/v1`, `kya.assessment-vectors/v2`) and no existing vector changed; the earlier 485 vectors are byte for byte identical (their combined digest is pinned in `test/contract-credential-score.test.mjs`). An implementation that predates these operations already answers an unknown operation with the exact `unsupported` reply, and the harness already scores that as `not-run` for a result vector and, for a refusal vector of an operation outside `assess` and `currency`, also as `not-run`. The version number therefore changes only when a schema string or the vector file schema must change. Operations are added by listing them in the `contract.operations` member of the vectors file. A reader who needs a count of operations reads that member, not the version.

Writing the text exposed behaviour of the library that a second implementation could not have guessed, and four of them were changed so that the text could say something simple and true:

- A token whose header or payload bytes are ill-formed UTF-8 is refused (`MALFORMED`); the library used to replace the bytes and parse the result.
- The evidence block is element 0 of an array; an object with a member named `0` used to be read as one.
- A status list is looked up by own member only and only for a string URL; an inherited name such as `toString` or a coerced key used to be found. The contract also refuses status list maps whose values are empty or not strings.
- A report that passes its checksum but lacks a member the rebuild needs is `REPORT_INVALID`; it used to make the verifier throw.

## Alternatives

- One `verify` operation for credentials, status lists and cards. Rejected: three different input shapes and result shapes, and no shared failure vocabulary.
- Verify only the JWS and leave claims, report binding and status to a later contract. Rejected: the requirements about fixture laundering, re-signed edits and revocation are about those steps, and the verifier would report `valid` for credentials the repository itself treats as broken.
- Put the status list check in its own operation. Rejected for now: the list is only meaningful relative to a credential entry and issuer; a separate operation would have to restate both.
- Bump the contract to version 3. Rejected: nothing a version 2 implementation relies on changed.
- Cover the capture requirements with `verify-capture`. Deferred: the record, hash chain and canary rules must first be written as pure inputs.

## Consequences

- Twenty-one more requirements reach `pass` in the harness report (60 of 258 instead of 39). `pass` means every vector citing the requirement passed, not that the requirement is fully tested; see `docs/fixlane14-integration.md` for what each new `pass` rests on.
- Implementers owe three more operations, each optional. Declaring them unsupported costs nothing already earned.
- The credential section fixes error code vocabulary and an order for them. A different order or a different code for the same failure is a conformance difference.
- Same-team limits remain: both implementations are JavaScript on one runtime, so Ed25519 verification (including the scalar bound), GZIP, base64url and number formatting agree partly by construction; the status list GZIP edge cases (trailing data, concatenated members) are not exercised.

## Validation

- `node scripts/run-vectors.mjs` against the reference adapter and the second implementation; counts in `docs/fixlane14-integration.md` and `docs/IMPLEMENTERS-GUIDE.md`.
- `test/contract-credential-score.test.mjs` and `test/contract-operations.test.mjs`: behaviour, byte compatibility of the earlier vectors, not-run scoring for an implementation of the six earlier operations, and the refusal share.
- The generator refuses to write when the reference disagrees with a hand-written claim.
- Every disagreement between the reference and the second implementation is written into the specification with a test; none is resolved by editing an expected value.
