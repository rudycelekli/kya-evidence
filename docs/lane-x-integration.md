# Lane X integration proposals (WS1-02)

Not applied to shared files. For the integrator.

## Bridge wiring (not done, with reason)

An added `limitCodes` member would alter serialized export bytes, and `verifyBridgeExport` compares every member of the expected and actual export (union of keys), so older verifiers and the interop vectors would reject or differ. Proposal: a new export schema version that adds `limitCodes: codesForLimitStrings(LIMITS)`, with regenerated vectors, decided under ADR-0027's versioning.

## Requirements (evidence/requirements.json), section "Interoperability and versioning"

- KYA-CLB-001 (MUST, area claim-boundaries): Every limit string emitted by a scanned module MUST be covered by a registry code. Test: test/claim-boundaries.test.mjs, "every limit string emitted by src is covered by the claim boundary registry".
- KYA-CLB-002 (MUST): The registry MUST NOT contain a string that src no longer emits. Test: "every claim boundary registry string is still present in src".
- KYA-CLB-003 (MUST): Codes MUST be unique, upper snake case and append-only. Tests: "claim boundary codes are unique and upper snake case"; "claim boundary codes are append only against the committed list".
- KYA-CLB-004 (MUST): `codesForLimitStrings` MUST throw on an unknown string and cover the outputs of assess and checkCurrency. Tests: "codesForLimitStrings throws on an unknown string and describe throws on an unknown code"; "codesForLimitStrings covers the real assess and checkCurrency outputs".
- KYA-CLB-005 (MUST): The benchmark verifier inline limitation list MUST equal the emitted list. Test: "benchmark verifier inline limitation list matches the emitted list".

Sections exist as headings in docs/SPECIFICATION.md: "Interoperability and versioning" and "Reports and viewers".

## Specification paragraph (under "Interoperability and versioning")

Claim-boundary codes classify the limit statements an artifact carries. A code states what the artifact does not show and never raises confidence. The registry (`evidence/claim-boundaries.json`) is append-only. Codes are not part of any record, digest or export; a producer MUST NOT omit or reword a limit statement because a code exists.

## world-class-status WS1-02

Set status to `partial` (not `done`): registry, module, tests, docs/CLAIM-BOUNDARIES.md and ADR-0031 exist; codes are not carried on artifacts, the scan covers a fixed emitter list, and no outside reader has used it. Evidence refs: evidence/claim-boundaries.json, src/claim-boundaries/index.mjs, test/claim-boundaries.test.mjs, docs/CLAIM-BOUNDARIES.md, docs/adr/0031-claim-boundary-codes.md. Also add `./claim-boundaries` to package.json `exports` when the integrator agrees.
