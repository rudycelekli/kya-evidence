# ADR-0045: Compare credentials with the report snapshot whose checksum was checked

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0022, ADR-0044

## Context

The VC verifier promises whole-credential comparison when the original report is supplied. It called `verifyAssessment(report)`, which captures and verifies an internal canonical snapshot, but rebuilt the credential from the caller's original report. A native JavaScript Proxy could expose a valid report through descriptors while returning an altered score through GET. A credential re-signed by the synthetic issuer with that altered score then passed report comparison. The same credential failed against the ordinary original report. This is a consistency defect in native report handling; it does not demonstrate compromised signing keys or affect ordinary parsed CLI JSON.

## Decision

Capture `report = JSON.parse(canonical(report))` before verifying its checksum. Use that same snapshot for all subsequent report reconstruction and validity bounds. Retain existing `REPORT_INVALID` and `REPORT_MISMATCH` results, status checks and issuer-policy handling.

## Alternatives

- Verify a private snapshot but compare live report reads: rejected because they can expose different data.
- Capture after verification: rejected; a second descriptor view can differ from the checked one.
- Reject every Proxy: no portable general Proxy detector exists. The canonical descriptor-backed data is the existing JSON boundary.

## Consequences

Honest JSON reports retain their results. A live GET view cannot replace the checked score, and a report is captured once before checking and reconstruction. Reflection traps can still execute during capture; this is not a JavaScript sandbox. The report checksum remains unauthenticated. Credential signatures prove integrity and key possession, not truthful execution, identity or authorization. A holder can still edit and re-sign a credential without an original report; that documented claim ceiling is unchanged. Schemas, core evaluator identity, scoring and public assessment vectors are unchanged.

## Validation

Three frozen tests cover ordinary JSON compatibility, plain tamper and stale-checksum refusal, static GET and changing-descriptor report substitution, and an honest native report captured once without GET reads. The previous verifier passes one and fails two; the candidate must pass all three. Two syntax-valid mutants remove capture or move it after verification, and the same test population must detect both with complete execution, no skips, cancellations or TODOs. Existing VC tests run separately. Evidence and review are same-team; outside independent assessment remains open.
