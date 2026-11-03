# ADR-0044: Verify the report snapshot used by bridge comparison

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0027, ADR-0041, ADR-0042

## Context

Bridge verification checked the report through `verifyAssessment(report)`, which captures its own canonical snapshot, then captured the live report a second time for comparison. A native JavaScript Proxy could expose a checksum-valid fixture report during the first capture and a runtime evidence mode with the stale checksum during the second. A matching tampered export could then pass report-only verification across all six bridge kinds. Parsed CLI JSON has no changing native descriptors. Currency rechecking already refused this stale report through its own checksum validation.

## Decision

Capture the supplied report once with `r = JSON.parse(canonical(report))`, then verify `r`. Use that same isolated report for timestamp and shape checks, currency processing and export reconstruction. Keep existing output capture and error handling: a captured report with an invalid checksum returns `REPORT_INVALID`, while a valid captured report that differs from the export produces `REPORT_MISMATCH`.

## Alternatives

- Verify the live report before a later capture: rejected; checksum validation and comparison can observe different data.
- Capture comparison data but verify the original live report: rejected; a different valid view could conceal an invalid captured checksum.
- Reject every Proxy: no general portable Proxy detector exists. A single descriptor-backed capture follows the existing canonical-data contract.

## Consequences

The report checksum now binds the exact captured report used by the comparison. Honest plain JSON results and the existing report-only versus currency-rechecked distinction remain unchanged. Native reflection traps may still run during capture; this is not a JavaScript sandbox. The report checksum remains unauthenticated and a coherent false currency block can still pass without rechecking. No identity, authorization, truthful execution, outside conformance or independent assessment claim is added. Public schemas and assessment evaluator semantics are unchanged.

## Validation

Four frozen tests cover ordinary JSON validity and mismatches across all six kinds, a valid first native view followed by a stale-digest runtime view, one capture of benign native input including a currency-rechecked case, and refusal of an invalid captured checksum even when a later native view would be valid. The previous implementation passes two tests and fails two; the candidate must pass all four. Two syntax-valid mutants restore verify-before-capture or verify the original live report after capture. Both must fail the same test population, with no skipped, cancelled or TODO tests. Existing bridge, output-snapshot and currency-consistency regressions run separately. Tests and review remain same-team evidence; outside independent assessment is open.
