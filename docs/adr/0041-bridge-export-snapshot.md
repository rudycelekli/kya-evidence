# ADR-0041: Capture bridge export data before verification reads

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0012

## Context

The bridge verifier promises to compare the whole supplied export in canonical form with a reconstruction from the report. It validated `canonical(output)` but discarded those bytes. Later shape reads and comparison accessed the original object. A native JavaScript caller could supply a Proxy whose descriptors contained a tampered score or evidence mode while its GET trap returned the original report-derived value. Such an export could pass, including with currency rechecking. Parsed CLI JSON does not contain Proxy behavior.

## Decision

Capture the canonical descriptor-backed data once as `JSON.parse(canonical(output))` before any export shape reads. Use that isolated snapshot for currency extraction, reconstruction options and whole-export comparison. Apply the same capture to every bridge kind. Retain existing resource bounds and malformed-input errors.

## Alternatives

- Validate and continue reading the original object: rejected; validation and comparison can observe different values.
- Capture immediately before final comparison: rejected; earlier currency and URL reads still observe live behavior.
- Reject every Proxy: JavaScript provides no general portable Proxy detector. Capturing the declared JSON data fits the existing canonicalization contract.

## Consequences

Honest plain JSON exports keep their existing result. Native objects are checked against the data their descriptors expose during capture, without later GET views changing the result. This is not a general sandbox for hostile JavaScript: reflection traps can still execute during capture. The supplied report checksum remains unauthenticated. Currency is independently recomputed only when its inputs are supplied; the change creates no identity, permission, truthful-execution or outside conformance claim. Public output schemas and evaluator semantics are unchanged.

## Validation

Four frozen tests cover forged GET views across all six bridge kinds in report-only and currency-rechecked modes, GET traps on otherwise honest exports, nested currency GET traps and ordinary JSON compatibility. The previous verifier passes one test and fails three; the candidate must pass all four. Two syntax-checked mutants discard the capture or delay it until after live reads. Both must be detected by the same frozen tests, with complete execution and no skips or cancellations. Existing bridge and native-object regressions run separately. Tests and review are same-team evidence; independent assessment remains open.
