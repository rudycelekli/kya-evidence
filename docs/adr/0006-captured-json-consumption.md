# ADR-0006: Consume the same captured data that is verified

**Status**: Implemented
**Date**: 2026-10-13
**Depends-on**: ADR-0002, ADR-0003, ADR-0005
**Review**: Adversarial regressions reproduce independent review findings; separate final source review recorded privately. External security certification remains open.

## Context

The SDK accepts JavaScript values as well as parsed JSON. A Proxy can expose one value through its data descriptors for canonical hashing and another through property access for scoring. Verifying canonical bytes and then consuming the original executable object can substitute outcomes, trust roles, artifact digests, graph corrections or comparison scores. Repeated capture of an original object can also bind a different input view to retained evidence.

## Decision

Capture plain JSON once at each public data boundary and consume that captured value for validation, verification and the resulting decision. Capture dense array membership from data descriptors, refusing accessors, sparse entries and extra members. Assessment captures each receipt once; both its score and bundle digest derive from those captures. JSON-invalid receipts are rejected and represented by null digest markers. Response capture precedes evaluation and observation construction. Artifact, report, graph and release verification use captured metadata throughout. Research source references and correction references are captured before validation.

## Alternatives

Trusting canonicalization to validate an object without using its return value leaves the substitution path open. Requiring callers to always parse JSON would hide a public SDK integrity defect. Freezing an original Proxy does not establish a stable property-access view. Rejecting every Proxy is not reliably available in JavaScript and is unnecessary when the cryptographic and decision paths consume the same captured data.

## Consequences

These captures establish a consistent input view, not a sandbox for executable JavaScript. Proxy descriptor traps may execute caller code; callers must isolate untrusted code. The strict JSON subset still rejects getters and unsupported values without invoking their getters. Invalid receipt bodies retain explicit rejection and null bundle markers; invalid array containers reject the whole request. Captured objects can be edited after return, which invalidates their recorded checksums rather than preventing writes.

## Validation

Regression cases substitute signed outcomes, policy roles, forbidden permissions, artifact digests, array elements, report scores/checksums, unsafe response actions, evaluator bindings, manifest descriptor views, graph corrections and source rights. Assertions require decisions, retained observation artifacts and output metadata to agree with the canonical captured inputs. Mutation controls require complete passing baseline populations and substantive failures under weakened scoring gates. Historical research snapshots continue to require their archived assessor source.
