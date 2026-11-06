# ADR-0053: Freeze array membership before canonical traversal

**Status**: Implemented locally; same-team review pending
**Date**: 2026-11-05
**Related**: ADR-0006, ADR-0052

## Context

Canonical JSON checked an array's live GET length, checked own keys against another GET length, then used more GET length reads during traversal. A Proxy over two own data items could report length two for the initial checks and one for traversal. Serialization silently omitted the second own item. The same view could conceal an own accessor that should have been refused. Ordinary JSON arrays and existing accessor controls did not exercise this changing length view.

## Decision

Reuse the existing descriptor-based captureArrayItems helper for canonical array membership, including its 100000-item limit, dense own keys and enumerable data-descriptor checks. Traverse the captured values rather than the caller's executable length view. Keep recursive node, depth and byte limits. Freeze the four deterministic synthetic cases before implementation and run the same evaluator on baseline, candidate and an actual weakening that restores only the former array branch.

## Alternatives

Caching the first GET length still trusts an executable substituted view. Re-reading descriptors while traversing lets caller behavior change later membership. Duplicating the existing helper adds another dense-array validator to maintain.

## Consequences

Normal JSON output and golden hashes remain unchanged. Executable length GET views cannot shorten the captured population or hide an own accessor. Reflective Proxy traps can still run or throw; this is not a sandbox, an atomic snapshot of an entire mutable object graph, an execution attestation or outside independent review. Strict array refusal wording now follows the shared capture helper. Canonical implementation bytes are bound into the conformance evaluator identity, so refresh its pinned digest explicitly; older evidence requires the archived evaluator.

## Validation

Four case designs and their concrete literal inputs were frozen before source edits: ordinary two-item output, changing GET length, throwing GET length and an accessor concealed behind changing length. Baseline passes one and fails three; candidate passes four and the existing canonical/property regressions (48 total). Restoring the original live-length branch in an isolated copy passes one and fails three, with identical frozen test bytes. No random signing keys or model calls occur in these controls. Broader regression and current-head CI remain separate promotion gates.
