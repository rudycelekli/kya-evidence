# ADR-0031: Machine-readable claim-boundary codes

**Status**: Proposed
**Date**: 2026-10-15
**Depends-on**: ADR-0016, ADR-0027, ADR-0028

Review boundary: written and tested by the authoring lane only. No maintainer review, no outside reader, no adoption.

## Context

Artifacts state their limits as free English text. A relying party or tool cannot tell which limits an artifact carries without matching strings, and a new limit sentence can ship with no one noticing it is new. The work-stream plan (WS1-02) asks for machine-readable claim-boundary codes.

## Decision

1. `evidence/claim-boundaries.json` is a registry of stable upper-snake-case codes, each with a meaning, artifact kinds and the exact English strings it covers.
2. `src/claim-boundaries/index.mjs` exposes the codes, `codesForLimitStrings` (throws on an unknown string) and `describe`. It lives outside `src/conformance/`, so the evaluator identity is unchanged.
3. Codes are append-only. `committedCodes` in the registry is the baseline; removal or rename fails a test.
4. A code states what an artifact does not show. It is a classification of existing text. No assessment, currency result, report digest or record format changes.
5. Codes are not added to bridge exports now. A new export member changes serialized bytes and is compared by `verifyBridgeExport`; carrying codes needs a separate, versioned decision.

## Alternatives

Replace the strings with codes: rejected, it changes every digest and all assessment vectors. Add a `limitCodes` member to reports and exports: rejected for now, same byte and verifier impact. Derive codes by pattern matching: rejected, a new sentence could be mis-coded silently; an exact registry throws instead.

## Consequences

New limit text cannot ship in a scanned module without a code. The scan covers a fixed list of emitting modules, so a limit written elsewhere is not caught. The registry text is English; a reworded string needs a registry update, which is intended friction. Codes say nothing about whether a limit is adequate or complete.

## Validation

`test/claim-boundaries.test.mjs` checks that every emitted limit string is covered, no registry string is stale, codes are unique, upper snake case and append-only, and that the real outputs of `assess` and `checkCurrency` map to codes. Unchanged report digests and assessment vectors are checked by the existing tests.
