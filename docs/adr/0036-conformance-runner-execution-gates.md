# ADR-0036: Separate conformance refusals from execution failures

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0034, ADR-0035

## Context

A portable conformance result depends on both the protocol implementation and the runner interpreting it. The previous runner treated `code !== 0 || signal` as a correct refusal. Node represents a signal exit with a null code, so SIGKILL could earn `pass` on an invalid-input vector. The ordinary-result path also accepted an unsupported reply with a missing or different operation or extra fields. This hid malformed replies as `not-run`. Finally, NaN or zero worker budgets and overflowing timer budgets were not validated before execution.

## Decision

Keep implementation semantics, vector inputs and expected outputs frozen. Change the runner's admission boundary:

1. Spawn failure, timeout, output overflow and signal termination fail every vector. A correct refusal requires a normal integer non-zero exit. Semantic mode preserves that distinction.
2. Share one unsupported-reply predicate across refusal and result vectors. Require exactly three members: `schema: kya.impl-result/v1`, the requested `operation`, and `unsupported: true`. Retain the original version 1 refusal rule: exit 0 is a failure even with an exact unsupported reply.
3. Before reading vectors or launching processes, require integer worker count 1–16 and integer timeout 1–2147483647 milliseconds. CLI errors exit 2 without a report. Values above 16 workers previously clamped; callers must now choose a supported budget explicitly.
4. Add five frozen adversarial tests and a separate four-control mutation runner. Each mutant runs the identical complete test population in an isolated temporary copy, must parse, and must fail an assertion. CI is configured to run the controls on both configured Node versions and operating systems.

## Alternatives

- Treat every non-zero or signal exit as refusal: rejected because a killed process provides no protocol refusal result.
- Introduce a new structured refusal envelope: deferred because it would change the language-neutral contract and existing implementers. It could distinguish declared refusals more precisely, though an issuer could still lie.
- Trust partial unsupported replies: rejected because an incorrect operation or extra decision fields can conceal broken adapters.
- Change vector expectations to accommodate crashes: rejected; the evaluator must preserve the frozen contract.

## Consequences

No assessment schema, suite, evaluator identity, signing input or golden-vector expectation changes. Reports made by the previous runner may overstate refusal coverage and should be rerun when used for a conformance claim. An ordinary non-zero exit can still be an uncaught exception rather than an intentional refusal. This change does not establish implementation completeness, external adoption, runtime safety or independent review. The new mutation controls are additional to the existing 87 assessment and related gate controls.

## Validation

`test/vector-runner-gates.test.mjs` exercises signals, normal refusal, semantic mode, malformed and exact unsupported replies, and library/CLI budget validation. `scripts/vector-runner-mutations.mjs` runs the same five tests on the candidate and four syntactically valid weakened runners, checking test population, skips and cancellations. Its optional `--previous FILE` runs those same frozen tests against a saved previous runner and records failures without altering expectations. Local evidence records the exact prior revision, source digests, Node version and outcomes; full-suite and source checks are reported separately. No hosted CI result is inferred from the workflow edit.
