# ADR-0047: Capture the standing policy before evaluating disclosure records

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0006

## Context

Assessor standing captures signed disclosure data but read its policy through live JavaScript properties. A policy whose descriptors contained a revoked assessor could return an empty revocation list through GET and produce `standing: good`. An array GET view could similarly replace a revoked key. The assessor population also retained a caller-owned array, so a disclosure reflection trap could change the requested population after policy validation.

## Decision

Capture the complete standing policy with `JSON.parse(canonical(p))` before validating fields or processing disclosures. Consume only that private copy, including the assessor population, revocations, blocking relationships and cooling-off configuration. Keep defaults for omitted fields and existing JSON null behavior. As with other canonical JSON boundaries, unsupported values such as explicit undefined members, getters and extended arrays are refused rather than executed as policy data.

## Alternatives

- Continue using live properties after validation: rejected; validation and standing can observe different data.
- Copy only revocations: rejected; the population and other policy controls remain mutable.
- Freeze the caller's object: rejected; it mutates caller-owned configuration and does not consistently capture Proxy views.

## Consequences

Ordinary JSON policy results remain compatible. Caller GET views cannot hide recorded revocations, and disclosure capture cannot substitute a different assessor population. Reflection traps may execute during canonical capture; this is not a JavaScript sandbox. Standing remains a local check over supplied signed declarations, not accreditation, independent review or proof that a disclosure is true. Assessment decisions, schemas, evaluator identity and public vectors are unchanged.

## Validation

Four frozen tests use a published synthetic key seed and fixed disclosure bytes. They cover ordinary/default and revoked policies, top-level and array GET substitutions, one-time capture without GET reads, and disclosure-triggered mutation of the caller's assessor list. Previous source passes one and fails three; the candidate must pass all four. A syntax-valid mutation removes policy capture and must be detected by the unchanged tests. The control runner requires complete execution, zero skips/cancellations/TODOs, a passing candidate and actual test failures for the mutant. Existing assessor regressions run separately. Evidence is same-team, not outside independent assessment.
