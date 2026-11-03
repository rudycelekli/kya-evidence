# ADR-0042: Bind report-only currency invariants to the report decision

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0013, ADR-0027, ADR-0041

## Context

Without currency recheck inputs, bridge verification uses the export's currency block and validates its internal shape. Two contradictions could nevertheless pass: a checked `reliable` value different from `current && report.decision === 'qualified'`, or a nonqualified report without its required `allowNonQualified` override. These are locally decidable inconsistencies with the supplied report and exporter rules. Detecting them does not establish that a currency result is true.

## Decision

After the existing report-only currency-block validation, require checked reliability to equal the conjunction of its current result and a qualified report decision. Require every nonqualified report to retain the `allowNonQualified` override, whether currency is checked or unchecked. Return the existing `MALFORMED` error for either contradiction. All six bridge kinds use this shared path; formats without an explicit reliability member derive it as before.

Keep the currency-rechecked path unchanged. Do not reject an otherwise coherent block merely because it carries an extra `allowNotCurrent` override. Report-only checks still cannot determine whether supplied currency inputs, trigger codes or the currency digest reflect a real check.

## Alternatives

- Accept every shape-valid currency block: rejected; the report already makes these contradictions decidable.
- Require currency rechecking for every verification: deferred; report-only comparison is a documented interface with an explicit claim ceiling.
- Reject every superfluous override: deferred; it would tighten compatibility beyond the two proven contradictions and reject the existing coherent-forgery example used to demonstrate report-only limitations.

## Consequences

Legitimate nonqualified checked and unchecked exports continue to verify. Contradictory explicit reliability or a concealed nonqualified override becomes malformed. This is an intentional admission correction, with no output schema or assessment/evaluator changes. A coherent but false currency block can still pass without rechecking. The report checksum remains unauthenticated; no identity, authorization, truthful execution, independent assessment or outside interoperability acceptance is established.

## Validation

Three frozen tests compare the previous implementation and candidate on identical inputs. They cover legitimate nonqualified exports across all six kinds in checked and unchecked modes, contradictory reliability in in-toto and OpenTelemetry exports, and missing nonqualified overrides across all six kinds in both modes. The previous verifier passes one test and fails two; the candidate must pass all three. Two syntax-valid mutants remove each new gate separately and must fail the same test population. The gate checker requires all three tests to complete with no skips, cancellations or TODOs. Existing bridge, snapshot and other impacted regression tests run separately. Tests and review are same-team evidence; independent assessment remains open.
