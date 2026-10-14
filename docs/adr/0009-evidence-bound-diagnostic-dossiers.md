# ADR-0009: Bind diagnostic dossiers to replayed evidence and exact scope

**Status**: Implemented
**Date**: 2026-10-14
**Depends-on**: ADR-0002, ADR-0003, ADR-0005, ADR-0006

Review boundary: separate project lane; no external certification.

## Context

An aggregate score cannot explain failed predicates, unknown capabilities, measurement gaps or the difference between an asserted action and a captured side effect. A checksum-only report can be fabricated consistently. Supplied receipts cannot establish that omitted incidents never happened. Comparisons using only a scope name can compare different permissions under the same name. The inspected source studies supply useful reporting mechanisms but do not establish truthful execution, outcome calibration or external certification.

## Decision

Create a reporting bounded context that recomputes assessment from all six frozen inputs. Derive strengths only from passed selected checks with matching replayed original structured responses; receipt-only passes remain reported assertions. Label the evidence tier. Preserve blocking failures, nonblocking failures and evaluation errors separately. A failure predicate is not a causal diagnosis. Blind spots include missing checks and structural limits: capture completeness, actual effects, model identity, issuer independence, contamination, predictive calibration and billing.

Verify supplied observation originals against selected signed receipt digests and every binding before extracting bounded diagnostic codes and reported timings/cost. Duplicate originals are quarantined. Do not embed raw responses or private error prose in the dossier. Publish cost subtotal, complete reported total and measurement coverage separately; unknown totals remain null. Dossier verification recomputes from frozen inputs rather than trusting prose around a rehashed report. Standalone rendering checks consistency but remains unauthenticated.

Bind assessment scopeDigest to the entire manifest scope. Score comparison requires matching valid scope digests; legacy reports must be reassessed before comparison. Scope labels remain readable identifiers rather than full scope identity.

## Alternatives

Passing an imported report checksum directly to a narrative generator would launder fabricated results. Labeling unknown checks as weaknesses confuses measurement failure with agent failure. Calling a rule-based label a root cause overstates causal evidence. Treating a best-case unresolved score bound as a confidence interval invents calibration. Changing old records silently would destroy reproducibility.

## Consequences

Reports become more explanatory without granting new execution authority or assurance. Missing originals visibly limit diagnostic reach even if the relying policy qualifies supplied receipts. Public fixture checks remain fixture evidence. Old archived engines replay their original reports; new exact-scope comparisons are deliberately stricter. Cryptographic integrity and declared independence remain distinct from truth and external independence.

## Validation

Reproduce same-scope-name/different-permission comparison on the baseline and require candidate refusal on identical inputs. Test omitted failures, missing originals, forged report narratives, wrong original bindings, duplicate originals, private response redaction, unknown cost and error/abstain behavior. Negative controls weaken actual reporting/scope gates and must trigger substantive assertions. The independent lane reviews bindings, information leakage and report claims.

The frozen scope repair cases changed from zero of three passing at the alpha2 baseline to three of three at the alpha3 candidate. Separate source mutations detected six selected reporting/replay gate defects with an executed positive control. Seven frozen standalone consistency controls changed from one passing before repairs to seven passing after repairs; original failures remain preserved privately. CLI replay and rendering regression tests exercise the integrated implementation. This is separate project-lane review, with external security certification and capture authentication still open.
