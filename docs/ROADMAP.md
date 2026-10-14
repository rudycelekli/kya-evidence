# From useful implementation to credible open standard

The ambition is neutral infrastructure for portable passports, independently assessed evidence, explicit relying-party policy and contestable agent assurance. The alpha demonstrates a rigorous local core. Becoming a standard needs multiple implementations and real evidence of use, not a declaration by its author.

| Stage | Deliverable | Evidence required for promotion |
| :--- | :--- | :--- |
| 0 · Reference core | Strict records, signed receipts, fixed denominator, CLI, offline viewer | Adversarial and mutation tests, reproducible package, explicit fixture labels |
| 1 · Independent challenge | External security/evaluator review and sanitized failure corpus | Reproduced defects, repaired gates, no unresolved critical bypass |
| 2 · Authorized runtime lanes | Claude Code, Codex and other explicitly configured transports | Official invocation verification, isolated execution, raw observation capture and bounded cost |
| 3 · Stronger capture | Tool side-effects, exact environment fingerprints, run completeness lineage | Instrumentation threat model, privacy tests, replay and external witnesses |
| 4 · Protected evaluation | Independent operators and protected holdouts | Evaluator validation, contamination controls, reproducibility, uncertainty |
| 5 · Multi-implementation protocol | Versioned conformance vectors and independent compatible implementations | At least two independent implementations passing shared vectors and disagreement resolution |
| 6 · Portable ecosystem | Credential/discovery bridges, relying-policy exchange, issuer accountability | Tested mappings, source-class preservation, correction/revocation/appeal interoperability |
| 7 · Empirical assurance | Use-case-specific weights and thresholds | Prospective outcome validation, failure-severity calibration and fairness scrutiny |

Alpha3 adds response-bound [diagnostic dossiers](DOSSIERS.md), [16 frozen public evaluator controls](BENCHMARKS.md) and exact full-scope comparison. The [source-grounded blueprint](research/2026-10-14-evaluation-blueprint.md) explains inherited mechanisms and remaining capture/calibration gaps. Local project-lane review is distinct from the external challenge required at stage 1. The Python byte checker is a team-built second implementation of a restricted byte/signature subset, distinct from independently governed full protocol implementations at stage 5.

## Bounded continuous cycle

Define a hypothesis. Freeze baseline, evaluator and cases. Create an isolated candidate. Compare identical cases, quality, latency and total cost. Independently review. Record `ACCEPT`, `REJECT` or `INCONCLUSIVE`. Retain rollback. Human publication authority remains intact. Research failure is evidence; it should not be hidden behind improved demo numbers.

Online agents can join through adapters after authorization. Executable availability is not evaluation. Runs must identify actual harness/model/configuration, retain scope and tool observations, exclude production accounts/secrets and keep fixture versus runtime status explicit. The dashboard never scores commercial products.

A real registered scheduler is required for ongoing automatic work, with bounded tasks and quiet unchanged-state behavior. This roadmap does not start or imply a scheduler. Approval or registration failures must be reported honestly.

## Unresolved research

Can independent issuers establish independence without central gatekeeping? How can signed run records prove completeness? How should offline revocation stay fresh? Can protected holdouts remain independently auditable without leaking cases? What real-world outcomes support predictive claims? How should appeals correct harm without exposing private traces? These questions remain open; cryptographic signatures do not solve them.
