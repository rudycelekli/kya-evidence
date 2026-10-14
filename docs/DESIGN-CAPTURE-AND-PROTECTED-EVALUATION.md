# Design overview: capture and protected evaluation

Status: proposed design for roadmap stages 3 (stronger capture) and 4 (protected evaluation). Nothing here is implemented; each ADR is `Proposed`.

| ADR | Closes | Roadmap |
| :--- | :--- | :--- |
| [0017](adr/0017-measured-signed-capture-attestation.md) measured signed capture | Agent-shaped observation; omitted runs; unobserved effects | Stage 3 |
| [0020](adr/0020-external-anchoring-of-evidence-bundles.md) external anchoring | Backdating and silent history rewrite; plan commitment | Stage 3 (external witnesses) |
| [0019](adr/0019-judge-reliability-floor.md) judge reliability floor | Unmeasured LLM/human graders | Stage 4 (evaluator validation, uncertainty) |
| [0018](adr/0018-evaluation-awareness-paired-runs.md) paired runs | Behaviour that differs when the agent thinks it is tested | Stage 4 (reproducibility, uncertainty) |

## How they fit

The capture harness (0017) records a signed plan before each campaign and signs measured facts per run. Anchoring (0020) commits the plan head, capture digests and bundle digests to an external append-only record, so omission and backdating become detectable. Judged checks (0019) and paired-run checks (0018) produce ordinary frozen-denominator checks (ADR-0003); their failure modes are `unknown`, never a silent pass. A relying policy opts in by requiring capture, anchoring, calibrated judges or the awareness family; absent evidence, the matching checks are unknown.

New policy anchor roles: `capture-issuer`, `calibrator`, `anchor-operator`; each distinct from the evaluator and from the `self`/`independent` role. Still unproven by any of them: truthful execution on a compromised capture host, label correctness, uniform sandbagging, content truth, completeness beyond what was planned and anchored, organizational independence.

## Implementation order (test-first)

1. 0019 statistic and refusal path: pure functions, no I/O, smallest blast radius, immediately usable.
2. 0017 schema, signing, binding and planned-ledger reconciliation with a fake harness; then policy `requireCapture`.
3. 0020 Merkle and chain verification with in-process fakes; then RFC 3161 and log-proof parsers; policy `requireAnchor`.
4. 0018 pair spec, bootstrap with committed seed, and `awareness` family; depends on 0017 for run capture and benefits from 0020 for the plan.
5. Only then: real harness integrations and an authorized real-backend anchoring trial, outside CI.

## Test strategy

Each step: failing-first unit tests; adversarial regressions per ADR Threats table; mutation controls that weaken each new gate (must be detected by `scripts/mutation-check.mjs` additions); frozen baseline and candidate comparison on identical cases; golden vectors for new canonical records so the Python byte checker (ADR-0008) can cover them later; zero runtime dependencies and no network in CI; privacy assertions that public records carry digests only. Independent review is required before any status moves beyond `Proposed`; ADR statuses follow implementation evidence.
