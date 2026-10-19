# From useful implementation to credible open standard

The ambition is neutral infrastructure for signed check receipts over an exact agent manifest (a declaration, not a passport or identity credential), independently assessed evidence, explicit relying-party policy and contestable agent assurance. The alpha demonstrates a rigorous local core. Becoming a standard needs multiple implementations and real evidence of use, not a declaration by its author.

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

Alpha.4 builds on alpha.3, which added response-bound [diagnostic dossiers](DOSSIERS.md), [16 frozen public evaluator controls](BENCHMARKS.md) and exact full-scope comparison. The [source-grounded blueprint](research/2026-10-14-evaluation-blueprint.md) explains inherited mechanisms and remaining capture/calibration gaps. Local project-lane review is distinct from the external challenge required at stage 1. The Python byte checker is a team-built second implementation of a restricted byte/signature subset, distinct from independently governed full protocol implementations at stage 5.

## Stage status at 2026-10-14

| Stage | Status | Basis |
| :--- | :--- | :--- |
| 0 · Reference core | Implemented for the alpha.4 scope | `npm test` passes with 0 skipped tests. Every requirement in the registry is traced to a test (see REQUIREMENTS.md). The mutation gates in `scripts/mutation-check.mjs` run in CI. Package reproducibility is checked in CI |
| 1 · Independent challenge | Open | No external review is recorded. The reviews named in ADR-0014 were project-lane reviews |
| 2 · Authorized runtime lanes | Partial, not promoted | Typed Claude Code and Codex parsers and adapter plans exist. The README states that Claude execution is blocked until managed policy can be established. No official invocation verification is recorded |
| 3 · Stronger capture | Open | No tool side-effect capture. Currency and incident records are offline checks over supplied data |
| 4 · Protected evaluation | Open | Public controls only |
| 5 · Multi-implementation protocol | Open | A nine-operation conformance contract with shared vectors exists (`interop/impl-contract/`). Two same-team implementations pass it: the JavaScript reference and `interop/second-impl/`. Neither is independent and no implementation outside the team exists. The team-built Python checker reconstructs vectors for a restricted subset, including incident-record vectors per [INTEROPERABILITY](INTEROPERABILITY.md); it is not an independent implementation either |
| 6 · Portable ecosystem | Open | W3C VC 2.0 export bridge implemented (`kya vc`, not validated by any external VC library). No correction, revocation or appeal interoperability |
| 7 · Empirical assurance | Open | No outcome validation or calibration |

## Done and next (2026-10-14)

Done, committed to the repository and tested locally. None of it has external review:

- Optional `principal.accountableParty` and policy `requirePrincipalBinding` (ADR-0012).
- `checkCurrency` and `kya currency` with named monitoring triggers (ADR-0013; incident-open added by ADR-0014).
- Signed `kya.incident/v1` report, resolution and appeal records with independent-only resolution and fail-closed duplicate handling (ADR-0014).
- Traced normative requirements registry with generated documentation (ADR-0011).
- Named mutation gates in `scripts/mutation-check.mjs`, run by CI.
- CI fails on any skipped or `todo` test.

Next, none started. Each needs an ADR and tests first:

- Verified principal binding through signed credentials from an accountable issuer.
- Signed or freshness-bounded revocation beyond the policy snapshot.
- A command that creates incident records. Today they are produced only through the library function `signIncident`.
- Surfacing `accountableParty` in the assessment report. Today it is visible only in the manifest and the subject digest.
- Re-deriving `scopeDigest` and decision/score consistency during currency checks on resealed reports.
- Appeal adjudication, and reopening a resolution when an appeal succeeds.
- External security and evaluator review (stage 1).
- A second independent implementation (stage 5).

Design proposals for stages 3 and 4 (measured signed capture, evaluation-awareness paired runs, a judge reliability floor, external anchoring) are in [DESIGN-CAPTURE-AND-PROTECTED-EVALUATION.md](DESIGN-CAPTURE-AND-PROTECTED-EVALUATION.md) and ADR-0017 to ADR-0020. They are proposed, not implemented.

## Bounded continuous cycle

Define a hypothesis. Freeze baseline, evaluator and cases. Create an isolated candidate. Compare identical cases, quality, latency and total cost. Independently review. Record `ACCEPT`, `REJECT` or `INCONCLUSIVE`. Retain rollback. Human publication authority remains intact. Research failure is evidence; it should not be hidden behind improved demo numbers.

Online agents can join through adapters after authorization. Executable availability is not evaluation. Runs must identify actual harness/model/configuration, retain scope and tool observations, exclude production accounts/secrets and keep fixture versus runtime status explicit. The dashboard never scores commercial products.

A real registered scheduler is required for ongoing automatic work, with bounded tasks and quiet unchanged-state behavior. This roadmap does not start or imply a scheduler. Approval or registration failures must be reported honestly.

## Unresolved research

Can independent issuers establish independence without central gatekeeping? How can signed run records prove completeness? How should offline revocation stay fresh? Can protected holdouts remain independently auditable without leaking cases? What real-world outcomes support predictive claims? How should appeals correct harm without exposing private traces? These questions remain open; cryptographic signatures do not solve them.
