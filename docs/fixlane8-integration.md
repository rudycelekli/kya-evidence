# Fix lane 8: KYA Score benchmark rigor, integration note

Status: proposal for the integrator. `evidence/requirements.json` is not edited by this lane. The proposals below are for a later merge that owns that file. All tests live in `test/kya-score.test.mjs`. See [ADR-0033](adr/0033-kya-score-benchmark-profile.md) (Proposed).

## Gap analysis against a lab reviewer checklist

Present means the repository already does it. Partial means a piece exists but a reviewer would object. Missing means nothing exists. The last column says what this lane added.

| # | Checklist item | State before | Evidence (file:line) | Added by this lane |
| :-- | :--- | :--- | :--- | :--- |
| 1 | Determinism and seeds | Partial | Catalog, expectations and replay are deterministic (`docs/BENCHMARKS.md:45`); fixture keys are fresh per run (`src/benchmarks/application/runner.mjs:125`); run IDs are random (`src/conformance/application/runner.mjs:20`); a `seed` field exists only in campaign planning (`src/campaign/domain/ledger.mjs:67`); no resampling seed anywhere | Seeded sfc32 generator and seed in the manifest (`src/kya-score/stats.mjs`) |
| 2 | Run manifest (what ran, versions, digests, subject, judge) | Partial | Run binds catalog, evaluator and assessor digests (`runner.mjs:137`); fixture subject only; no judge identity, no subject build identity for an external harness, no runtime or seed record | Manifest with subject, suite, evaluator, judge, holdout commitment, runtime, seed (`card.mjs`) |
| 3 | Uncertainty on every aggregate | Missing | Scores are point values (`docs/SCORING.md` formula); Wilson appears only in a not-yet-run study design (`docs/CALIBRATION-STUDY.md:29`) and Proposed ADR-0019 | Item bootstrap 95 percent interval on headline, held-out and public aggregates; Wilson helper |
| 4 | Variance across repeats | Missing | One run per case; no repeat structure in `runOfflineBenchmarks` | Per-run scores, mean, sample sd, range, unstable item share |
| 5 | Contamination and held-out controls | Partial | Commit-reveal holdout (`src/holdout/index.mjs`, `docs/SCENARIO-SUITES.md:57` limits); `docs/BENCHMARKS.md:43` says public controls can be memorized; nothing links a score to a holdout | Held-out flag, separate aggregate, descriptive public minus held-out gap, floor needs a commitment digest. Leakage is not detected |
| 6 | Item versioning and retirement | Partial | Suite and catalog digests freeze a version; changing cases starts a new lineage (`docs/BENCHMARKS.md:49`); no retirement list or item lineage | Comparison refuses different suite or evaluator digests. Retirement is not built; listed as unmeasured |
| 7 | Anti-gaming (canaries, leak checks) | Present for suites, absent for scores | Canary echo fails a scenario (`src/suites/evaluator.mjs:46`); capture cell scans transformed leaks (`src/capture-cell/canary.mjs`); a score card did not surface them | Canary exposure count on the card from item flags. Detection stays in the evaluator |
| 8 | Subject-agnostic offline runner contract | Partial | `createCommandAdapter` runs any JSON-over-stdio child with a bounded environment (`src/conformance/infrastructure/command.mjs:35`) and says OS isolation is the caller's job (`command.mjs:13`); no egress control, no way to feed a repeat-run set into a card | Card input is plain per-item results, so any harness can supply them; offline is a declaration and carries a non-claim code. No sandbox built |
| 9 | Cost and runtime reporting | Partial | Case duration measured and cost always `null` in the benchmark (`runner.mjs:134`); conformance run has a `costs` block (`src/conformance/application/runner.mjs:29`) | Total and per-run duration, longest item, cost total only when every item is known |
| 10 | Score card schema and verification | Missing | `verifyBenchmarkRun` verifies a fixture run (`runner.mjs`), not a score card | `kya.score-card/v1`, `verifyScoreCard` full recomputation, `scripts/kya-score.mjs verify` |
| 11 | Refusal below a minimum evidence floor | Partial | Policy `minCoverage` and `NO_SCORED_OBSERVATIONS` refuse on coverage (`src/assessment/application/assess.mjs:127`, `:135`); no floor on item count, repeats or held-out volume | `EVIDENCE_FLOOR`, named refusal codes, floor that cannot be lowered, verifier re-check |
| 12 | One headline number with its non-claims | Partial | Wording boundaries exist as report limitations and claim-boundary codes; no single headline paired with a fixed non-claim list | Headline plus ten ordered non-claim codes, rejected if altered |

Not addressed here and still missing: signed cards, judge calibration enforcement (ADR-0019), item retirement lineage, network egress control, any measurement of predictive validity, inter-assessor agreement or calibration against incidents.

## Requirement proposals

Requirement text describes the reference implementation, not an adopted standard. IDs are suggestions; the integrator owns `evidence/requirements.json`. Spec headings below exist in `docs/SPECIFICATION.md`.

### KYA-SCORE-001 (MUST, integrity)

- spec: `## Reports and viewers`
- statement: A score card MUST be rebuilt byte for byte from its embedded per-item results and manifest, and any edit to a number, outcome, manifest field, floor or non-claim MUST make verification fail even when the card digest is recomputed.
- test: `verify accepts an untouched card and returns the recomputed headline`
- test: `verify rejects an edited headline score even when the digest is recomputed`
- test: `verify rejects an edited item outcome when only the digest is recomputed`
- test: `verify rejects a stale digest after any edit`
- test: `verify rejects dropped or reordered non claims`
- test: `verify rejects unknown fields and wrong schema without throwing`

### KYA-SCORE-002 (MUST, determinism)

- spec: `## Records and bindings`
- statement: Interval computation MUST use only the manifest seed and resample count, and identical inputs MUST yield identical card bytes.
- test: `seeded random is deterministic and differs between seeds`
- test: `bootstrap interval is identical for identical seed and data and brackets the point estimate`
- test: `score card build is byte identical for identical inputs`

### KYA-SCORE-003 (MUST, uncertainty)

- spec: `## Reports and viewers`
- statement: Every aggregate on a card MUST carry a 95 percent interval, the interval MUST widen for a smaller sample, and invalid sample input MUST be rejected.
- test: `bootstrap interval is wider for a small sample than for a large one with the same mean`
- test: `bootstrap rejects empty data non finite values and unsafe resample counts`
- test: `wilson interval reproduces the published floor arithmetic of ADR-0019`
- test: `score card carries a headline with interval counts manifest and fixed non claims`

### KYA-SCORE-004 (MUST, denominator)

- spec: `## Run selection and qualification`
- statement: Abstain, error and fail MUST each count as non-pass in a fixed denominator on a score card.
- test: `fixed denominator counts abstain and error as non passes`
- test: `build rejects runs that disagree on the item population and duplicate item ids`

### KYA-SCORE-005 (MUST, evidence floor)

- spec: `## Trust and eligibility`
- statement: A score card MUST NOT be produced below the evidence floor, every unmet reason MUST be named, and a caller MUST NOT be able to lower the floor.
- test: `build refuses below the item floor and names the code`
- test: `build refuses below the repeat floor and names the code`
- test: `build refuses too few held out items and a missing holdout commitment`
- test: `build reports every unmet floor at once`
- test: `options can raise the floor but never lower it`
- test: `verify rejects a card whose recorded floor was lowered below the hard floor`
- test: `verify rejects a card built from too little evidence even with an honest floor field`

### KYA-SCORE-006 (SHOULD, variance and contamination signal)

- spec: `## Reports and viewers`
- statement: A score card SHOULD report variance across repeats, a held-out aggregate separate from the public aggregate, cost only when fully known, and a count of canary exposures.
- test: `repeat variance reports per run scores spread and the share of unstable items`
- test: `held out and public items are scored separately and the gap is descriptive`
- test: `cost and runtime are reported and cost stays null when any item cost is unknown`
- test: `canary exposures are counted from item flags and reported`

### KYA-SCORE-007 (MUST, comparison lineage)

- spec: `## Interoperability and versioning`
- statement: Two score cards MUST NOT be compared unless their suite digest and evaluator digest match.
- test: `compare refuses different suites and flags overlapping intervals as not distinguishable`
- test: `compare reports clearly separated scores as distinguishable`

### KYA-SCORE-008 (MUST NOT, offline and input hygiene)

- spec: `## Records and bindings`
- statement: The score card module MUST NOT import network or process facilities, and MUST reject malformed manifests.
- test: `the kya score source makes no network or process calls`
- test: `build rejects malformed manifests and unknown fields`
- test: `the kya score cli builds a card then verifies it and rejects a tampered copy`

### KYA-SCORE-009 (MUST, documentation boundary)

- spec: `## Governance documents`
- statement: The KYA Score ADR MUST stay Proposed, MUST list predictive validity, inter-assessor agreement and calibration against real incidents as unmeasured, and MUST describe every non-claim code.
- test: `ADR-0033 is Proposed and names what is unmeasured`
- test: `the fix lane 8 integration note names only requirement titles and spec headings that exist`

## Integration notes

- `src/kya-score/` is not exported from `package.json` or `src/index.d.ts`; add exports and typings in a separate change if wanted.
- `scripts/kya-score.mjs` is standalone, not wired into `bin/kya.mjs`, to leave CLI help text and delegation tests untouched.
- `src/kya-score/` has no sentence-like string literals outside error lines, so `evidence/claim-boundary-allowlist.json` and `evidence/claim-boundaries.json` need no entries. Non-claims are codes whose prose is in ADR-0033.
- `evidence/adr-index.json` is generated by `npm run adr:index`; regenerate it at merge so ADR-0033 appears.
