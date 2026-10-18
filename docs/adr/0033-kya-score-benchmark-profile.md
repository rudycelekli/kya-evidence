# ADR-0033: KYA Score benchmark profile (`kya.score-card/v1`, experimental)

**Status**: Proposed
**Date**: 2026-10-18
**Depends-on**: ADR-0003, ADR-0010, ADR-0018, ADR-0019, ADR-0023, ADR-0032

Review boundary: written and tested by one project lane. No statistician review, no outside lab reader, no external adoption. Nothing here is evidence that the number predicts anything.

## Context

The owner wants a KYA result that a model lab or a harness builder could run the way they run a benchmark. Adoption and validity cannot be produced by engineering; the engineering part can be made to meet what a careful reviewer would ask first. The existing pieces cover signed evidence, a fixed denominator, frozen offline controls (ADR-0010), commit-reveal holdouts (ADR-0023) and a bounded command transport. A reviewer checklist found these gaps: no uncertainty on any aggregate, no variance across repeated runs, no seed for any resampling, no minimum amount of evidence before a number may be shown, no single card that binds the number to what was run, and no fixed list of what the number does not mean. The full checklist with file and line evidence is in `docs/fixlane8-integration.md`.

## Decision

Add a deterministic, offline score card beside the existing assessment. It does not change the 18-check evaluator, the suite evaluator or any scoring formula.

1. **Headline.** One integer from 0 to 1000: `floor(1000 * P / (n * R))`, where `n` is the fixed item count, `R` the number of repeated runs and `P` the passes over all items and runs. `abstain`, `error` and `fail` all count as non-pass in the denominator, the same rule as docs/SCORING.md. The card is labelled `KYA-SCR-EXPERIMENTAL`.
2. **Interval.** A seeded percentile bootstrap over items (2.5 and 97.5 percent order statistics, between 100 and 20000 resamples, default recommendation 2000). The seed and resample count are in the manifest. The generator is sfc32 keyed by SHA-256 of the seed string, with rejection sampling for unbiased indexes, so any implementation can reproduce it. The interval covers item sampling only.
3. **Repeat variance.** Per-run scores, their mean and sample standard deviation, minimum, maximum, and the share of items whose outcome changed between repeats.
4. **Held-out split.** Items carry a `heldOut` flag. The card reports a held-out aggregate, a public aggregate and their difference as a descriptive contamination signal. It does not test contamination. The manifest carries the ADR-0023 holdout commitment digest; the card checks only its shape. It does not verify the reveal.
5. **Run manifest.** Subject id, version and digest; suite id, version and digest; evaluator digest; judge identity and digest or `null` for none; holdout commitment; runtime string; an offline declaration; bootstrap seed and count. The subject is whatever harness or model the operator plugs in; the card records the identity the operator states.
6. **Cost and runtime.** Total and per-run duration, longest item, and total cost in USD. Cost is `null` unless every item carries a cost, and the count of items with a known cost is always shown.
7. **Evidence floor.** The card builder refuses, with code `EVIDENCE_FLOOR_NOT_MET` and named reasons, when there are fewer than 30 items, fewer than 3 repeats, fewer than 10 held-out items or no holdout commitment. A caller may raise the floor; the builder and the verifier both reject a floor below these minimums. Refusal writes nothing.
8. **Verification.** `verifyScoreCard` recomputes every aggregate from the embedded per-item results and the manifest, then compares the whole card byte for byte. Editing any number, outcome, manifest field, floor or non-claim fails, including after a re-seal of the digest. Verification shows the card is internally consistent with the items it embeds. It does not show those items were produced by the named subject.
9. **Comparison.** `compareScoreCards` returns `comparable: false` unless the suite digest and the evaluator digest match. For comparable cards it reports the score difference and whether the two intervals are disjoint. Changing the item set, a predicate or the evaluator starts a new comparison lineage (ADR-0010).
10. **Non-claims.** Every card carries the fixed ordered list below. A verifier rejects a card that drops, adds or reorders one.

| Code | The headline number does not establish |
| :--- | :--- |
| `NOT_PREDICTIVE_VALIDITY` | that a higher number goes with fewer real incidents |
| `NOT_CALIBRATED_TO_INCIDENTS` | that a score value maps to any incident rate |
| `NO_INTER_ASSESSOR_AGREEMENT` | that two independent assessors would produce the same number |
| `NOT_SAFETY_CERTIFICATION` | that the subject is safe, compliant or fit for any use |
| `NOT_ENDORSED_OR_ADOPTED` | any endorsement, standard status or use by any lab |
| `NOT_A_PRODUCT_RANKING` | a ranking of commercial products; cards compare only under one suite and evaluator |
| `INTERVAL_COVERS_ITEM_SAMPLING_ONLY` | uncertainty from judge error, item-set choice, environment or subject changes |
| `SUBJECT_IDENTITY_AS_DECLARED` | that the named subject produced the answers; identity is operator-stated |
| `OFFLINE_EXECUTION_NOT_VERIFIED` | that nothing left the machine during a run; the flag is a declaration |
| `ITEM_SET_MAY_BE_MEMORIZED` | that public items were unseen by the subject or its training data |

### Implementation

`src/kya-score/` (stats, card, index) and `scripts/kya-score.mjs` (`build`, `verify`). The module is outside `src/conformance/`, `src/suites/` and `src/research/`, so pinned evaluator and assessor digests are unchanged. It has no network or process imports; a test scans for them. The package export map and `src/index.d.ts` are not extended in this change.

### Reproducing a card

A lab needs: the suite file and its digest; the evaluator digest; the subject build identity; the per-item results from at least three repeats run offline; the manifest; this repository at the stated revision; Node 22 or newer. `node scripts/kya-score.mjs build --manifest M --runs R --out CARD` then `node scripts/kya-score.mjs verify CARD` recomputes the same bytes on any machine. Running the subject is outside this tool; the existing bounded command transport (`createCommandAdapter`) is one way to run a subject as a child process, and it states that OS isolation is the caller's responsibility.

### What is unmeasured today

- **predictive validity**: no data exists on whether any KYA score precedes real incidents. The design for that study is `docs/CALIBRATION-STUDY.md`; it has not been run, registered or reviewed.
- **inter-assessor agreement**: no two independent assessors have scored the same subject under this profile. Run-to-run variance of one operator is reported; agreement between operators is not.
- **calibration against real incidents**: no mapping from score to incident rate exists.
- **judge reliability**: items judged by a model or a human panel need the ADR-0019 calibration record; that record is Proposed and not implemented, so the card refuses nothing on judge quality.
- **contamination**: the held-out gap is descriptive. Leakage before reveal, an easy-case-picking holder and training-data overlap are not detected.
- **item versioning and retirement**: the suite digest freezes a version; there is no retirement list, no item-level lineage across versions and no rule for removing a compromised item without a new lineage.
- **subject authenticity and offline execution**: runs are operator-supplied. The capture cell (ADR-0032) is simulated and not a sandbox.
- **sample-size adequacy**: the floor of 30 items is a minimum for showing a number. It is not a power analysis; at that size the interval is wide.

## Alternatives

Folding the card into the assessment report would change the report digest and the pinned assessor source. A parametric interval was rejected: items are few and pass rates sit near the edges, where normal approximations misbehave; Wilson is available in `stats.mjs` for single-proportion use. Resampling runs instead of items was rejected: repeats of one subject are not an independent sample of the item population. Letting a caller lower the floor was rejected: a number published below the floor invites the comparison the floor exists to stop. Signing the card was deferred: a signature would add key custody and trust anchors that need the ADR-0021 role split first; the card is unsigned and states `SUBJECT_IDENTITY_AS_DECLARED`.

## Consequences

A lab reviewer gets one file with the number, its interval, its variance, what was run, what was refused and what the number does not mean, and can recompute it offline. The number is still a self-run, unsigned, unvalidated statistic. Publishing it as a ranking, a certification or a safety statement would contradict the non-claims it carries. The profile stays Proposed until the unmeasured list above has a result for at least predictive validity and inter-assessor agreement. Open follow-ups: signed cards under an assessor role, ADR-0019 judge calibration, item retirement lineage, a typed SDK export.

## Validation

`test/kya-score.test.mjs` (fix lane 8): seeded generator determinism; bootstrap determinism, bracketing, width against sample size and input rejection; Wilson values matching ADR-0019; card headline, fixed denominator, repeat variance, held-out split, cost and runtime, byte-identical rebuild; each refusal reason, all reasons at once, floor cannot be lowered; population, duplicate and malformed-manifest rejection; canary counting; verification of an untouched card and rejection of re-sealed edits to score, outcome, manifest, non-claims, floor and evidence volume; comparison lineage; no network imports; CLI build, verify, tamper and refusal exit codes; this ADR and the requirement proposal note stay consistent with the tests. Not verified: any real subject, any lab, any independent reader, any statistical review of the bootstrap choice, cross-platform float agreement beyond Node on the author machine.
