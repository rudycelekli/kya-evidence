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
8. **Verification.** `verifyScoreCard` recomputes every aggregate from the embedded per-item results and the manifest, then compares the whole card byte for byte. Editing any number derived from the items, an outcome, an item flag, the seed or resample count, the floor or a non-claim fails, including after a re-seal of both digests. A manifest field that no computation reads (subject, suite, evaluator digest, judge, the value of a present holdout commitment, runtime string, offline flag) is an operator statement: a re-sealed edit of it is indistinguishable from a card honestly built with that manifest, so verification accepts it. Only a signature would bind those fields; signing is deferred (see Alternatives). Verification shows the card is internally consistent with the items it embeds. It does not show those items were produced by the named subject.
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

`src/kya-score/` (stats, card, index) and `scripts/kya-score.mjs` (`build`, `verify`). The module is outside `src/conformance/`, `src/suites/` and `src/research/`, so pinned evaluator and assessor digests are unchanged. It has no network or process imports; a test scans for them. The package export `./kya-score` and the typings in `src/kya-score/index.d.ts` (re-exported as types from `src/index.d.ts`) were added by fix lane 10, and `kya score build|verify` delegates to the script.

### Card layout and algorithms (normative detail, added by fix lane 10)

The first text of this ADR left the layout and several bytes of the computation to the code. A second verifier written from that text could not agree with the first (see `docs/fixlane10-integration.md`, disagreement log). The following is the complete rule set; where it and the code differ, that is a defect to fix with a test.

**Encoding.** Digest means SHA-256, lowercase hexadecimal, of the canonical JSON text: no whitespace, object members in ascending UTF-16 code unit order, strings JSON escaped, numbers in ECMAScript `Number::toString` form (so `0.1`, `1e-7`, `57.735027`, integers without a point). Cards never contain duplicate members, `NaN` or infinities.

**Top level.** Exactly these members: `schema` (`kya.score-card/v1`), `label` (`KYA-SCR-EXPERIMENTAL`), `manifest`, `floor`, `runs`, `runDigest` (digest of `runs`), `results`, `nonClaims`, `cardDigest` (digest of the object holding every other member).

**Manifest.** Exactly `subject` and `suite` (each exactly `id`, `version`, `digest`), `evaluatorDigest`, `judge` (`null` or exactly `id` and `digest`), `holdoutCommitment` (`null` or 64 hex), `environment` (exactly `runtime`, a string of 1 to 128 UTF-16 units, and `offlineDeclared`, a boolean), `bootstrap` (exactly `seed`, a string of 1 to 128 UTF-16 units, and `resamples`, an integer from 100 to 20000). Identifiers match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`. Digests are 64 lowercase hex characters.

**Floor.** Exactly `minItems`, `minRepeats`, `minHeldOutItems`, integers not below 30, 3 and 10.

**Runs.** One to 32 runs with distinct run identifiers (identifier pattern above). Each run has one to 2000 items, each exactly `id`, `outcome` (`pass`, `fail`, `abstain`, `error`), `heldOut` (boolean), `durationMs` (finite, 0 to 1e9), `costUsd` (`null`, or finite 0 to 1e6) and `canaryExposed` (boolean; a builder input may omit it, meaning false, but a card always carries it). Items inside a run are sorted ascending by `id` in UTF-16 code unit order, ids are distinct inside a run, and every run has the same ids and the same `heldOut` flag per id.

**Floor refusal.** With `n` items, `R` runs and `h` held-out items, the card is refused when `n < minItems`, `R < minRepeats`, `h < minHeldOutItems`, or `holdoutCommitment` is `null`.

**Generator.** `seededRandom(seed)` hashes the bytes `kya.score.seed/v1`, a line feed, then the UTF-8 seed, with SHA-256. Words `a`, `b`, `c`, `d` are the first four big-endian 32-bit words. One step, all arithmetic modulo 2^32: `t = a + b`; `a = b xor (b >> 9)`; `b = c + (c << 3)`; `c = rotl(c, 21)`; `d = d + 1`; `t = t + d`; `c = c + t`; output `t`. This is sfc32 with `d` incremented before it is added to `t`, which differs from the published sfc32; the order is part of this profile. Twelve outputs are discarded. `next(bound)` sets `limit = floor(2^32 / bound) * bound`, draws outputs until one is below `limit`, and returns it modulo `bound`.

**Aggregates.** For items `i` let `p_i` be the number of runs in which the item passed. For a set of `m` items and `R` runs the aggregate has `items = m`, `repeats = R`, `score = floor(1000 * sum(p_i) / (m * R))`, `resamples = B`, and `ci95`. The bootstrap seed string is the manifest seed, a vertical bar, and the label `all`, `heldout` or `public`. It runs `B` resamples; each draws `m` times `next(m)` and sums the chosen `p_i`. The sums are sorted ascending; with `k = floor(B * 25 / 1000)` the low sum is entry `k` and the high sum is entry `B - 1 - k`, and `ci95.low` and `ci95.high` apply the score formula to those sums. `results.headline` uses all items, `results.heldOut` the held-out items, `results.public` the others, or `null` when there are none, in which case `publicMinusHeldOut` is `null`; otherwise it is `public.score - heldOut.score`.

**Other results.** `outcomes` counts each outcome over all runs and items plus `denominator = n * R`. `repeatVariance`: `perRunScores` is `floor(1000 * passes / n)` per run in run order; `mean` is their arithmetic mean; `sd` the sample standard deviation (divisor `R - 1`); `min`, `max`; `unstableItemShare` is the count of items whose outcome is not identical across runs divided by `n`. `mean`, `sd` and `unstableItemShare` are rounded to 6 decimals as `Math.round(x * 1e6) / 1e6` (halves toward positive infinity). `cost`: `items = n * R`; `knownItems` counts non-null costs; `totalUsd` is `null` unless all are known, else the sum of `Math.round(costUsd * 1e6)` over all items divided by `1e6`. `runtime`: the durations are summed in binary64 in run order then item order; `totalDurationMs` is that sum rounded to 3 decimals the same way; `meanPerRunDurationMs` is the sum divided by `R`, rounded to 3 decimals; `maxItemDurationMs` is the largest duration. `integrity.canaryExposures` counts items with `canaryExposed` true over all runs.

**Verifier output.** The verifier rebuilds the card from `manifest`, `runs` and the recorded `floor` (a floor member below the hard minimum, or not exactly the three members, is a problem and the hard minimum is used for the rebuild), and the card is valid when it has no problems: digests match, the floor holds, the rebuild is not refused, and the canonical text of the rebuilt card equals that of the given card. Only `valid`, and for a valid card `score` and `cardDigest`, are normative. Problem codes are informative.

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

`test/kya-score.test.mjs` (fix lane 8): seeded generator determinism; bootstrap determinism, bracketing, width against sample size and input rejection; Wilson values matching ADR-0019; card headline, fixed denominator, repeat variance, held-out split, cost and runtime, byte-identical rebuild; each refusal reason, all reasons at once, floor cannot be lowered; population, duplicate and malformed-manifest rejection; canary counting; verification of an untouched card and rejection of re-sealed edits to score, outcome, manifest, non-claims, floor and evidence volume; comparison lineage; no network imports; CLI build, verify, tamper and refusal exit codes; this ADR and the requirement proposal note stay consistent with the tests. Fix lane 10 adds `test/kya-score-wiring.test.mjs` (CLI delegation, export map, typings) and `test/kya-score-second-verifier.test.mjs` (the vector set in `interop/score-verifier/vectors.json` run through both the JavaScript verifier and `interop/score-verifier/verify_score_card.py`). Not verified: that the Python verifier is independent review (same team, same session family, and the layout section above was written after seeing the first disagreements), any real subject, any lab, any independent reader, any statistical review of the bootstrap choice, cross-platform float agreement beyond Node on the author machine.
