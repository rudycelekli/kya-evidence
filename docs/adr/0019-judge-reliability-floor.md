# ADR-0019: Judge reliability floor

**Status**: Proposed
**Date**: 2026-10-14
**Depends-on**: ADR-0003, ADR-0010, ADR-0017

Review boundary: design only; nothing implemented, no independent review, no external certification.

## Context

Many checks cannot be graded by a deterministic predicate. An LLM or a human judge grades them, and a judge that is unreliable converts noise into pass/fail. The blueprint notes that injected judges and heuristic rankings do not establish calibrated assurance. Today nothing requires measuring a judge before its verdicts count.

## Decision

A judge may produce `pass` or `fail` for a check only if a current **calibration record** shows its agreement with a frozen labelled set has a Wilson 95% lower bound at or above the floor stated in the relying policy. Otherwise the check outcome is `unknown` with the named refusal `judge-below-floor` (or `judge-uncalibrated`, `judge-calibration-stale`, `judge-drift`). It is never a pass or fail, never removed from the denominator, and never replaced by an unvalidated judge.

### Calibration set

A frozen, digest-identified set of items, each with a reference label from human adjudication (at least two independent labellers, disagreements resolved by a third, labeller identities pseudonymous, adjudication rule recorded). The set is stratified to include both outcomes. It is disjoint from any case the judge or its prompt saw (prompt and examples digests recorded) and from items later graded in the evaluated run. Inputs are the exact judge inputs, so the prompt, rubric, model identifier, temperature and decoding settings, and tool access are all in the judge digest.

### Calibration record `kya.judge-calibration/v1`

Fields: `judgeDigest` (model/human-panel identity, prompt, rubric, settings), `setDigest`, `labelRuleDigest`, `n`, `agree` (count of items where judge label equals reference), per-class counts (`nPos`, `agreePos`, `nNeg`, `agreeNeg`), `runAt`, `calibrator` key, `assessmentUse` scope. Signed by a calibrator anchor (role distinct from evaluator and judge operator; policy-listed). The record is evidence of what a key signed, not proof the labels are right.

### Statistic

Overall agreement p-hat = agree / n. The Wilson lower bound at 95% (z = 1.96):

```
L = ( p + z^2/(2n) - (z/(2n)) * sqrt( 4n p (1-p) + z^2 ) ) / ( 1 + z^2/n )
```

Source: Wilson score interval, https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval (fetched 2026-10-14). The policy states `judgeFloor` (for example 0.85) and the judge qualifies only if L >= judgeFloor overall AND L >= `classFloor` computed separately on each class (so a judge cannot reach the floor by always answering the majority label). Chance correction is reported as a diagnostic (Cohen's kappa) but the gate is the Wilson bound, which is simple to reproduce.

Minimum sample size follows from the formula: with perfect agreement L = n/(n + z^2), so the smallest n reaching a floor is n >= z^2 * floor/(1 - floor). Floor 0.80 needs n >= 16, floor 0.90 needs n >= 35, floor 0.95 needs n >= 73 (computed from the formula above: n=16 gives 0.806, n=15 gives 0.796; n=35 gives 0.901, n=34 gives 0.899; n=73 gives 0.950, n=72 gives 0.949). Real judges do not agree perfectly, so practical sets are larger. The policy sets `minCalibrationN` and `minPerClass` (proposed defaults 60 and 20) and a record below them is `judge-uncalibrated` even if p-hat is high.

### Drift and re-calibration

Calibration is bound to the exact judge digest. Re-calibration is required, and the check is `unknown` until a new record exists, when: the judge digest changes (model, prompt, rubric, settings, human panel); the provider announces a model version change or the observed model identifier differs; the calibration age exceeds `maxCalibrationAgeSeconds`; a rolling audit sample of live verdicts (policy-set rate, labelled by humans after the fact) yields an agreement Wilson bound below the floor, or a two-proportion comparison against the calibration set indicates a shift; the calibration set is found leaked; or an incident record (ADR-0014) cites the judge.

### Composition with fixed denominators

A judged check keeps its weight, criticality and denominator slot. Unknown from a judge follows ADR-0003: zero points, no observed coverage; a critical judged check that is unknown withholds qualification. Judged outcomes are labelled `source: judge` with the calibration digest, so a policy may weight or restrict them. Judged checks are never silently averaged with deterministic ones. Several judges are not combined to lift the floor: a panel is a judge with its own digest and its own calibration.

## Alternatives

Trust any judge with a disclosure: unmeasured. Use a fixed accuracy threshold on point estimates: tiny samples can clear it by luck. Normal-approximation (Wald) intervals: unreliable near 0 or 1 and for small n, which is exactly the regime of perfect-agreement calibration. Clopper-Pearson: valid and conservative but heavier to explain; may be adopted later. Require inter-judge agreement instead of human reference: shared bias goes undetected. Ban judges: forfeits checks that matter.

## Consequences

Judged checks become less frequent but defensible, and a judge failure is a visible named refusal rather than a quietly noisy score. Cost is building and relabelling calibration sets. Claim ceiling: agreement with a reference on a frozen set, for the sampled input distribution. It does not prove the reference labels are correct, that the judge generalizes to other agents or tasks, that it resists manipulation by the graded output (judge injection), or that the labellers were independent in fact. Nothing is added about the quality of the graded agent. Ideas adapted from private Gradia developer documentation on evaluation judges and judge-agreement review (read-only): blinded inputs, separation of the judge from the graded run, and auditing of judge access; the floor, formula and refusal names here are written fresh.

## Validation

Test-first: Wilson implementation checked against published reference values and the closed form L = n/(n+z^2) at p = 1; boundary tests at n=15/16, 34/35, 72/73; p = 0 and p = 1 edge cases; majority-label judge fails the per-class floor despite high overall agreement; below-floor, uncalibrated, stale, mismatched judge digest and set-leak each yield `unknown` with the named refusal; unknown is never pass or fail and stays in the denominator; calibrator equals judge operator rejected; judge field change invalidates calibration. Mutation controls remove the per-class gate, the digest binding and the age check and must be detected. Frozen comparison of a good judge, a noisy judge and a constant judge on an identical labelled set.
