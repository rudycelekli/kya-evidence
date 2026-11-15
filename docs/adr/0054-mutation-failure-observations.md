# ADR-0054: Preserve mutation admission failure observations

**Status**: Implemented locally; same-team review pending
**Date**: 2026-11-06
**Related**: ADR-0036, ADR-0051, ADR-0053

## Context

The Node24/macOS PR61 job rejected a pristine mutation baseline after completedRun accepted its terminal TAP aggregate. Exact stack/source inspection therefore supports a completed baseline with failed assertions, not a timeout or signal. The specific control and assertions cannot be recovered: the runner passed its process result directly to admission, then removed the temporary tree in finally. One matrix job succeeded, two were cancelled and one failed. Neither elapsed time nor this evidence identifies a canonical-array root cause or establishes flakiness.

## Decision

Wrap the unchanged baseline and candidate admission functions with failure-only observation. Retain phase, control, parent source/evaluator, runner/grader, package and test-tree digest references, target source binding, baseline counts, status, signal, execution error and admission error. Emit the structured record to the existing stderr test log before the existing cleanup. Bound each captured output preview to at most1MiB, mark truncation, record captured UTF-8 length and hash the full captured decoded text. A failed diagnostic sink must not replace or suppress the original admission failure. Clean admissions emit nothing.

All87 mutation controls, per-control pristine baselines, candidate population checks, skip/TODO refusal and execution budgets remain unchanged. No cached baseline, relaxed acceptance or automatic retry is introduced. Parent checkout hashes are references, not independent attestations of the child runtime. The original captured CI log remains preserved; this change makes future failures attributable, and does not retrospectively recover its missing output.

## Alternatives

Retrying unchanged CI would not recover the original evidence. Printing only the generic grader error omits the failed control and child assertions. Relaxing baseline admission or reusing a prior baseline could manufacture mutation credit. A new artifact upload channel is unnecessary: existing CI logs retain emitted synthetic test diagnostics.

## Consequences

Future rejected runs retain bounded diagnostic text before cleanup. Hashes bind UTF-8 re-encoding of captured decoded strings, not original pipe bytes; buffer truncation or decode loss cannot be reversed. Diagnostics are for these owned synthetic tests and must not be treated as production logging or truthful execution evidence. The CI log transport can impose additional limits; a missing or truncated record remains missing evidence. Original CI failure cause remains unknown until a substantiated observation identifies it. Successful observer tests do not clear the CI gate or establish independent outside review.

## Validation

Six deterministic synthetic process/TAP cases and their test bytes were frozen before implementation. A compatibility adapter over the previous grader decisions without diagnostic emission passes1/6; the candidate passes6/6. An actual weakened collector replacing only captured stdout with empty text passes3/6 and is detected. Nine existing grader cases and its existing mutation-control wrapper also pass (16total tests with the new six). Two real owned Node test subprocesses then produced baseline assertion failure and candidate population mismatch; both were refused and emitted their exact captured-text observations. These subprocess inputs were separately frozen before that integration execution. The87-control preflight confirms unchanged population and valid anchors; no full87-control replay or resolution of the original failing CI assertion is claimed.
