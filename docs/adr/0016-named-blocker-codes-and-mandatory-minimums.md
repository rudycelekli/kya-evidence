# ADR-0016: Named blocker codes and mandatory minimums

**Status**: Implemented
**Date**: 2026-10-14
**Depends-on**: ADR-0003, ADR-0011, ADR-0012, ADR-0013

Review boundary: separate project lane; no external certification.

## Context

`assess()` explained every withheld or capped result in free text. Relying software could only string-match prose, so rewording a sentence could silently change behavior. A policy also had no way to say that one check must pass whatever the average: only critical flags in the frozen profile could do that, and they are fixed by the profile author, not the relying party.

The project owner's private product Gradia states one governing rule, refuse rather than default: a number that would otherwise be printed and wrong is withheld and named with a machine-readable refusal code (its README lists examples such as a spec-freeze block, a missing budget, a refused vintage and a refused export), and each gate is mutation-verified. Only that design idea was read, from its public-facing README and ADR titles. No Gradia code, data, paths or logs are used; the code table, the minimums design and every line here are written fresh for KYA.

## Decision

1. Add `blockerCodes` to `kya.assessment/v1` reports: exactly one code per entry of `blockers`, same order, drawn from a frozen append-only set (`BLOCKER_CODES`, tabled in SCORING.md). Human text is unchanged. A code is never reused for a different meaning. `NO_OBSERVED_CHECKS` and `SUBJECT_NOT_YET_VALID` are added to the requested set because those two blockers existed and a one-code-per-blocker rule cannot leave them nameless.
2. `verifyAssessment` checks the field only when present: it must be an array of known codes of the same length as `blockers`. Reports without it verify exactly as before, because the digest still covers whatever body the report carries. The dossier validator, the viewer model and the TypeScript types accept both shapes; the viewer shows the code beside the text.
3. `checkCurrency` triggers keep `id` and gain a stable `code` (`CURRENCY_CODES`).
4. Add an optional policy field `mandatoryMinimums`: a non-empty list of `{checkId, minimum}`, unique check IDs, `minimum` either `pass` or `independent-pass`. Validation is strict (exact keys, identifier, level enum, duplicates, 1 to 256 entries); `assess` refuses any ID outside the frozen profile. An unmet minimum caps the decision at `blocked` and adds one `MANDATORY_MINIMUM_NOT_MET` blocker per unmet check, whatever the score. `revoked` and `expired` stay more specific.
5. A minimum is met only by an eligible, observed `pass` in the selected run, signed by an independent key for `independent-pass`. Declarations are already rejected before scoring, and a removed or missing observation is `unknown`, which fails the minimum, so the cap cannot be lifted by omitting evidence.

## Alternatives

A numeric per-check threshold would invent a graded measure: check outcomes are binary, so the meaningful threshold is the assurance level, not a score. Marking the check critical in the profile changes the frozen profile digest and is not the relying party's decision. Folding minimums into `minScore` is exactly the averaging the gates exist to prevent. Replacing `blockers` with objects would break every existing consumer and digest. Emitting codes only in a side channel would let them drift from the report they describe. Making a minimum return `insufficient-evidence` when the check is unknown would let a caller treat omission as a softer outcome than failure, so unknown, failed and unproven all cap at `blocked`.

## Consequences

New reports carry a different digest than the same inputs did before this change, because the body gains a field; old reports keep their digests and still verify, compare and render. A policy using `mandatoryMinimums` has a different digest from the same policy without it, so a relying party sees it as a policy change under `checkCurrency`. Older readers that use exact-key validation of reports (for example a strict external dossier validator) will reject the new field until updated; the Python secondary implementation does not assess and is unaffected. A mandatory minimum on a non-critical check can block a result that would otherwise qualify, which is its purpose. Codes name why a result was withheld; they do not prove the evaluation was truthful.

## Validation

`test/refusal-codes.test.mjs` covers each code, the one-code-per-blocker invariant, rejection of mismatched or unknown code lists, and backward compatibility against a frozen report produced by the previous release (`test/fixtures/legacy-assessment-b3b09bd.json`): digests and verification are unchanged, a regenerated report equals it in every field except the added list, old and new reports compare in either order, currency accepts both, the dossier validator accepts reports with and without codes and the viewer renders both. `test/mandatory-minimums.test.mjs` covers the absent field, passing, failing, missing, abstaining, declared-only and independent-threshold boundary cases, removal of evidence, strict validation, profile binding and currency interaction. Mutation controls remove the minimum gate, treat unknown as met, downgrade the independent threshold, let a minimum override revocation, skip profile binding, drop or mislabel codes, skip code validation, accept duplicates and drop trigger codes; every one must be detected.
