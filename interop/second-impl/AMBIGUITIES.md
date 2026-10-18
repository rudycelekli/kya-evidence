# Places the sources were ambiguous or insufficient

Each entry: what was unspecified, how it was resolved (guess, or a vector), and the vector that decided or tests it. "Vector-resolved" means the specification, guide and contract did not determine the behaviour and a vector (input or expected value) was consulted. "Guess" means no vector pins it; another implementation could differ and still pass. "Unresolved" means the vectors fail on the digest for this reason.

## A. Byte-exact failures after round 2 (none)

After merging the round 2 `spec-gaps-2` texts (trigger detail strings, the four `limits` strings, the limitations list with the fixture string, the PEM exemption with a 2000 character bound, the wording-table order rule, the `SCORE_BELOW_POLICY` rule, `<status>` equal to `unknown`, and no 128 character cut) and applying only them: 111 of 111 vectors pass byte for byte and 111 of 111 pass semantically. The earlier gaps A1 (fixture limitation string), A2 (trigger detail), A3 (limits strings) and A4 (member set of the currency result) are closed by the text; the layout member set was confirmed by the digests now matching.

For this vector set the documented text closes the digest gap. That shows the text is sufficient for these 111 vectors, not that it is complete: wording for paths no vector reaches (for example `NO_OBSERVED_CHECKS`, which is unreachable) was not exercised, and sections B and C below are still guesses or vector-resolved choices for behaviour the text leaves open.

Remaining ambiguity noted while applying the text (no vector fails because of it):

- The precedence among the `incidents.ignored` reasons when several apply to one incident record is not stated. I check shape and signature, key trust, key revocation, subject, then future date (see C7 to C9).
- The PEM bound is 2000 characters in the text; Ed25519 SPKI PEM is far shorter, so the bound is not exercised by any vector.

## B. Vector-resolved (spec, guide and contract were insufficient)

| # | Gap and resolution | Vector |
| :-- | :--- | :--- |
| B1 | `evidenceBundleDigest` is not defined. It is the digest of the array of per-envelope digests in input order (digest of each complete envelope, proof included). Found by trying candidates against a stored assessment. | `currency.current-and-reliable`, `assess.qualified-all-pass-runtime` |
| B2 | The whole `kya.assessment/v1` layout (field names, `dimensions` entries with `weight`, check entries with `title`, `keyId`, `independence`, `acceptedEvidenceDigests` sorted, three base limitation strings) is only listed loosely in the specification. Copied from the stored assessment input. | `currency.current-and-reliable`, `currency.current-but-not-reliable` |
| B3 | A rejection entry's `id` is `null` when the envelope failed shape or signature checks, and the receipt's id otherwise. | `assess.tampered-evidence-payload`, `assess.key-substitution-rejected`, `assess.malformed-evidence-entry` |
| B4 | All rejection reason strings are free text with no list in any allowed source. Copied from expected values. The order in which reasons apply when several hold for one receipt (signature, trust, capture-issuer, source, binding, subject status, ...) is a guess; no vector has two applicable reasons except where noted below. | the 22 vectors with `rejectedEvidence` |
| B5 | Declaration receipts are rejected even when the policy allows `declaration`. | `assess.declaration-laundering-rejected`, `assess.minimum-declaration-cannot-satisfy` |
| B6 | Blocker structure: a critical failure produces only `CRITICAL_CHECK_FAILED` entries, suppressing unproven, coverage and run blockers; otherwise insufficiency blockers appear in the order of the code table in `docs/SCORING.md`; mandatory minimum entries stack after them and cap the decision at `blocked`. `docs/SCORING.md` lists the codes but not this short circuit. | `assess.critical-failure-and-unproven`, `assess.tied-runs-critical-failure-still-blocks`, `assess.minimum-stacks-on-empty-evidence` |
| B7 | Recency: receipts observed in the future do not establish a run, while revoked, over-age and expired receipts do. The specification says "before revocation, expiry and freshness exclusions" and is silent on future-dated receipts. | `assess.evidence-observed-in-future`, `assess.revoked-newer-failure-does-not-revive-older-pass`, `assess.evidence-over-age` |
| B8 | A quarantined duplicate evidence ID rejects every copy, raises `RUN_CONFLICT` and also `RUN_INVALIDATED`, and the repeated-check count is taken before quarantine (so `REPEATED_RUN_CHECKS` fires too), in that order. | `assess.duplicate-eligible-evidence-id-quarantined` |
| B9 | In an ambiguous tie the selected run still contributes its checks, score and coverage; only decision and codes change. | `assess.tied-latest-runs-ambiguous` |
| B10 | Mixed issuers or repeated checks leave the scored values intact and only add a blocker; the kept observation of a repeated check is the most conservative, then the earlier. The kept receipts are the ones listed in `acceptedEvidenceDigests`. (Rule given in the contract; the accept-list consequence was vector-resolved.) | `assess.mixed-run-issuers`, `assess.repeated-check-fail-then-pass-cannot-repair` |
| B11 | Revoked, expired and not-yet-valid subjects: `selectedRunId` null, all checks unknown, score 0 with upper bound 1000, every otherwise bound receipt rejected with the subject reason, `validUntil` equal to the manifest expiry, no minimum blockers. | `assess.minimum-keeps-revoked-decision`, `assess.subject-expired` |
| B12 | `validUntil` with no accepted receipt is the manifest expiry; with receipts it is the minimum of manifest expiry and each accepted receipt's expiry and its observation plus the policy maximum age. | `assess.empty-evidence`, `assess.manifest-expiry-bounds-validity` |
| B13 | `independentCoverage` counts only known pass or fail weight signed by an independent key; `independence` of an unknown check is `null`. | `assess.mixed-run-issuers`, `assess.independent-coverage-below-policy-partial` |
| B14 | `evidenceMode` is `none` when no receipt is accepted. | `assess.empty-evidence`, `assess.fixture-rejected-by-runtime-policy` |
| B15 | Mandatory minimum classification: an observed fail, or a pass signed by a non-independent key under `independent-pass`, is "not met"; abstain, error, missing and declared-only are "unproven". The description in `docs/SCORING.md` states this; the stacking order of the two codes (policy order, not grouped) was vector-resolved. | `assess.minimum-two-unmet-keep-policy-order` |
| B16 | A refused assessment: which top-level validation failures count (profile or scope mismatch, unknown or duplicate minimum, permission overlap, agent as own accountable party, bad evaluator digest, non-canonical time) comes from the refusal vector list; the specification says only "invalid top-level input fails". | the eight `assess.refuse-*` vectors |
| B17 | Currency refusal: "verify its checksum and consistency" is not defined. Implemented as: checksum matches, `validUntil` not before `assessedAt`, a `qualified` decision has no blockers, `blockerCodes` length equals `blockers` length, decision in the enumeration. | the four `currency.refuse-*` vectors |
| B18 | A stored assessment that is blocked or otherwise not qualified is "current" when no trigger fires but never "reliable", and `action` is `none` for it. | `currency.current-but-not-reliable` |
| B19 | Incident ordering: `ignored` entry per record, with the specified sort; `considered` counts every delivered record including exact duplicates; identical envelopes are deduplicated silently. | `currency.identical-envelope-delivered-twice` |
| B20 | Two reports with one ID from different keys are all kept (open), produce one ignored entry for the ID, and make a resolution of that ID ignored with a separate reason. | `currency.ambiguous-report-ids-fail-closed`, `currency.ambiguous-report-ids-input-order-reversed` |
| B21 | Two non-identical resolutions by one key under one ID are both ignored, one entry each. | `currency.same-key-conflicting-resolutions-not-honoured` |
| B22 | A trusted blocking report dated in the future stays open and is also listed as ignored with a note; a non-blocking future report, or a future resolution, is ignored. | `currency.future-blocking-report-stays-open`, `currency.future-low-report-ignored`, `currency.future-resolution-ignored` |
| B23 | A medium or low trusted report is `observed`, not open. | `currency.incident-medium-observed-only` |
| B24 | A resolution by a self-role key and a resolution by the reporter's own key give two different reasons, and a resolution dated at the same instant as the report is ignored. | `currency.resolution-by-self-role-key-ignored`, `currency.incident-cannot-resolve-own-report`, `currency.resolution-dated-same-instant-ignored` |

## B2. Resolved by the new texts (previously guesses or vector-resolved; N1 to N5 were closed in round 2)

Blocker wording (every code), `evidenceBundleDigest`, the rejection reason order (B4 and C5 were wrong: subject status applies to every trusted receipt before the binding checks, declaration and source checks come after the check-in-profile check, and key-revoked comes after future and predates), recency (B7, C4 confirmed), blocker order and short circuit (B6), validator grammars (C1, partly) and trigger order. Revoked, expired and not-yet-valid subject reports now match byte for byte (old A4 closed).

New gaps found while implementing the texts:

| # | Gap | Vector or area |
| :-- | :--- | :--- |
| N1 | Wrong or ambiguous: the grammar says text has "no control characters", but a PEM public key (trusted key, proof) contains line feeds. I exempted `publicKey`. The text should name that exception. | every vector with a key |
| N2 | Ambiguous: `docs/SCORING.md` has two orderings, the code table (principal after the run blockers and `NO_SCORED_OBSERVATIONS` before it) and the wording table (principal before `NO_SCORED_OBSERVATIONS`), and says "in table order". I used the wording table order; no vector contains both, so neither is pinned. | `assess.principal-required-unbound` (single blocker) |
| N3 | Ambiguous: `SCORE_BELOW_POLICY` for "a sufficiently observed result" does not say whether run blockers (ambiguous, mixed, repeated, invalidated, conflict) or the principal blocker make a result not sufficiently observed. I treat any insufficiency blocker as suppressing it. | not pinned |
| N4 | Ambiguous: the reason list gives 128-character cut for ids; I apply it to `rejectedEvidence` ids only. Grammar says identifiers are at most 128 characters, so an over-long id would be a shape failure and the cut could never apply to a valid receipt. | not pinned |
| N5 | Not stated: `<status>` in the minimum wording for a never-observed check. I used `unknown` (the check status in the report). | `assess.minimum-omitted-evidence-cannot-lift` matched |

## C. Guesses no vector pins (some now superseded, see B2)

| # | Choice made | Alternative |
| :-- | :--- | :--- |
| C1 | Validator grammars (identifier pattern, string length bounds, key sets, weights are positive integers, `minScore` is an integer 0 to 1000, coverage thresholds in 0..1, `maxEvidenceAgeSeconds` at least 1, check or tool list sizes). The sources say "exact keys, identifier and timestamp grammars" without stating them. | stricter or looser grammars |
| C2 | Signature check order: shape, then key ID against the embedded key, then canonical base64url encoding, then Ed25519; reason text for a malformed envelope, key mismatch and bad signature contains `envelope`, `key` and `signature` respectively (the contract fixes only those keywords). | any order |
| C3 | Evidence expiry boundary: expired when `expiresAt` is at or before the assessment time (validity ends at the boundary, matching the reference); stale when age is at or above the maximum. A receipt observed exactly at assessment time is not in the future. The same exclusive rule applies to manifest expiry and to `validUntil` in the currency check. Earlier text of this row chose the inclusive reading, which disagreed with the reference at the boundary instant; no vector pinned it. | inclusive (the earlier choice) |
| C4 | A receipt that predates the manifest does not establish run recency. | it could |
| C5 | The order of per-receipt rejection reasons when several apply (see B4); the subject status check is applied only to receipts that pass the binding checks. | any order |
| C6 | `SCORE_BELOW_POLICY` is raised only when no insufficiency blocker (unproven critical, coverage, independence) applies. The table says "sufficiently observed" without defining it. | raise it with them |
| C7 | A capture-issuer key reporting an incident is treated as untrusted ("not a trusted anchor"). | its own reason |
| C8 | Incident subject comparison uses the assessment's `subjectDigest`, not the supplied manifest's digest. | the manifest digest |
| C9 | Reporter-own-report is checked before independence of the resolver; appeals are not subject to those two rules, only to trust, subject, time and a known unambiguous target. | different order |
| C10 | A valid resolution of a non-blocking report lists the report under `resolved`, not `observed`. | `observed` |
| C11 | Two reports with the same key and same ID but different content are treated like two reports from different keys (kept open, flagged), not as a same-key conflict. | not honoured |
| C12 | `revokedSubjectDigests` is tested against the assessed subject digest (trigger `subject-revoked`), independently of `subject-changed`. | the current manifest's digest |
| C13 | Incident payload grammar: id pattern, `refId` must be a different identifier for resolution and appeal and `null` for report, severities `low`, `medium`, `high`, `critical`. | the contract only shows examples |
| C14 | Duplicate members in stdin JSON, prototype keys and nesting deeper than 64 are refused. | the limits are mine |
