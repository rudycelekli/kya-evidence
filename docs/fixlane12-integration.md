# Fix lane 12: validity boundary and metamorphic invariants

Scope: `checkCurrency` boundary semantics, a seeded metamorphic test file, one core fix it found. Not published, tagged or released.

## 1. Validity boundary

Decision: validity ends at `validUntil`, not after it. `assess` already treats an expiry at or before its own time as expired (manifest `expiresAt <= at`, receipt `expires > at` required, freshness `at - observed < max` required). `checkCurrency` used `at > validUntil`. It now uses `at >= validUntil`, so the same instant is expired in both functions and a relying party cannot read current for an assessment that `assess` would already refuse. Fail closed: the cost of the change is one extra reassessment at one instant.

Changed files: `src/assessment/application/currency.mjs`, `scripts/assessment-vectors.mjs` (vector renamed to `currency.at-validity-boundary-is-expired`, rationale rewritten), `evidence/assessment-vectors.json` (regenerated with `node scripts/assessment-vectors.mjs`), `interop/second-impl/currency.mjs`, `interop/second-impl/kya2.mjs`, `interop/second-impl/AMBIGUITIES.md` (row C3), `docs/SPECIFICATION.md`, `CHANGELOG.md`, `test/assessment.test.mjs` (new test for one millisecond before, at and after, both functions), `test/incidents.test.mjs` (its CHECK constant sat exactly on `validUntil` and relied on the old boundary; moved to 12:59). The requirement statement KYA-MON-001 says expiry and did not need a text change.

The second implementation encoded the inclusive reading in four places: currency expiry, manifest expiry, receipt expiry and receipt freshness inside `assess`. No vector covered those instants, so it passed 111 of 111 while differing from the reference at the boundary. All four are exclusive now. A scratch differential (450 random worlds with one receipt per check, expiries and freshness exactly at the assessment instant) agrees on decision, score and `reportDigest` in 450 of 450. The Python checker (`interop/python`) has no expiry logic and its 34 tests pass unchanged.

## 2. Metamorphic results (`test/metamorphic.test.mjs`)

| Invariant | Result |
| :--- | :--- |
| a. Adding a revocation (signer key, one receipt, subject, one of two receipts sharing an ID) never improves decision, earned score or coverage | Held |
| a. Adding a trusted open incident never makes an assessment current or reliable; double delivery, appeal, self resolution, backdated resolution and untrusted resolver cannot launder it | Held |
| b. Removing a receipt never creates a qualification and never raises score or coverage | Held for a single run with one receipt per check. False in general, see limits |
| c. Permuting evidence order never changes the decision or any member except the order-bearing ones | Held. `reportDigest` does change, by documentation: `evidenceBundleDigest` is in input order and `rejectedEvidence` carries the index (SCORING.md) |
| d. A time at or after `validUntil` never revives an assessment, for `assess` and `checkCurrency` | Held (and the boundary instant needed the fix in section 1) |
| e. Duplicating a receipt never changes the score | VIOLATED, fixed. See finding E-1 |
| f. Raising `minScore`, `minCoverage`, `minIndependentCoverage`, lowering `maxEvidenceAgeSeconds`, or adding a mandatory minimum never adds a qualified world | Held (two successive steps per case) |
| g. Same canonical inputs give the same bytes, independent of object key order, repeated, and the input is not mutated | Held for `assess` and `checkCurrency` |

A non-vacuity test requires both qualified and not qualified worlds in the corpus.

### Finding E-1 (fixed): replaying a failing receipt raised the score

A byte-identical or same-ID duplicate of a failing receipt is quarantined (`Duplicate evidence ID`). The check then fell back to the best surviving sibling observation, so a pass on the same check counted. Example: check 4 had an older fail and a newer pass; the conservative pick kept the fail (earned 500). Replaying the fail receipt gave earned 666, higher coverage, and for a critical check `blocked` became `insufficient-evidence`. The decision never became `qualified`, because the quarantined receipt sits in the selected run and RUN_CONFLICT blocks qualification. Impact: reported score, coverage and label, plus any consumer that reads `score` of a non-qualified report. Fix, test first: a check with a quarantined duplicate-ID receipt in the selected run is `unknown` (`src/assessment/application/assess.mjs`, `quarantinedChecks`). The 111 vectors, the traced tests and the second implementation (updated the same way) stay green; no vector pinned the old behavior. Regression test: `metamorphic e regression: replaying a failing receipt cannot let a sibling pass count toward the score`.

### Limits that are by design, pinned in tests, not hidden

1. Omission. Removing the newest run, a failing receipt in a repeated observation pair, or one copy of a duplicate-ID pair can turn blocked or conflicted into qualified. The core has no completeness commitment; ADR-0017 and ADR-0020 propose one and it is not implemented. Pinned by `metamorphic b limit`.
2. A byte-identical duplicate delivery of a receipt quarantines it and drops a qualified run to `insufficient-evidence` (fail closed, but a transport that delivers twice causes a spurious downgrade; incident records, by contrast, skip an exact duplicate envelope). Pinned by `metamorphic e pin`. Proposal for the owner, not made here: skip exact duplicate evidence envelopes the way incidents do. That is a specification change and it affects the second implementation and vectors.
3. Report digest is order dependent on the evidence array (documented).

### Invariants not expressed, and why

- Permutation of incident records and of `trustedKeys` inside `checkCurrency` is covered by `property-assessment.test.mjs` for incidents; the metamorphic file permutes `trustedKeys` for `assess` only.
- Monotonicity of qualification over wall-clock time before `validUntil` is not asserted: a receipt dated after the first check time legitimately appears later and can change the selected run.
- No invariant on `compareAssessments`, dossiers, universes or the VC bridge: out of scope for this lane.
- Revocation of a trusted resolver key inside `checkCurrency` is not tested as a separate relation: it changes `policyDigest` and fires `policy-changed` anyway.

### Divergences found in the second implementation, not fixed here

The scratch differential with duplicate IDs, repeated observations per check and several runs still shows digest-level differences, none pinned by a vector:

- Duplicate-ID counting: the reference counts every correctly bound trusted receipt across all runs, including expired or revoked ones; the second implementation counts live receipts of the selected run only.
- `REPEATED_RUN_CHECKS`: the reference counts bound receipts of the selected run; the second implementation counts live ones.
- Rejection reason for an invalid receipt in an older run: the reference reports the freshness or expiry reason, the second implementation reports `Older run excluded`.

Candidates for new vectors in the vector lane, and for a specification sentence.

## 3. Requirement proposals (not applied; `evidence/requirements.json` untouched)

IDs are the three letter and three digit part; prefix with `KYA-` like the others.

| ID | Level | Section (existing heading) | Statement | Exact test title |
| :--- | :--- | :--- | :--- | :--- |
| MET-001 | MUST | Reports and viewers | An assessment MUST be treated as not current at the instant equal to its `validUntil` and after it, by `assess` and by the currency check alike. | `validity ends at validUntil: currency and assess agree one millisecond before, at, and after the boundary` |
| MET-002 | MUST | Trust and eligibility | Adding a revocation to a policy MUST NOT improve the decision or raise the earned score or coverage. | `metamorphic a: adding a revocation never improves the decision or raises the earned score` |
| MET-003 | MUST | Reports and viewers | Adding a trusted open incident MUST NOT make an assessment current or reliable, and no combination of duplicate delivery, appeal, self resolution, backdated or untrusted resolution may clear it. | `metamorphic a: adding a trusted open incident never makes a reliable assessment more reliable` |
| MET-004 | MUST | Run selection and qualification | Removing a receipt from a single run that has one receipt per check MUST NOT create a qualification or raise score or coverage. | `metamorphic b: removing a receipt from a single run with one receipt per check never creates a qualification` |
| MET-005 | MUST | Run selection and qualification | Permuting the order of the evidence MUST NOT change the decision or any report member other than the order-bearing bundle digest, rejection indexes and the report digest. | `metamorphic c: permuting the evidence order never changes the decision or any order-free member` |
| MET-006 | MUST | Reports and viewers | At or after `validUntil`, neither `assess` on the same inputs nor the currency check MUST report a qualification or current state. | `metamorphic d: at or after validUntil neither assess nor checkCurrency treats the assessment as live` |
| MET-007 | MUST | Run selection and qualification | Duplicating a receipt MUST NOT improve the outcome or raise the score, and a check with a quarantined duplicate-ID receipt in the selected run MUST be unproven. | `metamorphic e: duplicating a receipt never improves the outcome or raises the score` and `metamorphic e regression: replaying a failing receipt cannot let a sibling pass count toward the score` |
| MET-008 | MUST | Run selection and qualification | Raising a required minimum MUST NOT add a qualified run. | `metamorphic f: raising a required minimum never adds a qualified run` |
| MET-009 | MUST | Interoperability and versioning | The assessment and currency results MUST be pure functions of the canonical inputs, independent of object key order. | `metamorphic g: assess and checkCurrency are pure functions of canonical inputs` |

## 4. Not verified

- The whole test suite, the mutation run and `node scripts/check.mjs` on a fresh clone were not all run (disk). Run: the 16 test files that touch currency, assess, vectors, the second implementation, the CLI, bridges and the gate (348 pass), the vector checker, both vector runs, the Python tests and `scripts/check.mjs`.
- `src/conformance/` and the pinned evaluator digest were not touched.
- No outside implementation exists; the second implementation is same-team.
- The mutation checks (`scripts/mutation-check.mjs`) were not run, so it is unknown whether any existing mutation control targeted `> validUntil` or the old selection.
