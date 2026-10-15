# Calibration study pre-registration template

Status: Draft template. Fill every field before any cohort assessment is run, then freeze and hash it as described below. Design reference: [CALIBRATION-STUDY.md](CALIBRATION-STUDY.md). Privacy reference: [PRIVACY.md](PRIVACY.md).

No data exists yet, and nothing in this template is evidence of predictive validity. A filled copy is a commitment, not a result. A blank or partly filled copy must not be frozen.

## How to use this template

Copy this file to a private working location, replace each `<<...>>` placeholder, delete the guidance lines starting with `Guidance:`, and keep the section headings unchanged. A filled copy may contain no `<<` marker. Free text is allowed only in the sections that ask for it; do not put names, contact details, prompts or incident narrative in it.

## Study identity

Study ID: <<identifier, letters digits and hyphens, matching the campaign ID below>>
Version of CALIBRATION-STUDY.md used: <<commit SHA or document SHA-256>>
Registrar: <<role or pseudonymous code, not a personal name>>
Registration time (UTC): <<canonical ISO timestamp, supplied explicitly>>

## Hypotheses

Primary H1: <<restate or state any change from the design, with reason>>
Secondary S1, S2, S3 in fixed sequence: <<restate>>
Direction: <<one-sided as in the design, or justify a change>>
Minimum useful AUC: <<value>>

## Outcome definition

Primary event definition: <<incident record kind, severity set, window, subject digest rule>>
Severe event definition: <<restate>>
Independent reporting keys (policy digest and key role): <<policy digest; how independence of each reporter is shown; at least two channels>>
Outcome adjudication panel (blinding statement): <<describe, no names>>

## Unit and population

Unit: <<one row per subject digest at index time, or justify>>
Eligibility: <<restate>>
Exclusions and their counts: <<list each exclusion rule>>
Frozen profile digest: <<64 hex>>
Frozen scenario-set digest: <<64 hex>>
Frozen evaluator digest: <<64 hex>>
Frozen policy digest: <<64 hex>>
Holdout commitment digest (if used): <<64 hex or none>>

## Follow-up and censoring

Index time rule: <<restate>>
Primary window: <<days>>
Descriptive windows: <<days>>
Checkpoints for configuration re-attestation: <<days>>
Subject digest change rule: <<follow-up ends at the change; restate>>
Withdrawal rule and bounds: <<restate>>

## Baselines

Random reference seed: <<integer>>
Declaration-only scoring rule (written out or digest of the rule): <<value>>
Vendor benchmark source and coverage condition for S2: <<value>>
Simple rule baseline: <<value>>

## Sample size

Assumed prevalence: <<value and source or "unknown, guessed">>
Assumed true AUC: <<value>>
Alpha, power, sidedness: <<values>>
Design effect for clustering: <<value and whether measured>>
Assumed attrition: <<value>>
Computation (script digest or formula and result): <<value>>
Minimum events E_min and minimum analysis agents N_min: <<values>>
Feasibility statement: <<state plainly how the cohort will be reached, or state that feasibility is not shown>>

## Analysis plan

Primary estimator and interval: <<value, bootstrap seed and resample count>>
Paired comparison method for each secondary: <<value>>
Final analysis code digest (set after the code is frozen, before unblinding): <<64 hex or pending>>
Handling of missing data and the missing thresholds: <<restate>>
Multiplicity: <<restate>>

## Decision rules

ACCEPT: <<restate with the registered numeric thresholds>>
REJECT: <<restate with the registered numeric thresholds>>
INCONCLUSIVE: <<restate, including the integrity gates>>

## Integrity gates

Gate list: <<restate; add any gate, never remove one>>
Who verifies each gate: <<role>>

## Data governance

Dataset fields (digest-only list): <<list>>
DPIA reference (digest of the completed DPIA): <<64 hex>>
Retention and deletion: <<value>>
Data steward (role, not a study author): <<role>>
Interim access rule: <<restate: sealed, data-quality and safety only>>
Publication authorization holder: <<role>>

## Deviations log

Deviations are appended after freezing, never edited in the frozen text. Each entry: date, section, change, reason, whether made before or after any outcome access. <<none at freeze time>>

## Freeze and hash procedure

The goal is that the filled document cannot be changed after data collection begins without the change being visible. This uses the existing campaign plan and ledger concepts and the existing canonicalizer; it adds no new ledger kind and no new record schema.

1. Normalize. Take the filled document as UTF-8 text, convert every line ending to LF, remove trailing spaces and tabs on every line, collapse a trailing run of blank lines to exactly one final newline, and delete the guidance lines. The normalized text is the frozen document.
2. Hash. Compute the SHA-256 of the frozen document bytes. This is the registration digest. Record it as 64 lowercase hexadecimal characters. (The reference tool for hashing bytes is `hashBytes`; the same value comes from any SHA-256 implementation.) To hash a structured copy instead, build the registration object with the study fields as strict JSON, canonicalize it with the project canonicalizer (a bounded sorted-key JSON subset, not RFC 8785), and take its SHA-256; record which of the two was used. The bytes hash is the default.
3. Commit through a registration campaign. Create a campaign plan, schema `kya.campaign-plan/v1`, signed by a key that the study policy lists as an unrevoked `capture-issuer` anchor (ADR-0021). The campaign ID is the study ID. The use-case text states that this is a calibration study registration and that no model is run. The plan has one attempt whose `scenarioSetDigest` carries the registration digest, and whose `subjectDigest` carries the SHA-256 of the study ID text. This reuses existing fields to bind a digest; it is a convention of this study, not a change to the plan format, and the runner is never invoked on this plan.
4. Open the ledger. `openLedger` signs a `planned` entry for the attempt. Then append a single `abandoned` entry with the existing reason code `campaign-closed` so the registration is not an unaccounted attempt. Verify the ledger and read its `headDigest` and `entryCount`.
5. Pin the head outside the ledger file. A truncated or forked ledger verifies unless the head is pinned elsewhere (ADR-0021). Record the head digest and entry count with an independent party, or with external anchoring (ADR-0020) once that is implemented; publication of the pin needs explicit human authorization. Without an external pin this step proves only that the ledger is consistent with itself, and the integrity gate in the design is not met.
6. Commit the cohort. Only after step 5, create the enrolment campaign plan listing every planned assessment attempt, as in the design, signed by the same kind of key, and open its ledger. The first `started` entry of any cohort attempt must be dated after the registration pin.
7. Verify before data. Re-hash the stored frozen document and confirm it equals the digest in the registration plan; run `verify-ledger` with `--expect-head` and `--expect-entries` for both ledgers.
8. Amendments. A change after freezing is recorded in the deviations log with a new frozen document and a new registration digest committed through a new registration campaign. Both digests stay on record; the earlier one is never replaced.

Not covered: the signature proves possession of the capture-issuer key, not that the registrar is honest or that the registration was written before the registrar knew any outcome. A registration made after data exists is detected only through the dates and an external pin.

Freeze record (fill after freezing):

Registration digest (SHA-256): <<64 hex>>
Registration campaign ID: <<study ID>>
Registration plan digest: <<64 hex>>
Ledger head digest and entry count: <<64 hex, integer>>
External pin holder and date: <<role, canonical ISO timestamp>>
