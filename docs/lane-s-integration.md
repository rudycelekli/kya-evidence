# Lane S integration proposals (WS8-02)

Proposals only. Lane S edited no shared file. Everything below needs an owner decision and, for items 1 and 3, a substantive ADR and review because they touch shared validation or the registry.

## 1. Optional policy field (not implemented)

Proposal: an optional policy field `assessorStanding` with the exact keys `required` (boolean), `declarerKeyIds`, `coolingOffDays`, `blockingRelationships`, validated in the shared policy validator. When absent, behaviour is unchanged byte for byte. When present and `required` is true, an evidence item whose independent key is not `good` in `checkAssessorStanding` would not count as independent. This changes assessment results, so it needs the golden vectors extended with a without-field control (results unchanged) and a with-field case, an ADR superseding part of ADR-0028, and a test that detects removal of the gate. Standing needs the disclosure records supplied alongside the assessment inputs, which is a new input and therefore a protocol change.

## 2. Requirements to add to evidence/requirements.json

Each statement must contain its level word. Section values must exist as `## <section>` headings in docs/SPECIFICATION.md. Proposed section: `Trust and eligibility`. Proposed area: `ASR`. Proposed IDs follow the pattern `KYA-ASR-NNN`.

| ID | Level | Statement | Section | Tests (exact titles in test/assessor.test.mjs) |
| :--- | :--- | :--- | :--- | :--- |
| KYA-ASR-001 | MUST | An assessor disclosure MUST be signed Ed25519 under the domain prefix and MUST reject extra fields, free text, unknown codes and records over 4096 bytes | Trust and eligibility | `assessor disclosures are signed, domain separated and strict`; `assessor disclosure rejects a forged signature from another key`; `assessor disclosure signed under another domain does not verify`; `assessor disclosure rejects extra fields, free text, bad codes and oversize input` |
| KYA-ASR-002 | MUST | Standing MUST be reported per key with named reason codes and MUST fail closed on expiry, revocation, a blocking relationship, unfinished cooling-off and an undisclosed conflict declared by a trusted other party | Trust and eligibility | `missing and expired and future disclosures name their reasons`; `a revoked assessor key is not in standing even with a valid disclosure`; `a blocking relationship removes standing and prior engagement is judged by cooling off`; `an undisclosed conflict declared by a trusted other party removes standing` |
| KYA-ASR-003 | MUST NOT | A disclosure MUST NOT grant standing to a key other than its signer, and a declaration MUST NOT count unless signed by a trusted declarer other than the assessor | Trust and eligibility | `replaying another keys disclosure does not give standing`; `declarations from the assessor itself or untrusted keys are ignored with reasons`; `a withdrawal by the same key ends a disclosure and cannot be forged by another key` |
| KYA-ASR-004 | SHOULD | Standing results SHOULD be independent of record order and duplicate delivery and equal-time disagreement SHOULD fail closed | Trust and eligibility | `the newest disclosure wins and equal time conflicts fail closed`; `duplicate delivery of one envelope is harmless and results do not depend on order` |

## 3. Spec text

Add a short paragraph under `## Trust and eligibility` stating that assessor standing is advisory, defined by ADR-0028, and does not alter assessment results unless a policy opts in. Link docs/ASSESSOR-INDEPENDENCE.md and docs/ACCREDITATION.md as drafts.

## 4. package.json

- `exports`: add `"./assessor": { "import": "./src/assessor/index.mjs" }`.
- `files` already includes `src/`.
- No new script is needed; `npm test` globs `test/*.test.mjs`.

## 5. Other shared files

- `npm run adr:index` regenerates `evidence/adr-index.json` to include ADR-0028. Lane S did not commit that file; the integrator should regenerate it once ADR numbering across lanes is settled.
- `docs/WORLD-CLASS-PLAN.md` WS8 status and `evidence/world-class-status.json`: record WS8-02 as partial (internal draft, no external review). It must not be marked verified; it needs an outside party (XUSE, EXT).
- `docs/governance/CHARTER.md` role table could cross-reference ASSESSOR-INDEPENDENCE.md for the Assessor row.
- ADR numbering: ADR-0027 was not present in this lane's base. Check for collisions.

## 6. Required for a green suite: docs/CRYPTO-AGILITY.md

`test/crypto-inventory.test.mjs` requires every domain prefix in src to be documented in the shared file docs/CRYPTO-AGILITY.md. Lane S did not edit it, so that one test fails on this branch until the integrator adds this row after the `kya.incident/v1` row:

`| `kya.assessor-disclosure/v1\n` | Assessor disclosure, conflict declaration, withdrawal payload (`kya.assessor-disclosure/v1`) | `src/assessor/disclosure.mjs` |`

## 7. Not verified

No accredited assessor exists. Criteria and thresholds (365 day cooling-off, three-period rotation, panel size, timelines) are drafts needing legal and practitioner review. Mutation controls for the signer-match and declarer-trust checks are not added; scripts/mutation-check.mjs is a shared file.
