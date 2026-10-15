Draft input for practitioner and legal review. Not legal advice. Not a compliance claim.

# Integration proposals for the crosswalks

Nothing here has been applied. Shared files (evidence/requirements.json, docs/REQUIREMENTS.md, docs/SPECIFICATION.md, README) were not edited. Each requirement below would need an ADR and a detecting test before entering the registry.

## Proposed requirements

The test titles are the exact titles in test/crosswalks.test.mjs. Area: `crosswalks`. Specification section: `## Governance documents` in docs/SPECIFICATION.md.

| Proposed ID | Level | Statement | Exact test title |
| :--- | :--- | :--- | :--- |
| KYA-XWK-001 | MUST | Every KYA requirement ID cited in a crosswalk MUST exist in the requirements registry. | every requirement ID cited by a crosswalk exists in the registry |
| KYA-XWK-002 | MUST | Every crosswalk file MUST open with the draft, not-legal-advice, not-a-compliance-claim notice. | every crosswalk file opens with the disclaimer |
| KYA-XWK-003 | MUST | Every crosswalk row MUST carry a status from the allowed set and MUST be flagged for primary re-check when its basis is not primary text. | every crosswalk row has an allowed status and a flag when its basis is secondary |
| KYA-XWK-004 | MUST | A crosswalk MUST NOT state compliance, certification or guarantees except in a negation. | no crosswalk claims compliance or certification outside a negation |
| KYA-XWK-005 | SHOULD | The crosswalk index SHOULD list every framework file. | the crosswalk index lists every framework file |

## Proposed changes to shared files

1. evidence/requirements.json: add the five entries above, each tracing to its test in test/crosswalks.test.mjs; regenerate docs/REQUIREMENTS.md with `npm run requirements`.
2. docs/SPECIFICATION.md, section `## Governance documents`: one sentence that crosswalks are informative, carry the notice, and make no compliance claim. No normative protocol change is needed.
3. README: link docs/crosswalks/README.md.
4. docs/WORLD-CLASS-STATUS.md: WS7 moves from Missing to Begun (drafts, no review). It must not move further until the named practitioner review (XREV) and legal review happen.

## Open items for the owner

- Obtain the licensed text of ISO/IEC 42001:2023 and the AICPA 2017 Trust Services Criteria (2022 points of focus) and re-check the 28 secondary rows.
- Re-read EU AI Act Articles 9, 12, 14 and 15 from the Official Journal text and check application dates and any later amendment.
- Name a practitioner reviewer per framework and arrange legal review of wording.
- Not covered yet: auditor guide and insurer data specification (the other WS7 deliverables).
