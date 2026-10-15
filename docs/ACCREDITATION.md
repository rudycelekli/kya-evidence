# Assessor accreditation process sketch (Draft)

Status: Draft sketch, version 0.1. Not adopted. Not legal advice. Needs review by legal counsel, practising assessors and a neutral body. No accreditation body exists, no assessor is accredited, and nothing here confers any status. Levels and thresholds are placeholders for discussion.

## 1. Principles

- Accreditation, if it ever exists, attests to a defined process and proficiency for a stated scope. It is not a certification of any agent and is not an authorisation grant.
- Independence criteria are in `docs/ASSESSOR-INDEPENDENCE.md`. Accreditation would require them plus proficiency.
- Every accreditation decision is contestable through the appeal path in section 4.
- Relying parties keep their own trust anchors. An accreditation never forces a relying party to trust a key.

## 2. Proposed levels

| Level | Meaning | Evidence required |
| :--- | :--- | :--- |
| 0 Listed | Key and contact route recorded. No claim about quality. | A signed disclosure for each operator assessed; contact route for challenges |
| 1 Practitioner | Has shown the ability to run the protocol and read results correctly | Proficiency test passed on frozen cases; passed golden assessment vectors; two disclosures with no upheld challenge |
| 2 Independent | May be assigned the `independent` role for operators where standing is good | Level 1; a completed assessment cross-checked by a second assessor with agreement analysis; documented information barriers; current disclosure |
| 3 Lead | May review other assessors | Level 2 for at least 18 months; a reviewed sample of other assessors' work; no open upheld incident |

Levels, durations and counts are proposals.

## 3. Evidence an assessor provides

1. Signed `kya.assessor-disclosure/v1` for each operator, kept current (maximum 366 days).
2. Proficiency test results on frozen cases, bound to evaluator and suite digests.
3. Cross-assessment: a second assessor assesses the same agent under the same policy; agreement is analysed and published as reliability, not as proof of correctness.
4. Method record: tooling digests, evaluator identity, and private-detail digests, never raw evidence.
5. Right of reply: the operator sees findings before publication and may attach a response by digest.

Withdrawal, expiry or a revoked key ends standing automatically in `checkAssessorStanding`; a human accreditation body would additionally record suspension and removal.

## 4. Appeals

Appeals are signed `kya.incident/v1` records of kind `appeal` (ADR-0014). The existing mechanism records the dispute and never clears a trigger by itself; a resolution must be signed by an `independent`-role key other than the reporter and dated after the report.

Proposed path for an accreditation decision or an assessment finding:

1. The affected party files an appeal incident referencing the report by `refId`, with private grounds referenced by `detailsDigest`.
2. A panel of at least three reviewers, none with a relationship to either side (each holding a current disclosure that shows `none` for both parties), reviews within a stated time. Proposed: acknowledge within 14 days, decide within 60 days.
3. The panel decision is a signed `resolution` record. An appeal does not suspend a published finding unless the policy says so.
4. A decision may itself be appealed once to a differently composed panel.

Timelines, panel size and the standing of panel members are proposals. The protocol cannot prevent panel capture; it only makes panel disclosures and decisions auditable.

## 5. Not established

No assessor, panel, body or scheme exists. Proficiency tests are not written. Inter-assessor reliability has not been measured. Legal effect, liability and regulatory recognition are unexamined.
