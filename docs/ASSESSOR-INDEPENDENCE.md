# Assessor independence criteria (Draft)

Status: draft criteria, version 0.1. Not accreditation law, not legal advice, not adopted by any body. These criteria need review by legal counsel and by practising assessors before anyone relies on them. No accredited assessor exists.

## 1. What this is for

A relying party policy may assign the `independent` role to a trusted key. Today that assignment is the relying party's own judgement and nothing in the protocol checks it. A signature proves possession of a key, not that the holder is independent of the agent operator. This document proposes criteria a relying party can apply before assigning the role, and a signed record (`kya.assessor-disclosure/v1`, ADR-0028) that makes the facts the criteria depend on contestable and expiring.

Independence here means: no relationship that would give the assessor a reason to favour a particular result for a particular operator. It is a property of one assessor key relative to one operator, at one time. It is not a property of a person in general.

## 2. Criteria for assigning the independent role

A relying party should assign `independent` to an assessor key only if all of the following hold at the time of assignment and for as long as the assignment stays in the policy.

1. **No financial relationship.** The assessor, its organisation and its principal owners hold no equity, debt, revenue share, success-based fee or other material financial interest in the operator, and the operator holds none in them. Ordinary fixed-fee payment for the assessment itself is allowed and is declared.
2. **No control relationship.** Neither side can appoint, remove or direct the other, share directors or officers, or hold voting control over the other.
3. **No authorship.** The assessor and the people who performed the assessment did not design, write, train, tune or operate the evaluated agent, its harness or its scenario suite, and did not write the policy under which it is assessed.
4. **No employment.** None of the people who performed the assessment is currently employed by or contracted to the operator.
5. **Cooling-off.** After a prior engagement with the operator (consulting, design review, employment, authorship) has ended, a default of 365 days passes before independence may be assigned for that operator. The period is a policy parameter; the default is a maintainer proposal.
6. **Tooling dependency is disclosed.** If the assessment relied on tooling, hosting or models supplied by the operator, this is disclosed. It does not by itself block independence but a relying party may treat it as blocking.
7. **Rotation.** A relying party should not rely on the same assessor key for the same operator for more than three consecutive assessment periods without a cooling-off or a second assessor. The count is a proposal.
8. **Disclosure.** The assessor key holds a current, own-signed disclosure for the operator (section 3). A disclosure expires after at most 366 days.
9. **Third-party challenge.** A trusted party may declare a relationship it knows of. An undisclosed declared relationship removes standing until the assessor lists the declared code in a current disclosure; the code clears the reason as soon as the code is listed, and the code does not itself require a review step. A relying party that wants a human review before restoring standing must add that step in its own process; any listed blocking relationship still removes standing.

Organisational, financial and tooling independence are different tests and a relying party may require them separately.

## 3. Records

`kya.assessor-disclosure/v1` has three kinds: `disclosure` (the assessor lists relationship codes for one operator, or `none`), `conflict-declaration` (another trusted key names relationships it believes exist) and `withdrawal` (the signer of an earlier record withdraws it: an assessor its disclosure, a trusted declarer its declaration). A withdrawal carries both the target id (`refId`) and the target envelope digest (`refDigest`) and binds to the digest, so a different record that reuses the id is not withdrawn. A withdrawal must be issued at or after its target and not in the future, or it is ignored (`withdrawal-time-invalid`). A withdrawn disclosure is treated as no disclosure from the withdrawal time onward: it does not revive an older disclosure. The latest started disclosure governs even after it expires, so letting an adverse newer disclosure lapse reports `disclosure-expired`, not the older record. Records hold coded fields and digests only. Names, contracts and narrative stay private and are referenced by `detailsDigest`. Relationship codes: `financial`, `control`, `authorship`, `employment`, `prior-engagement`, `tooling-dependency`, `none`.

`checkAssessorStanding` (in `src/assessor/`) returns standing per key with named reasons: `no-disclosure`, `disclosure-expired`, `disclosure-not-yet-valid`, `key-revoked`, `blocking-relationship`, `undisclosed-conflict-declared-by-other-party`, `cooling-off-not-elapsed`, `conflicting-disclosures`. It does not change any assessment result. A policy opt-in to use standing is a proposal only and is not implemented.

## 4. What this does not establish

- That a disclosure is true. A false disclosure is a signed false statement by a key; only a challenge, an incident record or an outside audit can expose it.
- That a person or organisation is who it claims to be. Keys are pseudonymous.
- That a declarer is right. A declaration is an allegation from a trusted key; the assessor may disclose and the relying party decides. Declarers can abuse this, so the declarer set is the relying party's explicit choice.
- Competence. Independence says nothing about proficiency; see `docs/ACCREDITATION.md`.
- Legal sufficiency in any jurisdiction or under any regulation.

## 5. Open questions for review

Whether 365 days and three periods suit practice; how to treat large firms where one part advises and another assesses (information barriers); how to treat open-source maintainers who contributed to an evaluated agent; whether a relying party needs a standing check at assessment time or also at verification time.
