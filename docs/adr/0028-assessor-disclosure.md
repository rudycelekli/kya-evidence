# ADR-0028: Assessor disclosure records and standing check

**Status**: Proposed
**Date**: 2026-10-15
**Depends-on**: ADR-0004, ADR-0012, ADR-0014, ADR-0021

Review boundary: written by one lane; no independent or legal review yet; no accredited assessor exists.

## Context

The `independent` policy role is asserted by the relying party and nothing records why. Promotion to independent evidence in ADR-0004 and incident resolution in ADR-0014 both lean on that role. Independence is a relationship between an assessor key and an operator, so it needs a record that can expire, be withdrawn and be challenged, without putting personal data or narrative into public artifacts.

## Decision

Add `kya.assessor-disclosure/v1` under `src/assessor/`: an Ed25519 signed record with exact keys, a domain-separation prefix, a 4096 byte limit and canonical JSON. Fields are coded: a closed relationship vocabulary, timestamps, an operator digest and a details digest. There is no free text. Three kinds: `disclosure` (signed by the assessor key itself), `conflict-declaration` (signed by a different key the relying party trusts as a declarer) and `withdrawal` (signed by the assessor key, referencing its own record). `checkAssessorStanding(disclosures, policy, now)` returns per key a standing and named reason codes. Invalid, misdirected, wrong-signer, untrusted-declarer and other-operator records are ignored and listed. Identical redelivery collapses, equal-time disagreeing disclosures fail closed, and a conflict declared by another party that the assessor did not disclose removes standing.

The check is advisory. It does not change an assessment result. A proposed optional policy field that would make assessment results depend on standing is documented in `docs/lane-s-integration.md` and is not added by this ADR. Any such change touches shared validation and needs its own review.

Criteria for when to assign the role are in `docs/ASSESSOR-INDEPENDENCE.md` and a process sketch is in `docs/ACCREDITATION.md`; both are drafts.

## Alternatives

Free text conflict statements would leak private detail and invite defamation risk. Letting the assessor alone attest would make independence a self-claim; third-party declarations add a challenge path. Making standing automatically change scores would let a missing record silently rewrite results, so it is opt-in. A central registry of assessors needs governance that does not exist.

## Consequences

Relying parties can audit why a key holds the role and see when that basis lapses. The mechanism cannot tell whether a disclosure is true, cannot identify a real person, and gives declarers a lever that can be abused, so the declarer set is explicit policy. Cooling-off and blocking sets are defaults proposed by maintainers and need practitioner review.

## Validation

`test/assessor.test.mjs` covers forged signature, wrong domain, replay of another key's disclosure, extra fields, oversize input, each standing reason, withdrawal forgery, equal-time conflicts, order independence and strict policy validation. Mutation controls for the signer-match and declarer-trust checks are not yet added.
