> **Draft for review by qualified legal counsel. Not legal advice. Not yet adopted by any body.**

# Name use and conformance claims (draft)

Status: draft, version 0.1 (drafted 2026-10-15). Not adopted. Counsel should review the name-use rules and the claim wording before anyone relies on them.

## 1. Registration status

No registered trademark exists for "KYA Evidence" or "Know Your Agent" as far as this repository records. No application has been filed. Do not add the symbols ® or ™ to any name, file or page for this project. The owner must confirm the registration position before any document relies on this section. Whether to seek registration is an open question for counsel (see section 7).

## 2. Describing the project

Use the description in the repository: "a reference implementation of an open protocol for signed evidence about an exact agent configuration". Say "reference implementation" or "experimental reference implementation" when describing the software. Do not describe the protocol as a standard, a certified scheme or an industry specification unless a body has adopted it.

## 3. Claims that may be made

A conformance claim names requirement IDs, not the whole protocol. An accurate claim has this form:

> This implementation passes the published vectors for requirement IDs KYA-INT-003 and KYA-BND-001 at registry digest `<digest>`, version `<version>`, on `<date>`. Report: `<link or path>`.

Permitted wording, when true and evidenced:

- "passes the published vectors for requirement IDs X, Y";
- "its conformance report lists these requirement IDs as pass, and these as not-run";
- "reconstructs the golden vectors for KYA-INT-004" (only after every published vector is reproduced and inputs outside its subset are refused);
- "this implementation is experimental and not independently reviewed".

## 4. Claims that may not be made

The following are prohibited, whatever the intent:

| Prohibited wording | Why |
| :--- | :--- |
| "certified", "KYA certified", "certification" | No certification scheme or accreditation exists |
| "endorsed by", "approved by", "recommended by" any body | No endorsement exists |
| "compliant with" any standard, regulation or framework (for example the EU AI Act, ISO/IEC 42001, NIST AI RMF, SOC 2) | No crosswalk has been reviewed (WS7); "compliant" is a legal finding |
| "adopted by", "a standard of", "ratified" | No adopting body exists (see `CHARTER.md`) |
| "member of", "affiliated with", "in partnership with" a standards venue or foundation | No affiliation exists |
| "KYA conformant" or "fully conformant" without requirement IDs | Conformance is per requirement ID (see `docs/CONFORMANCE.md`) |
| "trusted", "safe", "verified agent" as a statement about an agent | An assessment is policy-relative and bounded by its evidence and expiry |
| any claim that a commercial product scored a given result | Fixture results never score commercial products; no authorised commercial run is recorded |
| "independently reviewed" or "independently assessed" without a named reviewer and recorded review | Independence needs evidence (see `docs/GOVERNANCE.md`) |

A signature proves possession of a key and integrity of bytes. A claim must not describe a signature as proof of truthful execution, human identity, legal authority or independence.

## 5. Evidence required for a conformance claim

A conformance claim must be backed by a conformance report that follows `docs/CONFORMANCE.md` (`kya.conformance-report/v1`). The report must include:

1. the registry digest the claim is made under;
2. the implementation name, version and a release digest;
3. for each claimed ID, the result (`pass`, `fail`, `not-run` or `not-applicable`), the evidence class (`executed-test` or `portable-vector`) and the executed test or vector identifiers;
4. any declared subset, and the reason an ID is `not-applicable`;
5. every host-conditional trace that could not run, marked as not run;
6. the date the report was produced and the command used.

Additional rules:

- A trace in the reference implementation's own suite is not an independent claim. A second implementation makes its own claim.
- Host-conditional traces (KYA-INT-002 and KYA-INT-004) cannot count for a host that lacks the dependency.
- A claim is withdrawn when the registry digest changes in a way that affects the claimed ID, or when a passing vector is found to be wrong (see `VERSIONING.md` and `DECISION-PROCESS.md`).

## 6. Use of the name by others

1. Others may describe their software as "compatible with the KYA Evidence vectors for IDs X, Y" under section 3, with their own report.
2. A fork or derivative that changes normative behaviour must not present itself as KYA Evidence. It may say it is "derived from" the project, with a link to this repository and a list of the differences.
3. Use of the name in a product name, logo, domain or marketing requires the owner's written permission. Counsel should decide whether a policy with a licence is needed.
4. No logo or brand asset exists in this repository. Do not invent one.

## 7. Open questions for counsel

- Whether to seek trademark registration for the name, and in which jurisdictions.
- Who holds any registered mark, and how it transfers under the hand-over clause in `CHARTER.md`.
- The wording of the derivative-work rule in section 6.2 and whether it needs a licence.
- Whether third-party claims about "conformance" in marketing require a disclaimer or a takedown process.

See also: `CHARTER.md`, `IPR-POLICY.md`, `VERSIONING.md`, `../CONFORMANCE.md`, `../../SECURITY.md`.
