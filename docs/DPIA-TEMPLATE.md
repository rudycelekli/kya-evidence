# Data Protection Impact Assessment template for a KYA deployer

Status: Draft input for review by a qualified privacy professional. It is a structure to fill in, not legal advice, and a completed copy is not a compliance determination. Nothing here has been reviewed by counsel or a data protection authority. Which regime applies (for example GDPR, UK GDPR, CCPA, sector rules) and whether a DPIA is mandatory for your processing is for the deployer and its advisers to decide. Related: [PRIVACY.md](PRIVACY.md), [THREAT-MODEL.md](THREAT-MODEL.md).

How to use: copy this file into your own records, replace every bracketed prompt, mark each answer as Established (with a pointer to evidence), Assumed or Unknown, and have the privacy lead and the data protection officer (if any) sign off. Unknown answers stay visible; do not delete them.

## 1. Identification

| Item | Answer |
| :--- | :--- |
| Deployer (legal entity) | [name] |
| Role in this processing (controller, joint controller, processor) | [role] |
| Privacy lead, DPO, reviewer and date | [names, dates] |
| KYA version, profiles, suites and evaluator identity in use | [versions, digests] |
| Agent configurations assessed (manifest digests) | [list] |
| Version and date of this assessment | [version, date] |

## 2. Description of the processing

1. Purpose: what decision does the KYA assessment support, and who relies on it? [text]
2. Which artifacts are produced, stored, shared or published (manifests, evidence, assessments, incident records, dossiers, VC exports)? [list, with the data-flow table in PRIVACY.md section 2 as the baseline]
3. Where raw evidence is stored, who can read it, and for how long. [text]
4. Which parties receive each artifact (relying parties, assessors, anchoring services, auditors)? [list]
5. Any use of third-party model providers, capture environments or storage that process the raw material (processors and sub-processors). [list]
6. Transfers outside the jurisdiction. [text]

## 3. Data inventory

| Data category | Source | In signed artifacts? | In private raw material? | Identifies a person? | Special category? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Agent and scope labels | [source] | [yes/no] | [yes/no] | [direct/indirect/no] | [yes/no] |
| Principal and accountable-party references | [source] | | | | |
| Evaluation case inputs and agent outputs | [source] | | | | |
| Tool traces and logs | [source] | | | | |
| Incident narratives | [source] | | | | |
| Network, host and path metadata | [source] | | | | |
| Signing key identities | [source] | | | | |

Run `node scripts/privacy-scan.mjs` over the artifacts to be shared and attach the report. State its limits (PRIVACY.md section 3): a clean report does not show absence.

## 4. Lawful basis and transparency

For each category above: lawful basis or equivalent [text]; how people affected (users whose data appears in traces, personnel named as accountable parties) are informed [text]; whether consent is relied on and how it is withdrawn [text]. Legal analysis is for counsel.

## 5. Necessity and proportionality

- Is each field needed, or can a coded value or a salted commitment replace it? [text]
- Minimisation applied before hashing and signing (PRIVACY.md section 3). [text]
- Retention periods per material and the deletion mechanism (PRIVACY.md section 5). [text]
- How erasure and objection requests are handled given that signed published artifacts cannot be edited. [text]
- Accuracy: how wrong or stale assessments are corrected (expiry, incident and appeal records). [text]

## 6. Risks to individuals

Rate likelihood and severity as Low, Medium or High, with the reasoning, for each risk. Add rows.

| Risk | Likelihood | Severity | Existing measure | Residual |
| :--- | :--- | :--- | :--- | :--- |
| Personal data in a manifest label or principal ID is published | [rating] | [rating] | Scanner gate, review before signing | [rating] |
| Digest of a guessable value allows confirmation of an identity | | | Commitments with secret salt, omission | |
| Raw traces quoting users leak from the private directory | | | Permissions, retention, access log | |
| Accountable-party reference is re-identified | | | Pseudonym map access control and rotation | |
| Assessment is read as a judgment about a person | | | Wording rules, scope binding, expiry | |
| Incident record causes unfair consequence to a named person | | | Digest-only records, appeal process | |
| Capture environment metadata reveals staff or locations | | | Strip before building artifacts | |
| Access by an unintended recipient through a dossier | | | Sanitized projection, human authorization | |

## 7. Measures and safeguards

Technical: access control, encryption at rest and in transit, key management, scanner in CI, redaction order, commitments. [text]
Organisational: roles, training, review before publication, incident response, supplier due diligence. [text]
For each measure state who owns it and how it is verified. [text]

## 8. Consultation

Data subjects or their representatives consulted (or why not). Internal stakeholders. Supervisory authority consultation if high residual risk remains. [text]

## 9. Conclusion and sign-off

| Item | Answer |
| :--- | :--- |
| Residual risk accepted, mitigated further or processing not to proceed | [decision] |
| Conditions and actions with owners and dates | [list] |
| Review date and triggers for re-assessment (new profile, new recipients, new data categories, incident) | [text] |
| Sign-off: privacy professional | [name, date] |
| Sign-off: accountable executive | [name, date] |

Open items that remain Unknown stay listed here: [list]
