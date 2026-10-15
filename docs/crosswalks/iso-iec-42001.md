Draft input for practitioner and legal review. Not legal advice. Not a compliance claim.

# Crosswalk: ISO/IEC 42001:2023 AI management system

Scope: management system clauses and Annex A objective groups. The standard text is paywalled and the ISO page could not be fetched, so NO primary text was read. Clause titles follow the common ISO management system structure and Annex A objective topics come from secondary summaries, which disagree on control counts. Individual Annex A control numbers were deliberately not used because they could not be verified; where a sub-control matters it is described by topic. Every row needs primary re-check against the licensed standard. ISO/IEC 42001 certifies an organization management system; a KYA assessment is about one agent configuration and is not an input to a certificate on its own.

Source: https://www.iso.org/standard/81230.html (HTTP 403 when fetched); secondary summaries found by search: https://riskprofs.com/iso-42001-annex-a-controls-list/ and https://docs.modulos.ai/frameworks/iso-42001/annexes-a-d.html

Status meanings: `supports as input` means a KYA artifact can be one input to the evidence a practitioner assembles for the clause; `partial` means it addresses one aspect only; `not addressed` means KYA has no artifact for it. None of these states means the clause is met.

| Framework clause or control | Basis | KYA input evidence | What KYA does NOT show | Status |
| :--- | :--- | :--- | :--- | :--- |
| Clause 4 context of the organization (interested parties, scope of the AI management system) | secondary; needs primary re-check | Manifest scope and full-scope digest for one agent (KYA-BND-001, KYA-BND-003) | Organization context, interested parties or management system scope | `partial` |
| Clause 5 leadership and AI policy | secondary; needs primary re-check | Accountable party reference (KYA-PRN-001); governance documents (docs/GOVERNANCE.md, KYA-GOV-001) | Top management commitment or an organizational AI policy; KYA governance documents govern the KYA project only | `not addressed` |
| Clause 6 planning: AI risk assessment, treatment, AI system impact assessment, objectives | secondary; needs primary re-check | Frozen policy-relative assessment (KYA-SCO-001, KYA-SCO-002) | The organization risk assessment method, treatment decisions or impact assessment on people | `partial` |
| Clause 7 support: resources, competence, awareness, documented information | secondary; needs primary re-check | Signed, digest-bound records usable as controlled documented information (KYA-INT-003) | Competence, awareness, or document control procedures | `partial` |
| Clause 8 operation: operational planning and control, risk assessment and treatment in operation | secondary; needs primary re-check | Currency checks and triggers while operating (KYA-MON-001) | Operational controls of the organization | `partial` |
| Clause 9 performance evaluation: monitoring and measurement, internal audit, management review | secondary; needs primary re-check | Reassessment triggers (KYA-MON-001); conformance report of the KYA reference itself (KYA-CNF-001) | Internal audit programme or management review; a conformance report concerns an implementation of KYA, not an organization | `partial` |
| Clause 10 improvement: nonconformity, corrective action, continual improvement | secondary; needs primary re-check | Signed incident records and correction lineage (KYA-INC-001, KYA-INC-003, KYA-UNI-002) | Corrective action management by the organization | `partial` |
| Annex A policies related to AI | secondary; needs primary re-check | None | Any organizational AI policy | `not addressed` |
| Annex A internal organization (roles, responsibilities, reporting of concerns) | secondary; needs primary re-check | Accountable party reference (KYA-PRN-001, KYA-PRN-002) | Roles, authorities or a concern reporting channel | `partial` |
| Annex A resources for AI systems (data, tooling, compute, people) | secondary; needs primary re-check | Manifest lists tools, model and artifacts (KYA-BND-001) | Resource adequacy or data resources | `partial` |
| Annex A assessing impacts of AI systems (impact assessment process and documentation) | secondary; needs primary re-check | None. KYA has no impact assessment artifact | Any impact assessment | `not addressed` |
| Annex A AI system life cycle, including testing, verification and event logging by topic | secondary; needs primary re-check | Frozen suites and control catalog (KYA-CON-001, KYA-BEN-001); runtime versus fixture origin (KYA-TRU-003). No system event log artifact | Design and development process, deployment planning, operation and system event logs | `partial` |
| Annex A data for AI systems (data quality, provenance, preparation) | secondary; needs primary re-check | None | Anything about training or input data | `not addressed` |
| Annex A information for interested parties (documentation for users, incident communication) | secondary; needs primary re-check | Assessment report and dossier with stated limits (KYA-RPT-002, KYA-RPT-003) | User-facing documentation or external reporting channels | `partial` |
| Annex A use of AI systems (responsible use, intended use objectives) | secondary; needs primary re-check | Policy templates state rationale and limits (KYA-ACT-005) | How the deployer uses the system | `not addressed` |
| Annex A third-party and customer relationships (suppliers, customers, responsibility allocation) | secondary; needs primary re-check | Trust roles by policy (KYA-TRU-001); credential binds agent by digest (KYA-VCB-001) | Contracts, supplier evaluation or allocation of responsibilities | `partial` |

