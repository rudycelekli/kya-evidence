Draft input for practitioner and legal review. Not legal advice. Not a compliance claim.

# Crosswalk: SOC 2 trust services criteria

Scope: the Common Criteria groups CC1 to CC9 and the additional categories Availability (A1), Confidentiality (C1) and Processing Integrity (PI1). Only group-level identifiers and topics, taken from secondary summaries, are used; individual criterion numbers such as CC7.2 and their points of focus were NOT verified and are not cited. NO primary text was read. Every row needs primary re-check. A SOC 2 report is an attestation by a licensed practitioner about a service organization system and controls over a period; a KYA assessment is about one agent configuration and is not a substitute for, or an input that makes, such a report.

Source: https://linfordco.com/blog/2017-tsp-section-100-trust-services-criteria-soc-2/ and https://www.vanta.com/resources/soc-2s-trust-service-criteria (secondary); authority is the AICPA document "2017 Trust Services Criteria with Revised Points of Focus 2022" (TSP section 100), not fetched

Status meanings: `supports as input` means a KYA artifact can be one input to the evidence a practitioner assembles for the clause; `partial` means it addresses one aspect only; `not addressed` means KYA has no artifact for it. None of these states means the clause is met.

| Framework clause or control | Basis | KYA input evidence | What KYA does NOT show | Status |
| :--- | :--- | :--- | :--- | :--- |
| CC1 control environment (integrity, oversight, accountability) | secondary; needs primary re-check | Accountable party reference (KYA-PRN-001, KYA-PRN-002) | Tone at the top, board oversight or HR practices | `not addressed` |
| CC2 communication and information | secondary; needs primary re-check | Reports state limits and blind spots (KYA-RPT-003) | Internal or external communication of control information | `partial` |
| CC3 risk assessment (objectives, risk identification, fraud, change) | secondary; needs primary re-check | Frozen policy-relative assessment (KYA-SCO-001); any manifest change invalidates evidence (KYA-BND-001) | The organization risk assessment, fraud risk or change impact analysis | `partial` |
| CC4 monitoring activities (ongoing evaluations, communication of deficiencies) | secondary; needs primary re-check | Reassessment triggers (KYA-MON-001); incident records (KYA-INC-001, KYA-INC-004) | An organization monitoring programme or deficiency tracking to resolution | `partial` |
| CC5 control activities (selection and development of controls, policies) | secondary; needs primary re-check | Policy templates with explicit limits (KYA-ACT-005); CI gate (KYA-ACT-001) | Control design and deployment across the organization | `partial` |
| CC6 logical and physical access controls | secondary; needs primary re-check | Signature and key trust checks apply to KYA records only (KYA-TRU-001, KYA-TRU-002); manifest permissions (KYA-BND-002) | Access control to systems, physical access, or whether the assessed agent permissions are enforced at runtime | `not addressed` |
| CC7 system operations (detection of anomalies, incident response and recovery) | secondary; needs primary re-check | Signed incident records with independent resolution (KYA-INC-001, KYA-INC-003); reassessment on unresolved incident (KYA-INC-002) | Detection tooling, response procedures or recovery testing | `partial` |
| CC8 change management | secondary; needs primary re-check | Any manifest field change invalidates evidence (KYA-BND-001); evaluator digest pin (KYA-EVL-001) | The change management process, approvals or testing of changes in production | `partial` |
| CC9 risk mitigation (business disruption, vendor and partner risk) | secondary; needs primary re-check | Reliance never transfers accountability (docs/research/2026-10-14-kyc-to-kya-controls.md); trust roles by policy (KYA-TRU-001) | Vendor management programme or business continuity | `not addressed` |
| A1 availability | secondary; needs primary re-check | None | Anything about capacity, backup or recovery of the assessed system | `not addressed` |
| C1 confidentiality | secondary; needs primary re-check | Raw evidence kept private, only authorized sanitized artifacts published (AGENTS.md); private directory handling (KYA-CMP-017) | Confidentiality classification, retention or disposal of customer data | `partial` |
| PI1 processing integrity (complete, valid, accurate, timely processing) | secondary; needs primary re-check | Deterministic canonicalization and digests (KYA-INT-001, KYA-INT-003); complete check populations (KYA-BND-003) | That the assessed system processes customer data completely and accurately | `partial` |

