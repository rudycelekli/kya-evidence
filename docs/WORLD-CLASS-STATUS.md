# World-class plan status

Generated from [evidence/world-class-status.json](../evidence/world-class-status.json) by `node scripts/world-class-status.mjs --write`. Last updated 2026-10-15.

An item is verified only when linked evidence of the right kind exists: a requirement, test or file for CI verification, and a named outside party with an https link and a date for external review, independent implementation or real use. Work that needs an outside party cannot be marked verified on internal evidence.

Totals: 34 items; 19 planned, 7 in progress, 5 implemented, 3 verified. Items that need an outside party: 11; verified by an outside party: 0.

## WS1 Narrow, precise problem

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS1-01 Problem statement and explicit non-goals (README states what this is not; no standalone one-page statement yet) | in progress |  | `README.md`, `docs/SPECIFICATION.md` |  |
| WS1-02 Machine-readable claim-boundary codes on every artifact | planned |  |  |  |
| WS1-03 Comprehension test with three outside readers | planned |  |  | yes |

## WS2 Core plus profiles

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS2-01 Conservative policy templates for three use cases (thresholds are unvalidated starting points) | implemented |  | `test/policy-templates.test.mjs`, `docs/POLICY-TEMPLATES.md` |  |
| WS2-02 Scenario suite family with synthetic incident reconstructions (no external fidelity review) | implemented |  | `test/suites.test.mjs`, `docs/adr/0023-scenario-suites-and-holdout-commitments.md` |  |
| WS2-03 Profile specification and registry rules | planned |  |  |  |
| WS2-04 Domain-expert sign-off for each flagship profile | planned |  |  | yes |

## WS3 Two independent implementations

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS3-01 Golden assessment vectors for assessment semantics (Lane K) | in progress |  |  |  |
| WS3-02 Byte-level canonical and signature vectors, JavaScript and Python (team-built Python checker, restricted subset) | VERIFIED | CI | `KYA-INT-003`, `KYA-INT-004` |  |
| WS3-03 Implementer's guide and language-neutral harness | planned |  |  |  |
| WS3-04 Two outside implementations pass all normative vectors | planned |  |  | yes |

## WS4 Neutral governance

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS4-01 Draft charter, IPR, claims, versioning, extension and decision documents (drafts for counsel, not adopted) | in progress |  | `docs/GOVERNANCE.md` |  |
| WS4-02 Legal counsel review of IPR and trademark drafts | planned |  |  | yes |
| WS4-03 Neutral home chosen and charter ratified by three independent organisations | planned |  |  | yes |

## WS5 Threat model and external security review

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS5-01 Dependency-free property and fuzz test suite | VERIFIED | CI | `test/property-canonical.test.mjs`, `test/property-assessment.test.mjs` |  |
| WS5-02 Mutation controls over security gates, run in CI (targeted gates only) | VERIFIED | CI | `scripts/mutation-check.mjs`, `test/evaluator-identity.test.mjs` |  |
| WS5-03 Formal threat model, cryptographic agility plan and supply-chain hardening | in progress |  | `docs/THREAT-MODEL.md` |  |
| WS5-04 Two commissioned external reviews with retest | planned |  |  | yes |

## WS6 Interop with incumbents

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS6-01 W3C VC 2.0 export with Bitstring Status List (not checked with an external VC library) | implemented |  | `test/vc-bridge.test.mjs`, `docs/adr/0022-vc-export-bridge.md` |  |
| WS6-02 in-toto predicate, OpenTelemetry conventions, OAuth and SPIFFE bindings, A2A and MCP metadata | planned |  |  |  |
| WS6-03 A third-party tool consumes each exported format | planned |  |  | yes |

## WS7 Regulator, auditor and insurer mapping

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS7-01 KYC-to-agent control research note (several primary texts still unfetched) | in progress |  | `docs/research/2026-10-14-kyc-to-kya-controls.md` |  |
| WS7-02 Crosswalks to the EU AI Act, ISO/IEC 42001, NIST AI RMF and SOC 2 | in progress |  |  |  |
| WS7-03 Practitioner and legal review of each crosswalk | planned |  |  | yes |

## WS8 Assessor accountability and appeals

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS8-01 Signed incident, resolution and appeal records (appeals are recorded but cannot reopen a resolution) | implemented |  | `test/incidents.test.mjs`, `docs/adr/0014-signed-incident-and-appeal-records.md` |  |
| WS8-02 Assessor independence criteria, conflict-of-interest records, accreditation | planned |  |  |  |
| WS8-03 Two assessors cross-assess one agent; an appeal is exercised end to end | planned |  |  | yes |

## WS9 Privacy by design

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS9-01 Digest-only records with no personal-data fields | in progress |  | `test/incidents.test.mjs` |  |
| WS9-02 Selective disclosure, DPIA template, automated personal-data leak check | planned |  |  |  |
| WS9-03 External privacy review and completed DPIA | planned |  |  | yes |

## WS10 Real usage data and a feedback loop

| Item | Status | Verifier | Evidence | Needs outsiders |
| :--- | :--- | :--- | :--- | :--- |
| WS10-01 Campaign harness with a signed planned-attempt ledger (ledger slice of ADR-0017 only) | implemented |  | `test/campaign-ledger.test.mjs`, `docs/adr/0021-capture-issuer-role-and-campaign-ledger.md` |  |
| WS10-02 Private campaign on three agent configurations (needs explicit owner go-ahead before any real vendor run) | planned |  |  |  |
| WS10-03 Three relying-party pilots with written case studies | planned |  |  | yes |
| WS10-04 Pre-registered prospective calibration study design | planned |  |  |  |
