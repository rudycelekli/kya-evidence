# Plan: from reference implementation to a standard that others adopt

Status: plan, not a specification. Date: 2026-10-14. Owner decisions recorded in the project memory apply (private pilot first; no publication or vendor naming without explicit go-ahead).

**Rule for this plan.** An item is *verified* only when it links evidence a third party could re-check: a CI run, a published report, a signed conformance report, or a named external reviewer's written findings. Saying so is not evidence. Items that need outsiders are marked **EXT**; this plan will not mark them done on internal work alone.

## How "verified and ready" is defined

| Verifier | Meaning | Examples |
| :--- | :--- | :--- |
| **CI** | A repository check fails if it regresses | traced requirements, mutation controls, conformance report, property tests |
| **XREV** | A named person or organisation outside the maintainers reviewed it and their written report is linked | security review, domain-expert review, legal review |
| **XIMP** | An implementation by another team passes the published vectors | second implementation |
| **XUSE** | A relying party or assessor used it on a real case and a written case study exists | pilots |

## The ten work-streams

### WS1 Narrow, precise problem (today: Good)
Target: a reader outside the project can restate in one minute what KYA claims and does not claim.
Deliverables: one-page problem statement and explicit non-goals; defined-term glossary with RFC 2119/8174 usage; "what a KYA result is not" statement attached to every artifact as machine-readable claim-boundary codes (this is cheap and high value); scope freeze and stability levels for v1.0.
Verified by: CI (every requirement traced; claim-boundary codes present on all artifacts) and XREV (a comprehension test: three outside readers restate the scope without error).

### WS2 Core plus profiles (today: Partial)
Target: a profile mechanism and three flagship profiles that domain experts accept.
Deliverables: profile specification (frozen checks, policy template, scenario suite, evaluator digest, minimum capture tier, minimum independence class); profile registry rules; flagship profiles for code agents, agentic payments, and read-only enterprise assistants, built with the scenario-suite and policy-template lanes; per-profile golden vectors.
Verified by: CI (each profile has vectors and templates validating) and XREV (one domain expert signs off each profile's checks and thresholds as reasonable starting points).

### WS3 Two independent implementations (today: team-built byte subset only)
Target: at least two implementations by different teams pass 100% of normative vectors.
Deliverables: **golden assessment vectors** (inputs to expected report digests, including adversarial cases), because today's vectors cover bytes and signatures, not assessment semantics; an implementer's guide; a language-neutral conformance harness using the conformance-report format; an internal clean-room third-language implementation written from the spec only, to flush ambiguity (labelled not independent); an outreach and incentive plan (grants or bounties) for outside implementers.
Verified by: CI (vectors, harness) and **XIMP** (two outside implementations pass; every disagreement is logged and resolved in an ADR). **EXT.**

### WS4 Neutral governance (today: Missing)
Target: a neutral home, an IPR policy and a decision process that no single vendor controls.
Deliverables: governance charter; contributor policy (DCO); IPR and trademark policy (royalty-free patent commitment); versioning and deprecation policy; namespaced extension registry; RFC-style change process with named editors; decision matrix for a home (W3C Community Group, DIF working group, a foundation project) and an outreach plan.
Verified by: XREV (legal counsel reviews the policies) and an adopted charter ratified by at least three independent organisations. **EXT.**

### WS5 Threat model and external security review (today: threat model yes, review none)
Target: published reviews, all critical and high findings closed with regression tests.
Deliverables: formal threat model (trust boundaries, assumptions registry, abuse cases); cryptographic agility plan (Ed25519 now, JCS/RFC 8785 alignment decision, domain-separation audit, post-quantum migration note); release supply-chain hardening (signed tags, provenance, SBOM); vulnerability disclosure policy; two commissioned reviews (protocol and cryptography; implementation); retest.
Verified by: CI (property and fuzz suite, mutation controls) and **XREV** (published reports plus retest). **EXT.** All of this code was largely written with AI assistance, so human expert review is not optional.

### WS6 Interop with incumbents (today: VC bridge in progress)
Target: each bridge has a mapping table, round-trip tests and one outside consumer.
Deliverables: W3C VC 2.0 export (in progress) plus SD-JWT selective disclosure; an in-toto attestation predicate type; OpenTelemetry semantic conventions for capture events; OAuth/OIDC and SPIFFE bindings for runtime identity; A2A agent-card and MCP metadata extensions; crosswalk with the DIF KYA-OS work; published JSON Schemas and a JSON-LD context.
Verified by: CI (round trips) and XUSE (a third-party tool consumes each format). Do not fork incumbents; contribute where they exist.

### WS7 Regulator, auditor and insurer mapping (today: Missing)
Target: crosswalks that an auditor can use without a project member in the room.
Deliverables: control crosswalks to the EU AI Act, ISO/IEC 42001, NIST AI RMF and SOC 2 criteria, each with a gap column; an auditor's guide for assessing with KYA evidence; an insurer data specification. Every mapping needs primary-source text fetched and cited (several regulatory sources are still unverified in this repository).
Verified by: XREV (at least one named practitioner reviews each crosswalk) and a legal review of wording. **EXT.**

### WS8 Assessor accreditation, conflict of interest, appeals (today: appeals and incidents begun)
Target: independence is a defined, auditable property and not an assertion.
Deliverables: assessor independence criteria (organisational, financial, tooling); a signed conflict-of-interest declaration record; a tiered accreditation scheme; proficiency tests; an appeals process with timelines and an independent panel; right of reply before publication; inter-assessor reliability measurement.
Verified by: XUSE (two assessors cross-assess the same agent, agreement analysis published, one appeal run end to end). **EXT.**

### WS9 Privacy by design (today: Partial)
Target: privacy is a testable property.
Deliverables: data-flow inventory and DPIA template; selective disclosure (SD-JWT); redaction-before-hash tooling; retention and deletion rules; an automated personal-data leak check in CI; legal review for GDPR and similar regimes.
Verified by: CI (leak check, traced privacy requirements) and XREV (privacy review, completed DPIA). **EXT.**

### WS10 Real usage data and a feedback loop (today: None)
Target: evidence that the standard works on real cases, and a way to learn from it.
Deliverables: a private campaign on at least three agent configurations using the campaign harness and ledger; at least three relying-party design partners with a pilot kit; an opt-in, no-telemetry outcome-reporting protocol; a pre-registered, prospective calibration study design (predictive validity is stage 7 and is not claimed); an errata process.
Verified by: XUSE (written case studies) and a pre-registered analysis plan published before results. **EXT.**

## Sequencing

| Phase | Window | Focus |
| :--- | :--- | :--- |
| 0 | now to 4 weeks | Finish the four lanes in flight; golden assessment vectors (WS3); claim-boundary codes (WS1); threat model draft (WS5); governance and IPR drafts (WS4); shortlist reviewers and a possible home |
| 1 | 1 to 3 months | Capture cell and tiers (ADR-0017); flagship profiles (WS2); interop bridges (WS6); private pilot (WS10); crosswalk drafts (WS7); privacy tooling (WS9) |
| 2 | 3 to 9 months | External reviews and fixes (WS5); outside implementer programme (WS3); design partners; governance home decision (WS4); assessor pilot (WS8) |
| 3 | 9 to 18 months | v1.0 with stability levels; venue submission; calibration study results; published case studies |

Critical path: golden assessment vectors, then outside implementers; the security review and governance home gate any adoption claim.

## Premortem: how this fails

| Failure | Mitigation |
| :--- | :--- |
| Nobody builds a second implementation | Self-contained spec, assessment vectors, grants or bounties, a small required subset first |
| A single vendor captures governance, or none forms | Choose a neutral home early; multi-organisation charter before v1.0 |
| The result is used as a badge after its evidence expired | Expiry, exact-scope binding, claim-boundary codes, no universal score |
| Agents are tuned to the public suite | Protected holdouts with commit-reveal, rotation, evaluation-awareness runs |
| Legal exposure from naming vendors | Counsel review, vendor right of reply, private first, no ranking |
| Scope creep makes the core unreviewable | Keep the core small; put variety in profiles |
| A flaw surfaces after adoption | Early external review, bounty, evaluator-identity pinning and revocation |
| Incumbent standards move first | Build interop first; contribute to existing efforts instead of forking |
| Bus factor and AI-written code nobody understands | Recruit human maintainers; human review of every security-relevant module |

## What needs the owner

Budget for two external reviews and a possible bounty; legal counsel for governance, privacy and publication; introductions to implementers, design-partner relying parties and a standards venue; explicit go-ahead before any real vendor run or publication.

## Tracking

Status lives in this document's tables until a machine-readable ledger (`evidence/world-class-status.json`, with a CI rule that "verified" requires a linked evidence artifact) is built; that ledger is the first deliverable of Phase 0. Until then, no stream is described as complete.
