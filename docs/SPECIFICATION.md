# KYA Evidence specification, v0.1

Status: implemented experimental reference protocol. Independent security and standards-body review remain open. Normative requirements describe this implementation; they do not claim an adopted standard. Numbered requirements and their test traces are in [REQUIREMENTS.md](REQUIREMENTS.md).

## Purpose

Assess an exact agent configuration against a relying party's frozen policy for a declared scope, at a stated time. This is not human identity verification, an authorization grant, legal compliance, general safety or universal creditworthiness. `principal.id` is a pseudonymous controller reference. Never assign a person's creditworthiness or moral standing from this agent score.

The manifest declares; the profile freezes checks; receipts record outcomes; policy assigns trust and thresholds; assessment explains a decision. Keep declared, fixture-tested, runtime-observed and independently assessed evidence distinct.

## Records and bindings

| Record | Schema | Binding |
| :--- | :--- | :--- |
| Manifest | `kya.manifest/v1` | Agent, principal, full system, scope and validity interval |
| Profile | `kya.profile/v1` | ID, version, title and every frozen check/weight/critical flag |
| Policy | `kya.policy/v1` | Profile digest, scope, coverage/score/independence thresholds, optional mandatory minimums, source classes, freshness, trust anchors and revocations |
| Evidence | `kya.evidence/v1` | Subject, scope, profile, evaluator, run, check, artifact digest, outcome, source and validity interval |
| Assessment | `kya.assessment/v1` | Input digests, time, source mode, decision, score, dimensions, checks, rejections and limitations |
| Research universe | `kya.universe/v1` | All executable source bytes, package routing, frozen inputs/time, replayed assessment, source references, parent hypothesis and correction references |

Strict JSON rejects duplicate members, unsupported values, prototype keys, excessive resources and unknown schema fields. Canonicalization uses a bounded sorted-key JSON subset, not a claimed RFC 8785 implementation. SHA-256 digests are 64 lowercase hexadecimal characters. Timestamps are canonical UTC ISO strings.

The subject is the full-manifest digest. It binds harness/version, model, artifact/configuration digests, tool identities/versions/permissions and explicit scope. A manifest MAY declare `principal.accountableParty` as `{kind:'natural-person'|'legal-entity', ref}`, a pseudonymous reference to who answers for the agent; it admits no personal-data fields and an agent can never be its own accountable party. A policy MAY set `requirePrincipalBinding`; when true, a manifest without that declaration cannot qualify. The declaration is an unverified claim: it makes accountability inspectable and bound to the subject digest, and does not prove identity, authority or legal liability. Relying on an issuer's evidence never transfers the relying party's own accountability. Tool permissions must be allowed in scope. Allowed and forbidden permissions cannot overlap. Changing a manifest field creates a new subject and invalidates old evidence for it.

## Trust and eligibility

Receipt outcomes are `pass`, `fail`, `abstain`, `error`. Sources are `runtime`, `fixture`, `declaration`; declarations never satisfy scored checks. A response cannot elevate fixture origin to runtime origin. An Ed25519 proof authenticates bytes and key possession, not truthful observation.

Trust anchors and `self`/`independent` roles come from an out-of-band relying policy. A receipt cannot make its own key trusted or assign itself independence. Organizational independence remains an external assertion. Revocation covers subject digests, evidence IDs and key IDs, using a supplied policy snapshot.

Eligibility requires a valid proof, trusted non-revoked key, matching subject/scope/profile/evaluator/check, allowed observed source and valid time. Future, pre-manifest, expired and overly old evidence is rejected. Rejection reasons remain in the report. Eligible duplicate evidence IDs are quarantined; invalid untrusted copies cannot quarantine an otherwise trusted receipt.

## Run selection and qualification

Only the latest whole run is selected. Checks cannot be mixed from several runs. Correctly bound trusted receipts establish recency before duplicate quarantine, expiry, freshness and revocation exclusions; invalidating a newer failure cannot revive an older pass. Tied latest runs create ambiguity and cannot qualify; a selected critical failure still blocks. A frozen run has one evaluator key and one observation per check. Repeated checks or mixed issuers cannot qualify it. Critical failure remains visible across observation timestamps. Successful retries require a fresh complete run ID. Independent capture is still needed to detect omitted entire runs.

Every frozen check stays in the denominator. Unknown, abstained and errored checks earn zero points and no observed coverage. Pass and fail count as observed; only pass earns points. Critical failure blocks; critical unresolved checks withhold qualification. Revoked or invalid-time subjects cannot qualify. At least one known pass/fail is required even when thresholds are zero. Coverage, independence and score thresholds then apply. See [SCORING.md](SCORING.md). A policy MAY name `mandatoryMinimums` (`{checkId, minimum}` with `minimum` `pass` or `independent-pass`); an unmet minimum caps the decision at `blocked` whatever the score, and a declaration or a removed observation cannot satisfy one. Every withheld or capped result carries a stable machine-readable code (`blockerCodes`, one per blocker); see [ADR-0016](adr/0016-named-blocker-codes-and-mandatory-minimums.md).

`validUntil` is bounded by the manifest expiry, selected receipts and policy age cutoffs. Reassess using fresh policy revocations before reliance. Revocation is not a live lookup service.

## Reports and viewers

The report includes input digests, full-scope `scopeDigest`, `selectedRunId`, `ambiguousRuns`, every check, `acceptedEvidenceDigests`, rejection reasons and explicit limitations. `scopeDigest` hashes the entire manifest scope, including purpose and permissions. A readable scope ID alone is insufficient for comparison. Legacy assessments must be recomputed before new exact-scope comparisons. `blockers` lists human-readable reasons and `blockerCodes` the stable code for each, index for index; reports without `blockerCodes` remain valid. `reportDigest` is an unsigned checksum. `verify` returns checksum integrity with `authenticated:false`; an attacker can checksum false claims. Recompute from trusted original inputs to assess assurance.

A relying party SHOULD run `checkCurrency` (CLI `kya currency`) before each reliance. It compares the assessment against the current manifest, policy and clock and fires `subject-changed`, `policy-changed`, `subject-revoked`, `assessment-expired`, `assessment-aged` (optional policy `maxAssessmentAgeSeconds`) or `clock-regression`; each trigger also carries a stable `code`. Any trigger means reassess. It is the analogue of KYC ongoing monitoring for change events. It also accepts signed [incident records](adr/0014-signed-incident-and-appeal-records.md) (`kya.incident/v1`: report, resolution, appeal; digest-only, no narrative). A trusted unresolved high or critical report fires `incident-open`. Every distinct trusted report record is kept and a resolution may target a report only when exactly one report carries that ID, so duplicate or conflicting IDs fail closed. Only an independent policy-anchored key other than the reporter resolves a report, with a resolution dated strictly after it; a future-dated trusted blocking report stays open; and an appeal is recorded without clearing it. Ignored records are listed with reasons. It does not observe runtime behavior, an omitted incident is undetectable, and its result is unauthenticated. Continuous behavioral monitoring needs independent capture and remains open.

[Diagnostic dossiers](DOSSIERS.md) recompute the assessment and join originals to selected signed receipts. Replayed supported response predicates can support scoped strengths; signed assertions without matching originals remain reported passing claims. Failures preserve criticality without claiming a causal root cause. Missing telemetry, unresolved checks and seven structural observation limits remain visible. Standalone rendering validates consistency; trusted-input dossier verification recomputes the complete projection. Both remain unauthenticated without separate issuer/capture authority.

[Embedded benchmarks](BENCHMARKS.md) preserve 16 public fixture control cases and their complete expected populations. They challenge the evaluator and never measure commercial-agent competence or protected-holdout generalization.

The dashboard displays imported files as unverified claimed reports. Its presets use `kya.viewer-fixture/v1` and cannot masquerade as signed assessments. Raw observations and signed receipts are not embedded in the check list. Preserve authorized raw evidence privately, and redact before hashing public observation artifacts.

## Research replay and branching

[Universes](UNIVERSES.md) freeze all six assessment inputs including explicit time, current implementation inventory, computed report, question and source references. Forks clone inputs and name their parent and hypothesis. Verification recomputes the complete assessment under the matching archived implementation. Parent/correction graphs detect missing references and expose affected descendants; correction references remain declarations separate from revocation authority. Hash equality proves matching bytes, not who issued them, when they existed or whether observations were truthful. Comparisons require compatible complete populations and make no causal improvement claim.

## Interoperability and versioning

This is not an official implementation of Open-KYA, W3C VC, A2A or MCP. Credential/discovery bridges must preserve exact input digests, source class and limits. Compatibility needs executable multi-implementation tests. Alpha schema changes require explicit versioning and migration notes. Invalid top-level input fails; invalid individual receipts become rejections. Determinism requires frozen time and input files.
