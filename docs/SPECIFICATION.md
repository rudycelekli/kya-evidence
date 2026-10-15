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

Records are digest-only and carry no personal-data fields. [PRIVACY.md](PRIVACY.md) describes the data flow, redaction before hashing and a scanner (`scripts/privacy-scan.mjs`); a clean scan is not evidence that no personal data is present.

## Trust and eligibility

Receipt outcomes are `pass`, `fail`, `abstain`, `error`. Sources are `runtime`, `fixture`, `declaration`; declarations never satisfy scored checks. A response cannot elevate fixture origin to runtime origin. An Ed25519 proof authenticates bytes and key possession, not truthful observation.

Trust anchors and `self`/`independent` roles come from an out-of-band relying policy. A receipt cannot make its own key trusted or assign itself independence. Organizational independence remains an external assertion. Revocation covers subject digests, evidence IDs and key IDs, using a supplied policy snapshot.

Eligibility requires a valid proof, trusted non-revoked key, matching subject/scope/profile/evaluator/check, allowed observed source and valid time. Future, pre-manifest, expired and overly old evidence is rejected. Rejection reasons remain in the report. Eligible duplicate evidence IDs are quarantined; invalid untrusted copies cannot quarantine an otherwise trusted receipt.

Assessor standing is advisory. A signed assessor disclosure (`kya.assessor-disclosure/v1`, [ADR-0028](adr/0028-assessor-disclosure.md)) lets a relying party check whether a key it assigned the `independent` role has declared and kept clear of conflicts, but it does not alter an assessment result and the criteria in [ASSESSOR-INDEPENDENCE.md](ASSESSOR-INDEPENDENCE.md) and [ACCREDITATION.md](ACCREDITATION.md) are drafts. Standing proves only that a key signed a disclosure, not that it is true.

## Run selection and qualification

Only the latest whole run is selected. Checks cannot be mixed from several runs. Correctly bound trusted receipts establish recency before duplicate quarantine, expiry, freshness and revocation exclusions; invalidating a newer failure cannot revive an older pass. Tied latest runs create ambiguity and cannot qualify; a selected critical failure still blocks. A frozen run has one evaluator key and one observation per check. Repeated checks or mixed issuers cannot qualify it. Critical failure remains visible across observation timestamps. Successful retries require a fresh complete run ID. Independent capture is still needed to detect omitted entire runs; a proposed design is in [ADR-0017](adr/0017-measured-signed-capture-attestation.md) and [ADR-0020](adr/0020-external-anchoring-of-evidence-bundles.md) (not implemented).

Every frozen check stays in the denominator. Unknown, abstained and errored checks earn zero points and no observed coverage. Pass and fail count as observed; only pass earns points. Critical failure blocks; critical unresolved checks withhold qualification. Revoked or invalid-time subjects cannot qualify. At least one known pass/fail is required even when thresholds are zero. Coverage, independence and score thresholds then apply. See [SCORING.md](SCORING.md). A policy MAY name `mandatoryMinimums` (`{checkId, minimum}` with `minimum` `pass` or `independent-pass`); an unmet minimum caps the decision at `blocked` whatever the score, and a declaration or a removed observation cannot satisfy one. Every withheld or capped result carries a stable machine-readable code (`blockerCodes`, one per blocker); see [ADR-0016](adr/0016-named-blocker-codes-and-mandatory-minimums.md).

`validUntil` is bounded by the manifest expiry, selected receipts and policy age cutoffs. Reassess using fresh policy revocations before reliance. Revocation is not a live lookup service.

## Reports and viewers

The report includes input digests, full-scope `scopeDigest`, `selectedRunId`, `ambiguousRuns`, every check, `acceptedEvidenceDigests`, rejection reasons and explicit limitations. `scopeDigest` hashes the entire manifest scope, including purpose and permissions. A readable scope ID alone is insufficient for comparison. Legacy assessments must be recomputed before new exact-scope comparisons. `blockers` lists human-readable reasons and `blockerCodes` the stable code for each, index for index; reports without `blockerCodes` remain valid. `reportDigest` is an unsigned checksum. `verify` returns checksum integrity with `authenticated:false`; an attacker can checksum false claims. Recompute from trusted original inputs to assess assurance.

A relying party SHOULD run `checkCurrency` (CLI `kya currency`) before each reliance. It compares the assessment against the current manifest, policy and clock and fires `subject-changed`, `policy-changed`, `subject-revoked`, `assessment-expired`, `assessment-aged` (optional policy `maxAssessmentAgeSeconds`) or `clock-regression`; each trigger also carries a stable `code`. Any trigger means reassess. It is the analogue of KYC ongoing monitoring for change events. It also accepts signed [incident records](adr/0014-signed-incident-and-appeal-records.md) (`kya.incident/v1`: report, resolution, appeal; digest-only, no narrative). A trusted unresolved high or critical report fires `incident-open`. Every distinct trusted report record is kept and a resolution may target a report only when exactly one report carries that ID, so duplicate or conflicting IDs fail closed. Only an independent policy-anchored key other than the reporter resolves a report, with a resolution dated strictly after it; a future-dated trusted blocking report stays open; and an appeal is recorded without clearing it. Ignored records are listed with reasons. It does not observe runtime behavior, an omitted incident is undetectable, and its result is unauthenticated. Continuous behavioral monitoring needs independent capture and remains open.

[Diagnostic dossiers](DOSSIERS.md) recompute the assessment and join originals to selected signed receipts. Replayed supported response predicates can support scoped strengths; signed assertions without matching originals remain reported passing claims. Failures preserve criticality without claiming a causal root cause. Missing telemetry, unresolved checks and seven structural observation limits remain visible. Standalone rendering validates consistency; trusted-input dossier verification recomputes the complete projection. Both remain unauthenticated without separate issuer/capture authority.

[Embedded benchmarks](BENCHMARKS.md) preserve 16 public fixture control cases and their complete expected populations. They challenge the evaluator and never measure commercial-agent competence or protected-holdout generalization.

The dashboard displays imported files as unverified claimed reports. Its presets use `kya.viewer-fixture/v1` and cannot masquerade as signed assessments. Raw observations and signed receipts are not embedded in the check list. Preserve authorized raw evidence privately, and redact before hashing public observation artifacts.

### Currency result layout and reason vocabulary

A `kya.currency/v1` result has exactly these members: `schema`, `assessmentDigest` (the assessment's `reportDigest`), `checkedAt` (the check time as ISO UTC), `current` (true only when no trigger fired), `reliable` (`current` and the assessment decision is `qualified`), `action` (`reassess` when any trigger fired, else `none`), `triggers` (entries `{id, code, detail}` in firing order), `incidents`, `authenticated` (always false) and `limits`. `incidents` has `considered`, `open`, `resolved`, `appealed`, `observed` and `ignored`; the ID lists are de-duplicated and sorted, and `ignored` entries `{id, reason}` are sorted by `id` (null as empty) then `reason`. `limits` holds four fixed strings. Trigger detail strings are informational; branch on `code`.

Trigger firing order is: `clock-regression`, `subject-changed`, `policy-changed`, `subject-revoked`, `assessment-expired`, `assessment-aged`, `incident-open`.

Trigger `detail` strings feed the result digest and are fixed: `clock-regression` `Check time precedes the assessment time`; `subject-changed` `Manifest no longer matches the assessed subject digest`; `policy-changed` `Relying policy differs from the assessed policy`; `subject-revoked` `Subject digest is revoked by the supplied policy`; `assessment-expired` `Assessment validity interval has ended`; `assessment-aged` `Assessment is older than the policy maximum age`; `incident-open` `<n> unresolved high or critical incident record(s) for this subject`, where `<n>` is the decimal count of open incident IDs. The four `limits` strings, in order, are: `Detects change against supplied manifest, policy and clock only; it does not observe runtime behavior`; `Report checksum is unauthenticated; recompute from trusted inputs before reliance`; `Incident records are trusted only through the supplied policy anchors; an omitted incident is undetectable`; `A passing check is not an authorization grant`.

An assessment's `limitations` holds, in order, `Local policy result; not an authorization grant`, `Signatures attest bytes and key possession, not truthful execution` and `No universal predictive validation; public suites can be gamed`, followed by `Includes synthetic fixture evidence; not a real product benchmark` only when the evidence mode is `fixture` or `mixed`.

Reasons for `rejectedEvidence` entries (`{index, id, reason}`, sorted by `index`; `id` is null when the record never passed shape and signature validation, and is the record's own ID otherwise; because identifiers are at most 128 characters no cut applies to a valid record). A record gets the first reason that applies, in this order: a capture error text; any shape or signature failure text; `Signer is not a relying-party trust anchor`; `A capture-issuer key cannot issue scoring evidence`; `Subject is revoked`; `Subject is expired`; `Subject is not yet issued`; `Exact system digest differs`; `Evidence scope differs`; `Frozen profile differs`; `Evaluator digest differs`; `Evidence check is outside frozen profile`; `A declaration cannot satisfy an observed check`; `Evidence source is disallowed`; `Observation is in the future`; `Observation predates manifest`; `Signing key is revoked`; `Evidence is revoked`; `Evidence is expired`; `Evidence exceeds freshness policy`. After that, `Duplicate evidence ID`, `Equally recent run excluded; ambiguous runs cannot qualify`, `Older run excluded; checks cannot be mixed across runs` and `Superseded observation within selected run` apply to otherwise eligible records.

Recency of a run counts every receipt that was authentic and correctly bound, including revoked, expired and stale ones, so that invalidating a failure cannot resurrect an older pass. A receipt that fails any check before the `Observation is in the future` check, or that is itself future-dated or predates the manifest, never counts toward recency.

Reasons for `incidents.ignored` entries: `Invalid incident record: <detail>` (id null), `Signing key is not a trusted anchor`, `Signing key is revoked`, `Incident concerns a different subject`, `Conflicting records share an ID; reports kept open, resolutions cannot target them`, `Conflicting records share one key and ID; not honoured`, `Incident is dated in the future`, `Blocking incident is dated in the future (clock skew or misdated); kept open`, `Ambiguous reference: several reports share this ID`, `References unknown incident`, `Resolution requires an independent trusted key`, `Reporter cannot resolve its own report` and `Resolution must be dated after the incident`.

Within the incident reasons, a record gets the first that applies in this order: `Invalid incident record`, `Signing key is not a trusted anchor`, `Signing key is revoked`, `Incident concerns a different subject`; a record that passes these is then judged by the shared-ID, future-date and resolution reasons in the order listed above. An exact duplicate record (same envelope digest) counts toward `considered` but is otherwise skipped and never listed.

Validator grammars: an identifier is 1 to 128 characters of the form `[A-Za-z0-9][A-Za-z0-9:._/-]*`; text is 1 to 512 characters (unless a field says otherwise) with no control characters, except that a public key field holds a PEM SPKI public key of at most 2000 characters with line breaks and is validated by its own rule; a hash is 64 lowercase hexadecimal characters; a timestamp is the exact `YYYY-MM-DDTHH:MM:SS.mmmZ` form that round-trips through `Date#toISOString`.

Bindings that export an assessment into other ecosystems (in-toto, OpenTelemetry-style attributes, OAuth claims, SPIFFE, A2A and MCP metadata) are described in [INTEROP-BRIDGES.md](INTEROP-BRIDGES.md). They are unsigned, fail closed on non-qualified or non-current input, claim no conformance with the target specifications and have not been consumed by any third-party tool.

## Research replay and branching

[Universes](UNIVERSES.md) freeze all six assessment inputs including explicit time, current implementation inventory, computed report, question and source references. Forks clone inputs and name their parent and hypothesis. Verification recomputes the complete assessment under the matching archived implementation. Parent/correction graphs detect missing references and expose affected descendants; correction references remain declarations separate from revocation authority. Hash equality proves matching bytes, not who issued them, when they existed or whether observations were truthful. Comparisons require compatible complete populations and make no causal improvement claim.

## Interoperability and versioning

This is not an official implementation of Open-KYA, W3C VC, A2A or MCP. Credential/discovery bridges must preserve exact input digests, source class and limits. Compatibility needs executable multi-implementation tests. Alpha schema changes require explicit versioning and migration notes. Invalid top-level input fails; invalid individual receipts become rejections. Determinism requires frozen time and input files.

Claim-boundary codes classify the limit statements an artifact carries ([CLAIM-BOUNDARIES.md](CLAIM-BOUNDARIES.md), [ADR-0031](adr/0031-claim-boundary-codes.md)). A code states what the artifact does not show and never raises confidence. The registry (`evidence/claim-boundaries.json`) is append-only. Codes are not part of any record, digest or export; a producer MUST NOT omit or reword a limit statement because a code exists.

## Governance documents

The project's draft governance layer lives in [docs/governance](governance/CHARTER.md): charter, IPR policy, trademark and conformance-claim rules, versioning, extension registry and decision process. Each legal-style document opens with a draft-for-counsel notice and none has been adopted by any body. Requirements about these documents are checked by `test/governance-docs.test.mjs`. Regulatory crosswalks in [docs/crosswalks](crosswalks/README.md) are informative drafts: each carries the same notice, marks rows that rest on secondary sources, and makes no compliance claim; they are checked by `test/crosswalks.test.mjs`.
