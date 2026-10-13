# KYA Evidence specification, v0.1

Status: implemented experimental reference protocol. Independent security and standards-body review remain open. Normative requirements describe this implementation; they do not claim an adopted standard.

## Purpose

Assess an exact agent configuration against a relying party's frozen policy for a declared scope, at a stated time. This is not human identity verification, an authorization grant, legal compliance, general safety or universal creditworthiness. `principal.id` is a pseudonymous controller reference. Never assign a person's creditworthiness or moral standing from this agent score.

The manifest declares; the profile freezes checks; receipts record outcomes; policy assigns trust and thresholds; assessment explains a decision. Keep declared, fixture-tested, runtime-observed and independently assessed evidence distinct.

## Records and bindings

| Record | Schema | Binding |
| :--- | :--- | :--- |
| Manifest | `kya.manifest/v1` | Agent, principal, full system, scope and validity interval |
| Profile | `kya.profile/v1` | ID, version, title and every frozen check/weight/critical flag |
| Policy | `kya.policy/v1` | Profile digest, scope, coverage/score/independence thresholds, source classes, freshness, trust anchors and revocations |
| Evidence | `kya.evidence/v1` | Subject, scope, profile, evaluator, run, check, artifact digest, outcome, source and validity interval |
| Assessment | `kya.assessment/v1` | Input digests, time, source mode, decision, score, dimensions, checks, rejections and limitations |

Strict JSON rejects duplicate members, unsupported values, prototype keys, excessive resources and unknown schema fields. Canonicalization uses a bounded sorted-key JSON subset, not a claimed RFC 8785 implementation. SHA-256 digests are 64 lowercase hexadecimal characters. Timestamps are canonical UTC ISO strings.

The subject is the full-manifest digest. It binds harness/version, model, artifact/configuration digests, tool identities/versions/permissions and explicit scope. Tool permissions must be allowed in scope. Allowed and forbidden permissions cannot overlap. Changing a manifest field creates a new subject and invalidates old evidence for it.

## Trust and eligibility

Receipt outcomes are `pass`, `fail`, `abstain`, `error`. Sources are `runtime`, `fixture`, `declaration`; declarations never satisfy scored checks. A response cannot elevate fixture origin to runtime origin. An Ed25519 proof authenticates bytes and key possession, not truthful observation.

Trust anchors and `self`/`independent` roles come from an out-of-band relying policy. A receipt cannot make its own key trusted or assign itself independence. Organizational independence remains an external assertion. Revocation covers subject digests, evidence IDs and key IDs, using a supplied policy snapshot.

Eligibility requires a valid proof, trusted non-revoked key, matching subject/scope/profile/evaluator/check, allowed observed source and valid time. Future, pre-manifest, expired and overly old evidence is rejected. Rejection reasons remain in the report. Eligible duplicate evidence IDs are quarantined; invalid untrusted copies cannot quarantine an otherwise trusted receipt.

## Run selection and qualification

Only the latest whole run is selected. Checks cannot be mixed from several runs. Duplicate quarantined evidence still establishes run recency so an old passing run cannot revive. Tied latest runs create ambiguity and cannot qualify; a selected critical failure still blocks. Within one selected run, latest observation wins and failure wins equal-time conflicts. This limits obvious cherry-picking; independent capture is still needed to detect omitted entire runs.

Every frozen check stays in the denominator. Unknown, abstained and errored checks earn zero points and no observed coverage. Pass and fail count as observed; only pass earns points. Critical failure blocks; critical unresolved checks withhold qualification. Revoked or invalid-time subjects cannot qualify. At least one known pass/fail is required even when thresholds are zero. Coverage, independence and score thresholds then apply. See [SCORING.md](SCORING.md).

`validUntil` is bounded by the manifest expiry, selected receipts and policy age cutoffs. Reassess using fresh policy revocations before reliance. Revocation is not a live lookup service.

## Reports and viewers

The report includes input digests, `selectedRunId`, `ambiguousRuns`, every check, `acceptedEvidenceDigests`, rejection reasons and explicit limitations. `reportDigest` is an unsigned checksum. `verify` returns checksum integrity with `authenticated:false`; an attacker can checksum false claims. Recompute from trusted original inputs to assess assurance.

The dashboard displays imported files as unverified claimed reports. Its presets use `kya.viewer-fixture/v1` and cannot masquerade as signed assessments. Raw observations and signed receipts are not embedded in the check list. Preserve authorized raw evidence privately, and redact before hashing public observation artifacts.

## Interoperability and versioning

This is not an official implementation of Open-KYA, W3C VC, A2A or MCP. Credential/discovery bridges must preserve exact input digests, source class and limits. Compatibility needs executable multi-implementation tests. Alpha schema changes require explicit versioning and migration notes. Invalid top-level input fails; invalid individual receipts become rejections. Determinism requires frozen time and input files.
