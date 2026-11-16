# KYA Passport and gateway implementation plan

**Goal.** A relying party can discover an agent, verify its registered controller and exact revision, determine current signing authority, authorize one exact action, and reconstruct the decision after faults or key changes. A 10/10 rating requires reproducible engineering evidence and independent operational evidence in every workstream. The [readiness ledger](WORLD-CLASS-STATUS.md) remains the broader project tracker.

## Baseline and execution order

The Passport registry stores signed lifecycle events and keeps historical fingerprint lookups. Recoverable passports commit an offline recovery key at registration. The gateway now journals delivery and reconciles operator-verified terminal receipts. Per-passport signed checkpoints and durable mirrors provide bounded freshness and local rollback protection. The MCP gateway verifies an exact call, avoids replay on one SQLite host, and can require the active Passport. Each gateway retains a local head pin across restarts. Independent witnesses and first-use freshness remain future work. Loopback OIDC and MCP tests use a synthetic identity and tool. This plan treats independent review, external integration and calibration as acceptance evidence to collect.

### 1. Prove the trust chain in an approved pilot

**Inputs.** Existing test tenant issuer URL, OIDC client ID, exact registered callback, and an authorized test identity. Provide the client authentication mode and a vault reference if the client is confidential. Supply a reachable HTTPS pilot gateway with persistent storage, the trusted issuer/subject to principal mapping, and a controller key custody owner. Supply an externally operated MCP endpoint, tool name, versioned input schema, authentication configuration, and written permission to exercise a read-only or idempotent operation.

**Build.** Run Authorization Code with PKCE against the pinned issuer. Verify the provider's ID-token signature and check issuer, audience, nonce, state, expiry and recent login. Use separate key material for the agent and controller. Enroll the principal, pin the approved passport ID and route revision, and wire the gateway to the authoritative registry. Give each run an ID and retain redacted input commitments, fixture versions and signed heads.

**Accept.** The external tool returns the expected result for the exact authorized call. Replay, edited arguments, principal-key retirement, agent-key rotation, stale manifest, terminal revocation and registry unavailability all produce auditable denials without downstream dispatch. A new key succeeds between rotation and revocation. Reopen the database and re-run the refusal cases. Record the identity provider, runtime, endpoint classes and role of the operator. Keep tokens and user attributes out of the evidence pack.

### 2. Make delivery recoverable

The gateway commits an operation ID and delivery record with acceptance. Extend the journal to supported downstream retry protocols. Keep states for queued, dispatched, response observed and outcome unknown. For a downstream system that implements idempotency, forward the operation ID and reconcile via an authenticated receipt or status endpoint. A route without those capabilities leaves uncertain outcomes for operator review. Define a bounded retry budget and enforce side-effect scope independently of retries.

Prove behavior at each crash boundary before and after acceptance, dispatch and receipt recording. Inject timeouts, upstream duplicates, process death and storage restore. Assert a single downstream effect for supported routes and an explicit unresolved outcome for other routes. Publish latency, error rates and audit completeness against the same baseline workload.

### 3. Establish registry freshness, distribution and recovery

Specify signed, time-bounded checkpoints that commit to an append-only global event log and a verifiable index of passport heads. Inclusion establishes membership. Consistency proofs connect successive checkpoints. A relying party pins the registry root, persists its last trusted checkpoint and validates freshness under its own policy. Authenticate the current head and the lookup result independently. Register at least two independently operated witnesses and a read-only mirror. Define issuer migration and namespace continuity.

Define a recovery policy at registration, with a separate recovery key or quorum, sequence preconditions, auditable recovery, and explicit compromise semantics. Preserve historical fingerprints. Simulate loss of controller keys, tampered witnesses, outage, omitted events, a split view, rollback across restart, proof failure, and restoration from an independent mirror. Set availability and recovery objectives from observed pilot requirements and verify them in drills.

### 4. Harden a hosted service and its privacy boundaries

Define public and private fields, configurable retention, selective disclosure, abuse limits, quota ownership, and restore access. Threat-model operator impersonation, key exfiltration, manifest correlation, malicious registrations, stale metadata and supply-chain injections. Keep linkage data restricted to operators who need it. Establish telemetry and an incident escalation route. Run independent security and privacy review, record findings and retest fixes. Track assessment scope and jurisdiction with practitioners and counsel.

### 5. Prove interop, oversight and adoption

Freeze a language-neutral Passport schema and vector corpus. Cover identifier derivation, exact signature bytes, canonical encoding, stale histories, key rotation, revocation, recovery, checkpoints, freshness and lookup proofs. Test from independently authored implementations and independent consumers of ecosystem export formats. Exercise assessor independence, correction and appeal. Use the campaign tooling for authorized blind comparisons and keep all attempts, including failures. Recruit relying parties and define prospective calibration measures before data collection. Move governance to a neutral home after independent stakeholder agreement.

## Acceptance matrix

| Readiness area | Evidence required for 10/10 |
| --- | --- |
| Scope and usability | Three outside readers independently explain the assurances and integrate with one walkthrough. Every evidence type has documented boundaries. |
| Profiles and policy | Versioned schemas, risk-specific policy profiles, negative conformance tests and domain-expert acceptance. |
| Independent implementations | Two outside implementations pass frozen normative vectors and produce mutually readable results. |
| Governance | Neutral home and ratified governance, versioning, appeals and trademark rules reviewed by counsel. |
| Security and reliability | Two commissioned external reviews with retest, one complete failure-injection campaign, and a recovery drill meeting agreed objectives. |
| Interoperability | Approved hosted OIDC and external MCP proof, plus independent verification of each supported export profile. |
| Audit and regulatory mapping | Reviewed control-to-artifact crosswalks, sample audit traceability and sign-off from relevant practitioners and counsel. |
| Assessor accountability | Agreement and disagreement evidence from independent assessors on the same subject, with a completed appeal. |
| Privacy | Reviewed data map, retention and deletion receipts, leak checks, selective disclosure tests and independent impact assessment. |
| Real usage and calibration | Three distinct relying-party pilots, a campaign on three authorized agent configurations, and preregistered calibration with published uncertainty. |

**Evidence rule.** Each milestone needs a repository revision, configuration and trust anchor references, exact test corpus, outcomes and failure records. For external milestones record the attestor, date, scope and evidence link. Assign owners and pilot targets before starting each operational milestone.
