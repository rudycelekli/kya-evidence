# Threat model

Protect the meaning and integrity of a scope-specific relying-party assessment. Assets include exact configuration binding, receipt integrity, frozen evaluation meaning, trust-anchor policy, privacy and auditability. Adversaries include score-seeking subjects, dishonest issuers, malicious adapters, colluding assessors and mistaken policy owners.

**Status.** This is a design-time model written by the project authors. No independent security review of this document or of the implementation has taken place (work-stream WS5 in [WORLD-CLASS-PLAN.md](WORLD-CLASS-PLAN.md) keeps that open). Every mitigation below names a requirement ID in `evidence/requirements.json` (each traced to a passing test by the requirement gate) or a test file; where neither exists the row says so. "UNVERIFIED" marks a statement the author could not confirm against code or tests. Related: [CRYPTO-AGILITY.md](CRYPTO-AGILITY.md), [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md), [VULNERABILITY-DISCLOSURE.md](VULNERABILITY-DISCLOSURE.md), [SECURITY.md](../SECURITY.md).

## Boundaries

Untrusted manifest, receipt and adapter responses enter strict parsing/validation. Out-of-band policy appoints trusted keys and roles. Signature, binding, time, source and revocation gates precede aggregation. Frozen profile and one latest run precede critical gates. Reports contain unsigned checksums; the viewer treats imports as unverified.

The caller owns filesystem and process isolation. A child process is not an OS sandbox. Native agents run only in authorized owned lanes, excluding production secrets and accounts. The package does not automatically fetch scripts, run arbitrary repositories or invoke paid models.

### Trust boundary map

```
 UNTRUSTED                      |  VALIDATION GATE          |  TRUSTED (by out-of-band choice)
 ------------------------------ | ------------------------- | ---------------------------------
 subject / agent under test --TB1--> adapter response --TB2--> strict parser + schema (src/shared/canonical.mjs)
 evidence issuer (any key)   --TB3--> signature check ........> trust-anchor check (policy)  <--TB4-- relying party's policy snapshot
 incident reporter (any key) --TB3--> signature check ........> trust-anchor check (policy)
 PR author (head branch)     --TB5--> CI gate (action/, scripts/kya-check.mjs) <-- base-branch policy, pins
 credential holder / relay   --TB6--> VC-JWS verifier (src/vc-bridge) .........> expected issuer keys or policy
 campaign operator           --TB7--> signed ledger (src/campaign) .............> capture-issuer anchor
 test authors / model vendor --TB8--> holdout commitment (src/holdout) .........> committed root, held opening
 maintainers / CI / registry --TB9--> release archive (scripts/pack.mjs) .......> consumer who verifies digests
```

| ID | Boundary | What crosses it | What is NOT established by crossing it |
| :--- | :--- | :--- | :--- |
| TB1 | Subject to assessor | Manifest declaration, agent behaviour | That the manifest describes what ran |
| TB2 | Adapter to evaluator | Scenario responses (`kya.scenario-response/v1`) | That observations are truthful; a runtime adapter can fabricate them |
| TB3 | Signer to verifier | Ed25519 envelopes (`kya.evidence/v1`, `kya.incident/v1`, campaign, conformance report) | Truthful execution or issuer honesty; only key possession over exact bytes |
| TB4 | Policy owner to verifier | Trust anchors, roles, revocations, thresholds | Freshness of revocations or independence of anchors |
| TB5 | Pull request to CI gate | Head manifest and evidence | That policy and pins were not edited if the workflow file itself is under attacker control |
| TB6 | Credential relay to verifier | `vc+jwt` credentials and status lists | Identity, authorization, or that the issuer is trustworthy |
| TB7 | Operator to ledger | Planned attempts and transitions | That a campaign ran, or that an unanchored head was not replaced |
| TB8 | Holdout holder to world | Commitment, later opening | That cases did not leak before reveal or were representative |
| TB9 | Maintainer to consumer | Packed archive and unsigned release receipt | Publisher identity or build provenance (not signed today) |

## Assets and actors

| Asset | Why it matters | Where it lives |
| :--- | :--- | :--- |
| Subject digest and bound manifest | Ties a result to one exact agent configuration | `kya.manifest/v1`, `src/identity` |
| Evidence receipts | Carry observations with key-possession proof | `src/evidence` |
| Trust-anchor policy and revocation lists | Decide who counts and who is revoked | `kya.policy/v1` supplied by the relying party |
| Frozen evaluator and profile | Give a score its meaning | `src/conformance`, `evidence/evaluator-identity.json` |
| Assessment report | The relied-on decision | `src/assessment` (checksum only, unauthenticated) |
| Private signing keys | Authority to create receipts, incidents, ledgers, credentials | Key holders; never in this repository |
| Holdout opening and salt | Secrecy of hidden cases | Holdout holder |
| Raw evidence bundles and private traces | May contain secrets or personal data | Campaign private directory (0600, outside the repository) |
| Release artefacts | What a consumer actually installs | `scripts/pack.mjs` output, Git history |

| Actor | Capability assumed | Goal |
| :--- | :--- | :--- |
| Score-seeking subject operator | Controls the agent, its adapter and any declarations; sees public cases | Qualify without being safe |
| Dishonest or compromised issuer | Holds a trusted signing key | Sign false receipts, incidents or ledgers; omit runs |
| Colluding assessors | Several keys that policy believes independent | Fake independence |
| Malicious adapter | Fabricates responses and usage figures | Launder fixtures as runtime evidence |
| Malicious pull-request author | Controls head manifest and evidence, may edit workflow files | Make the CI gate pass |
| Network or relay attacker | Replays or substitutes old files, stale status lists, old policy snapshots | Rely-on-stale |
| Insider or mistaken policy owner | Edits policy, roles, revocation lists | Weaken or misconfigure trust |
| Supply-chain attacker | Compromises a maintainer account, a CI action or a registry upload | Ship altered code |
| Curious or leaking party | Reads reports, logs, public records | Learn private traces or hidden cases |

## Assumptions registry

Security claims hold only while these hold. Violating one removes the guarantee, not merely weakens it.

| ID | Assumption | If violated | Checked by the code? |
| :--- | :--- | :--- | :--- |
| A1 | Node.js `node:crypto` (Ed25519, SHA-256, HMAC-SHA-256) is correct | Any signature or digest claim fails | No |
| A2 | The relying party obtains the policy (trust anchors, roles, revocations) out of band and authentic | Attacker chooses who is trusted | Partly: digest pins (KYA-ACT-009, KYA-ACT-012) when the caller supplies them |
| A3 | Private keys stay with their holders and are used only for their role | Receipts or credentials signed by an attacker verify | Only the capture-issuer role separation (KYA-CMP-009) |
| A4 | When `now` is not supplied the system clock is honest | Expiry, freshness and currency checks are wrong | The gate states the clock source (KYA-ACT-002) |
| A5 | The caller isolates processes, files and network for adapters | Adapter escapes or exfiltrates | No; a child process is not a sandbox |
| A6 | Repository history and branch protection preserve the pinned evaluator digest and reviewed code | Evaluator drift or a rewritten gate | Pin test (KYA-EVL-001); hosting settings UNVERIFIED |
| A7 | Roles `self`, `independent` and `capture-issuer` are assigned truthfully by the policy owner | Independence is meaningless | No |
| A8 | The runtime and the build environment (Node 22 or later, GitHub-hosted runners) are not compromised | Code under test is not the code that runs | No |
| A9 | Public toy keys in fixtures and golden vectors never become trust anchors | Anyone can forge | Vectors carry a warning; no mechanical check UNVERIFIED |
| A10 | Ed25519 and SHA-256 are not broken for the evidence lifetime | All historic evidence forgeable or collidable | No; see the post-quantum note in [CRYPTO-AGILITY.md](CRYPTO-AGILITY.md) |
| A11 | Policy snapshots are refreshed at a cadence the relying party chooses | Revoked keys or subjects still accepted | No live revocation exists |
| A12 | Reviewers other than the authoring lane have inspected the code | Undetected defects | False today: no external review (see [SECURITY.md](../SECURITY.md)); most code was written with AI assistance |
| A13 | A relying party actually runs `checkCurrency` and the gate before each reliance | Stale decisions are relied on | No |
| A14 | The holdout holder keeps the salt and cases secret until reveal | Memorisation of hidden cases | No |

## Component analysis (STRIDE)

S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation of privilege. "Req" is a requirement ID in `evidence/requirements.json`.

| Component | STRIDE | Threat | Mitigation (Req or test) | Residual |
| :--- | :--- | :--- | :--- | :--- |
| Receipts | S | Receipt signed by an attacker key | Signature validity is separate from trust (KYA-TRU-001) | Wrong anchors (A2, A7) |
| Receipts | T | Payload edited, key substituted, noncanonical signature | KYA-TRU-002, KYA-INT-003 | None beyond A1 |
| Receipts | R | Issuer later denies signing | Ed25519 binds a key to bytes | No timestamp or anchor: ADR-0020 is Proposed, not implemented; a key holder can claim compromise |
| Receipts | I | Leakage through receipts | Receipts carry digests; `verifyArtifact` takes explicit bytes and never fetches (`src/evidence/domain/services/signatures.mjs`) | A manifest or artefact the caller publishes is not protected |
| Receipts | D | Oversized or deeply nested input | Resource limits: 1 MiB, depth 32, 100,000 nodes (KYA-INT-001, KYA-INT-002) | OS-level limits belong to the caller (A5) |
| Receipts | E | Receipt claims independence for itself | KYA-TRU-001 | Sybil organisations |
| Policy | S/T | Policy swapped or edited | Digest pins `--expect-policy-digest` (KYA-ACT-009, KYA-ACT-012) | Only when the caller sets pins from a trusted source |
| Policy | E | Evaluator key reused as capture issuer | KYA-CMP-009 | Other role reuse across organisations is invisible (A7) |
| Policy | D | Stale snapshot keeps revoked keys alive | `revokedKeyIds`, `revokedSubjectDigests`, `revokedEvidenceIds` (KYA-TRU-004) | No live service (A11); `revokedKeyIds` is a flat list with no effective-time field, so revocation applies to all of a key's receipts |
| Assessment | T | Resealed report with a valid checksum | KYA-RPT-001 (checksum unauthenticated) | Recompute from trusted inputs |
| Assessment | T | Remove a failed check from the denominator | KYA-SCO-001, KYA-SCO-002 | None known |
| Assessment | S | Fixture or declaration presented as runtime | KYA-TRU-003, KYA-ACT-008, KYA-MIN-003 | Adapter fabrication (TB2) |
| Assessment | E | High average hides a critical failure | KYA-SCO-002, KYA-MIN-002 | Policy owner sets mandatory minimums |
| Assessment | R | Latest-run cherry-pick | KYA-RUN-001 to KYA-RUN-004 | Whole runs can be omitted without ledger plus anchor |
| Incidents | S | Untrusted key forces or clears reassessment | Only trusted anchors count; others listed as ignored (KYA-INC-002) | A trusted key can post a real report |
| Incidents | T | Hide a report by reusing its ID | KYA-INC-004 | Ambiguity holds a subject open |
| Incidents | R | Reporter resolves own report | KYA-INC-003 | Same organisation, two keys (A7) |
| Incidents | I | Narrative leaks private detail | Details digest only (KYA-INC-001) | None |
| Incidents | D | Report flood by a trusted key | None | No rate limit or triage |
| Incidents | E | Appeal used to clear a trigger | KYA-INC-003 | No adjudication path |
| Currency | T | Caller supplies stale manifest, policy or clock | Compares only supplied inputs (KYA-MON-001, KYA-MON-002) | A13 |
| Currency | S | Forged or resealed assessment fed in | KYA-MON-002, KYA-MON-003, pin `--expect-assessment-digest` (KYA-ACT-011) | Unpinned file is only as trusted as its source |
| Campaign ledger | S | Ledger signed by a non-plan key | KYA-CMP-004, KYA-CMP-016 | A policy-less verify reports signer unchecked |
| Campaign ledger | T | Edit, remove, reorder or re-plan history | Hash chain and signatures (KYA-CMP-003), planned entries first (KYA-CMP-002) | Truncated tail or whole-ledger replacement undetected unless the head is pinned (KYA-CMP-015) or anchored; anchoring not implemented |
| Campaign ledger | R | Operator denies or omits an attempt | Unaccounted attempts stay in the denominator (KYA-CMP-005) | Plan never published before runs |
| Campaign ledger | I | Prompts or traces stored | No free text (KYA-CMP-006); raw bundles 0600 in a private directory (KYA-CMP-010, KYA-CMP-017) | Local disk compromise |
| Campaign ledger | D | Unbounded attempts | Code caps 256 planned attempts and 4096 entries (`src/campaign/domain`); no requirement names the caps | UNVERIFIED as a requirement |
| Campaign ledger | E | Capture issuer doubles as evaluator or independent assessor | KYA-CMP-009 | A7 |
| VC bridge | S | `alg: none`, HMAC confusion, embedded `jwk`, wrong `kid` | KYA-VCB-004, KYA-VCB-012 | did:key has no rotation |
| VC bridge | T | Header, payload or signature edited; injected members | KYA-VCB-005, KYA-VCB-014 | Without the source report only internal consistency is claimed |
| VC bridge | R | Replay of a revoked or expired credential | Validity at explicit `now` (KYA-VCB-006); status list freshness (KYA-VCB-013) | Status only as fresh as the list supplied |
| VC bridge | I | Subject or principal exposed | Digest-only subject (KYA-VCB-001); keyed status index (KYA-VCB-011) | Issuer ledger and status secret must be protected |
| VC bridge | D | Gzip bomb in status list | Decompression ceiling, minimum size (KYA-VCB-009) | None known |
| VC bridge | E | Signature taken as trust | Trust relative to expected keys or policy (KYA-VCB-006); `authenticated: false` (KYA-VCB-005) | Consumers that ignore the flag |
| CI gate and Action | T | PR edits policy, profile or pins | Policy and pins come from the base branch (`docs/GITHUB-ACTION.md`), `require-pins` default true (KYA-ACT-012) | If the PR edits the workflow file itself, the gate can be removed; branch protection or a required workflow is needed, UNVERIFIED for any given repository |
| CI gate and Action | T | Untrusted strings start workflow commands or inject Markdown | Escaping of annotations, summary and outputs (KYA-ACT-003) | None known |
| CI gate and Action | I | Secrets printed | Environment secrets are not printed (KYA-ACT-003) | None known |
| CI gate and Action | S/E | Fixture result gates as reliable | KYA-ACT-008, KYA-ACT-006 | None known |
| CI gate and Action | T | Mutable third-party actions | `action/action.yml`, `.github/workflows/ci.yml` and `.github/workflows/release.yml` pin every `uses:` by full commit SHA with a version comment | The SHAs were resolved by the project and not independently re-checked against the action source; a pinned SHA can still be a malicious commit if it was resolved wrongly; see [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) |
| Holdouts | T | Swap, drop, duplicate or reorder cases after commit | KYA-HLD-001, KYA-HLD-004 | Commitment only useful if recorded before the campaign |
| Holdouts | I | One reveal leaks siblings or salt | KYA-HLD-003 | Pre-reveal leakage not prevented (A14) |
| Holdouts | S | Leaf and node confusion | KYA-HLD-003 | None known |
| Holdouts | R | Holder picks easy cases then commits | None | Not mitigated |

## Abuse cases

| ID | Attacker and concrete capability | Attack | Defences | Outcome |
| :--- | :--- | :--- | :--- | :--- |
| AC1 | Subject operator controlling agent and adapter; has read the 18 public checks | Memorise the public suite and fabricate runtime observations | Frozen core cannot be edited (KYA-CON-001); suites and holdouts (KYA-SUI-*, KYA-HLD-*); fixture never reliable by default (KYA-ACT-008) | Public-case passes show nothing about general behaviour; fabrication by a runtime adapter is not detected without independent capture |
| AC2 | Holder of a trusted evaluator key | Sign passing receipts for a run that did not happen | None cryptographic | Not mitigated; a ledger (KYA-CMP-*) makes omission detectable only if the plan was recorded first |
| AC3 | Trusted capture issuer | Run a campaign, publish only favourable attempts | Planned entries first, unaccounted stay in denominator (KYA-CMP-002, KYA-CMP-005) | Detectable only when the plan or ledger head was externally pinned; head pin supported (KYA-CMP-015), anchoring is not |
| AC4 | Pull-request author who can edit any file in the PR | Edit the policy to lower thresholds; or edit the workflow to skip the gate | Base-branch policy and pins (KYA-ACT-009, KYA-ACT-012) | The first is blocked; the second needs branch protection outside this repository |
| AC5 | Relay that replays an old assessment and an old status list | Present a revoked agent as qualified | Validity window and mandatory `validUntil` on lists (KYA-VCB-006, KYA-VCB-013); currency check (KYA-MON-001) | Window-bounded; no live revocation |
| AC6 | Attacker who steals one trusted signing key | Sign new receipts; backdate | Policy revocation of the key id (KYA-TRU-004) | Backdating is possible until the key is revoked; revocation voids legitimate older receipts too; no anchor to separate them |
| AC7 | Model vendor or contractor with access to hidden cases | Train on the holdout | Commit-reveal exposes post-hoc changes only (KYA-HLD-004) | Leakage not detected |
| AC8 | Author of a second implementation or a malformed input | Parser differential so two verifiers disagree | Strict parser, golden vectors, Python second implementation (KYA-INT-002, KYA-INT-003, KYA-INT-004) | Python checker covers a declared subset only |
| AC9 | Account takeover of a maintainer or a CI action | Publish altered code or a tampered archive | Zero runtime dependencies; deterministic archive and receipt (KYA-REL-001) | No release has been made, so no archive is signed or attested. The manual release workflow contains a provenance attestation job that has never been run. CI action refs are SHA pins that the project resolved itself; see [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) |
| AC10 | Contributor or AI assistant adding a hollow or skipped test | Make a requirement appear traced | Requirement gate and CI zero-skip rule (KYA-REQ-001) | Hollow assertions pass the gate; review is the control |

## Existing attack catalogue

Rows from the earlier model are kept as written; the last column links each row to its evidence.

| Attack | Control | Residual risk | Verified by |
| :--- | :--- | :--- | :--- |
| Signed receipt mutation | Ed25519 and strict canonical input | Compromised or dishonest key can sign lies | KYA-TRU-002, KYA-INT-003 |
| Executable JavaScript input substitution | Capture JSON once; score, hash and retain the same data view | Proxy descriptor traps execute caller code; this is not a JavaScript sandbox | KYA-TRU-006, KYA-INT-001 |
| Self-appointed trust/independence | Out-of-band policy keys/roles | Misconfiguration, issuer collusion and Sybil organizations | KYA-TRU-001 |
| Wrong model/configuration/scope | Full-manifest and exact scope/profile/evaluator binding | Declaration needs independent runtime observation | KYA-BND-001, KYA-BND-003 |
| Hidden failures or denominator removal | Frozen checks, latest whole run, critical gates | Whole runs can be omitted without external capture | KYA-SCO-001, KYA-SCO-002, KYA-RUN-001 |
| Latest-run ambiguity or duplicate trick | Ambiguity prevents qualification; duplicate receipts still establish recency | Malicious trusted issuer can deny qualification | KYA-RUN-002, KYA-RUN-003, KYA-TRU-005 |
| Stale or revoked claims | Time/freshness checks and policy-snapshot revocation | Snapshot may be stale; no live revocation service | KYA-TRU-004, KYA-MON-001 |
| Declaration/fixture laundering | Declarations never score; source controlled by adapter origin | Runtime adapter may fabricate observations | KYA-TRU-003, KYA-ACT-008 |
| Injection/peer authority | Structured adversarial cases | Public-case passes do not establish general resistance | KYA-CON-001, KYA-SUI-003 |
| Malformed input/resource abuse | Strict JSON, field/depth/size caps, bounded transport | Caller must isolate OS resources and storage | KYA-INT-001, KYA-INT-002 |
| Forged report with valid checksum | Viewer labels imports; CLI checksum unauthenticated | Recompute from trusted original inputs | KYA-RPT-001 |
| Secret leakage through reports | Text rendering, bounded output, suppressed stderr | Raw traces require redaction and private storage | KYA-ACT-003 for the CI gate; `test/dossier-render.test.mjs` and `test/presentation.test.mjs` for rendering (assertion coverage UNVERIFIED) |
| Suite contamination/evaluator drift | Frozen descriptor, release source binding, mutation tests | Protected holdouts and empirical calibration open | KYA-EVL-001, KYA-BEN-002, KYA-HLD-004 |

### Currency, incidents and principal threats

| Attack | Control | Residual risk | Verified by |
| :--- | :--- | :--- | :--- |
| Stale assessment relied on after a change | `checkCurrency` / `kya currency` fires `subject-changed`, `policy-changed`, `subject-revoked`, `assessment-expired`, `assessment-aged` or `clock-regression`; any trigger gives `action: reassess` and exit 2 | Compares only the supplied manifest, policy and clock. No runtime observation or live revocation, and no protection for a relying party that never runs the check | KYA-MON-001, KYA-REF-004 |
| Incident suppressed by an untrusted key | Only records signed by a key in the policy's trust anchors count. Untrusted, revoked, misdirected and malformed records are listed under `ignored` with a reason | An incident nobody supplies is undetectable. A trusted key can post a real report and force reassessment | KYA-INC-002 |
| Incident hidden by a duplicate ID | Every distinct trusted report is kept. An identical envelope delivered twice collapses. Reports sharing an ID stay open and resolutions aimed at them are listed as ambiguous | An ambiguous report can keep a subject unqualifiable until the policy owner resolves which record is authentic | KYA-INC-004 |
| Equivocation by one key (same ID, conflicting records) | Conflicting same-key non-report records are not honoured; reports from that key stay open | The trusted key can still flood reports. No rate limit or triage exists | KYA-INC-004 |
| Cross-key ID reuse | A resolution may target only an unambiguous report ID, so one key cannot clear another key's report | Wrong trust anchors remain a policy misconfiguration risk | KYA-INC-004 |
| Future-dated or clock-skewed incident | Future-dated blocking reports stay open and are listed. Future-dated non-blocking reports and future-dated resolutions are ignored | Fail-closed lets a skewed or misdated reporter hold a subject open. Tolerance is not tuned | KYA-INC-002 |
| Reporter resolves its own report | A resolution counts only from an `independent` anchor, never the reporter's key, and only when dated strictly after the report | Independence is a policy assignment. Two keys run by one organization are not detected | KYA-INC-003 |
| Appeal used to clear a trigger | Appeals are recorded under `appealed` and never clear a trigger | No adjudication, no reopening of a resolution and no contest path | KYA-INC-003 |
| Malformed or resealed assessment | Canonical strict parsing, exact fields, digest recheck, validity not before assessment time, digest shape and decision enum checked | A rehashed report passes the checksum. `scopeDigest` and decision/score consistency are not re-derived, and `reliable` trusts the decision string. Re-run `assess` from trusted inputs rather than trusting the file | KYA-MON-002, KYA-MON-003 |
| False accountable-party declaration | Pseudonymous `kind` and `ref` only, no extra fields, an agent cannot name itself, `requirePrincipalBinding` withholds qualification when absent, and the declaration is inside the subject digest | The declaration is unverified. A false reference qualifies when policy requires one. The report shows `principalId` but not `accountableParty` | KYA-PRN-001, KYA-PRN-002 |
| Requirement-trace gaming: skipped, commented or dynamic tests | Gate strips comments, requires exactly one live test title per trace, treats dynamic titles, option variables and unconditional skip/todo as untraceable, and flags host-conditional skips. CI fails unless `# skipped 0` and `# todo 0` | Text-only gate. Declarations inside template literals or dead branches at column 0 are invisible | KYA-REQ-001 |
| Requirement-trace gaming: hollow test body | None automatic | A trace shows that a titled test exists and passes, not that its assertions cover the MUST. Review is the control | None (by design) |
| Mutation-harness blind spot | `scripts/mutation-check.mjs` runs its named gate mutants against the assessment, incident, blocker-code and mandatory-minimum tests, requires each to fail, and requires the test population to match the baseline | Only targeted gates, with textual anchors, run against a fixed list of test files. The requirement gate, canonical parser and Python checker are not mutated. An unlisted weakening is not detected | CI step `node scripts/mutation-check.mjs`; no requirement ID |

## Prohibited claims

This package does not verify human identity, legal delegation, actual organizational independence, universal safety or future performance. It must not score human creditworthiness. A policy result cannot override platform or tenant authorization.

## Not mitigated

- Truthful execution of the subject, and any runtime behavior between checks.
- Revocation freshness beyond the policy snapshot a relying party supplies.
- Identity proofing of the accountable party, and legal liability.
- Incidents that no one signs or supplies, and incident truth.
- Appeal adjudication and reopening of resolutions.
- Organizational independence of trusted keys.
- External review of the whole reference implementation.
- Time of signing: no timestamp or external anchor is implemented (ADR-0020 is Proposed), so backdating after key compromise and tail truncation of an unpinned ledger are not detectable.
- Key compromise response beyond policy revocation: there is no effective-time revocation and no key rotation protocol (guidance only, see [CRYPTO-AGILITY.md](CRYPTO-AGILITY.md)).
- A malicious or mistaken trusted key flooding incident reports.
- Pre-reveal leakage of holdout cases, and a holder who chooses easy cases before committing.
- Release authenticity: no release exists, so no archive, receipt or tag is signed or attested. The manual release workflow has a build provenance attestation job that has never been run, so it is untested in practice (see [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md)).
- Correctness of the action commit SHAs the project pinned: they were resolved by the project and not independently re-checked against the action source.
- A pull request that edits the CI workflow to bypass the gate, absent branch protection.
- Cryptanalytic or quantum attacks on Ed25519 and SHA-256 (A10).
- Hollow test assertions behind a traced requirement.

## Verification and response

Required adversarial cases include mutation, executable input substitution, duplicate JSON/IDs, untrusted self-signing, wrong bindings, future/expired/revoked evidence, run cherry-picking, declaration and role laundering, critical failure despite high averages, unknown coverage, HTML injection and child resource limits. Mutation tests must catch weakened evaluator gates. Separate bounded source reviews and repair reproductions are retained in private development records; an external whole-artifact security audit remains open.

Preserve a sanitized reproduction, exact release digest, failing assertion and impact. Freeze promotion for bypassed gates. Repair with regressions and independent review, revoke affected policy identifiers, then publish an authorized correction without exposing private traces. See [SECURITY.md](../SECURITY.md) and the draft [VULNERABILITY-DISCLOSURE.md](VULNERABILITY-DISCLOSURE.md).

Blocker codes and `blockerCodes` lists are covered by the same unauthenticated report checksum as every other report field. Verification cross-checks them only against the report's own decision and critical-failure count, so a resealed report can still carry a plausible but false code list; recompute from trusted inputs before reliance.
