# Threat model

Protect the meaning and integrity of a scope-specific relying-party assessment. Assets include exact configuration binding, receipt integrity, frozen evaluation meaning, trust-anchor policy, privacy and auditability. Adversaries include score-seeking subjects, dishonest issuers, malicious adapters, colluding assessors and mistaken policy owners.

## Boundaries

Untrusted manifest, receipt and adapter responses enter strict parsing/validation. Out-of-band policy appoints trusted keys and roles. Signature, binding, time, source and revocation gates precede aggregation. Frozen profile and one latest run precede critical gates. Reports contain unsigned checksums; the viewer treats imports as unverified.

The caller owns filesystem and process isolation. A child process is not an OS sandbox. Native agents run only in authorized owned lanes, excluding production secrets and accounts. The package does not automatically fetch scripts, run arbitrary repositories or invoke paid models.

| Attack | Control | Residual risk |
| :--- | :--- | :--- |
| Signed receipt mutation | Ed25519 and strict canonical input | Compromised or dishonest key can sign lies |
| Executable JavaScript input substitution | Capture JSON once; score, hash and retain the same data view | Proxy descriptor traps execute caller code; this is not a JavaScript sandbox |
| Self-appointed trust/independence | Out-of-band policy keys/roles | Misconfiguration, issuer collusion and Sybil organizations |
| Wrong model/configuration/scope | Full-manifest and exact scope/profile/evaluator binding | Declaration needs independent runtime observation |
| Hidden failures or denominator removal | Frozen checks, latest whole run, critical gates | Whole runs can be omitted without external capture |
| Latest-run ambiguity or duplicate trick | Ambiguity prevents qualification; duplicate receipts still establish recency | Malicious trusted issuer can deny qualification |
| Stale or revoked claims | Time/freshness checks and policy-snapshot revocation | Snapshot may be stale; no live revocation service |
| Declaration/fixture laundering | Declarations never score; source controlled by adapter origin | Runtime adapter may fabricate observations |
| Injection/peer authority | Structured adversarial cases | Public-case passes do not establish general resistance |
| Malformed input/resource abuse | Strict JSON, field/depth/size caps, bounded transport | Caller must isolate OS resources and storage |
| Forged report with valid checksum | Viewer labels imports; CLI checksum unauthenticated | Recompute from trusted original inputs |
| Secret leakage through reports | Text rendering, bounded output, suppressed stderr | Raw traces require redaction and private storage |
| Suite contamination/evaluator drift | Frozen descriptor, release source binding, mutation tests | Protected holdouts and empirical calibration open |

## Currency, incidents and principal threats

| Attack | Control | Residual risk |
| :--- | :--- | :--- |
| Stale assessment relied on after a change | `checkCurrency` / `kya currency` fires `subject-changed`, `policy-changed`, `subject-revoked`, `assessment-expired`, `assessment-aged` or `clock-regression`; any trigger gives `action: reassess` and exit 2 | Compares only the supplied manifest, policy and clock. No runtime observation or live revocation, and no protection for a relying party that never runs the check |
| Incident suppressed by an untrusted key | Only records signed by a key in the policy's trust anchors count. Untrusted, revoked, misdirected and malformed records are listed under `ignored` with a reason | An incident nobody supplies is undetectable. A trusted key can post a real report and force reassessment |
| Incident hidden by a duplicate ID | Every distinct trusted report is kept. An identical envelope delivered twice collapses. Reports sharing an ID stay open and resolutions aimed at them are listed as ambiguous | An ambiguous report can keep a subject unqualifiable until the policy owner resolves which record is authentic |
| Equivocation by one key (same ID, conflicting records) | Conflicting same-key non-report records are not honoured; reports from that key stay open | The trusted key can still flood reports. No rate limit or triage exists |
| Cross-key ID reuse | A resolution may target only an unambiguous report ID, so one key cannot clear another key's report | Wrong trust anchors remain a policy misconfiguration risk |
| Future-dated or clock-skewed incident | Future-dated blocking reports stay open and are listed. Future-dated non-blocking reports and future-dated resolutions are ignored | Fail-closed lets a skewed or misdated reporter hold a subject open. Tolerance is not tuned |
| Reporter resolves its own report | A resolution counts only from an `independent` anchor, never the reporter's key, and only when dated strictly after the report | Independence is a policy assignment. Two keys run by one organization are not detected |
| Appeal used to clear a trigger | Appeals are recorded under `appealed` and never clear a trigger | No adjudication, no reopening of a resolution and no contest path |
| Malformed or resealed assessment | Canonical strict parsing, exact fields, digest recheck, validity not before assessment time, digest shape and decision enum checked | A rehashed report passes the checksum. `scopeDigest` and decision/score consistency are not re-derived, and `reliable` trusts the decision string. Re-run `assess` from trusted inputs rather than trusting the file |
| False accountable-party declaration | Pseudonymous `kind` and `ref` only, no extra fields, an agent cannot name itself, `requirePrincipalBinding` withholds qualification when absent, and the declaration is inside the subject digest | The declaration is unverified. A false reference qualifies when policy requires one. The report shows `principalId` but not `accountableParty` |
| Requirement-trace gaming: skipped, commented or dynamic tests | Gate strips comments, requires exactly one live test title per trace, treats dynamic titles, option variables and unconditional skip/todo as untraceable, and flags host-conditional skips. CI fails unless `# skipped 0` and `# todo 0` | Text-only gate. Declarations inside template literals or dead branches at column 0 are invisible |
| Requirement-trace gaming: hollow test body | None automatic | A trace shows that a titled test exists and passes, not that its assertions cover the MUST. Review is the control |
| Mutation-harness blind spot | `scripts/mutation-check.mjs` runs its named gate mutants against the assessment, incident, blocker-code and mandatory-minimum tests, requires each to fail, and requires the test population to match the baseline | Only targeted gates, with textual anchors, run against a fixed list of test files. The requirement gate, canonical parser and Python checker are not mutated. An unlisted weakening is not detected |

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

## Verification and response

Required adversarial cases include mutation, executable input substitution, duplicate JSON/IDs, untrusted self-signing, wrong bindings, future/expired/revoked evidence, run cherry-picking, declaration and role laundering, critical failure despite high averages, unknown coverage, HTML injection and child resource limits. Mutation tests must catch weakened evaluator gates. Separate bounded source reviews and repair reproductions are retained in private development records; an external whole-artifact security audit remains open.

Preserve a sanitized reproduction, exact release digest, failing assertion and impact. Freeze promotion for bypassed gates. Repair with regressions and independent review, revoke affected policy identifiers, then publish an authorized correction without exposing private traces. See [SECURITY.md](../SECURITY.md).

Blocker codes and `blockerCodes` lists are covered by the same unauthenticated report checksum as every other report field. Verification cross-checks them only against the report's own decision and critical-failure count, so a resealed report can still carry a plausible but false code list; recompute from trusted inputs before reliance.
