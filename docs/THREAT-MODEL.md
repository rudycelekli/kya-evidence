# Threat model

Protect the meaning and integrity of a scope-specific relying-party assessment. Assets include exact configuration binding, receipt integrity, frozen evaluation meaning, trust-anchor policy, privacy and auditability. Adversaries include score-seeking subjects, dishonest issuers, malicious adapters, colluding assessors and mistaken policy owners.

## Boundaries

Untrusted manifest, receipt and adapter responses enter strict parsing/validation. Out-of-band policy appoints trusted keys and roles. Signature, binding, time, source and revocation gates precede aggregation. Frozen profile and one latest run precede critical gates. Reports contain unsigned checksums; the viewer treats imports as unverified.

The caller owns filesystem and process isolation. A child process is not an OS sandbox. Native agents run only in authorized owned lanes, excluding production secrets and accounts. The package does not automatically fetch scripts, run arbitrary repositories or invoke paid models.

| Attack | Control | Residual risk |
| :--- | :--- | :--- |
| Signed receipt mutation | Ed25519 and strict canonical input | Compromised or dishonest key can sign lies |
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

## Prohibited claims

This package does not verify human identity, legal delegation, actual organizational independence, universal safety or future performance. It must not score human creditworthiness. A policy result cannot override platform or tenant authorization.

## Verification and response

Required adversarial cases include mutation, duplicate JSON/IDs, untrusted self-signing, wrong bindings, future/expired/revoked evidence, run cherry-picking, declaration and role laundering, critical failure despite high averages, unknown coverage, HTML injection and child resource limits. Mutation tests must catch weakened evaluator gates. Independent security review remains pending.

Preserve a sanitized reproduction, exact release digest, failing assertion and impact. Freeze promotion for bypassed gates. Repair with regressions and independent review, revoke affected policy identifiers, then publish an authorized correction without exposing private traces. See [SECURITY.md](../SECURITY.md).
