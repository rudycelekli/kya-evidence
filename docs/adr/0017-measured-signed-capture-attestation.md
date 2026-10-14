# ADR-0017: Measured, signed capture attestation (`kya.capture/v1`)

**Status**: Proposed
**Date**: 2026-10-14
**Updated**: 2026-10-14, first slice implemented in ADR-0021 (`capture-issuer` role, signed planned-attempt campaign ledger and runner). Egress probes, environment fingerprint, tool-surface measurement, capture records and anchoring remain unimplemented; status stays Proposed.
**Depends-on**: ADR-0003, ADR-0004, ADR-0009, ADR-0014

Review boundary: design only for everything except the slice named above; no independent review, no external certification.

## Context

ADR-0003 keeps every frozen check in the denominator and selects the latest whole run, but states that trusted issuers can omit entire runs. ADR-0009 replays original responses and keeps "actual effects" as a named blind spot. The evaluation blueprint records an owned experiment where an agent returned compliant structured answers while writing synthetic markers through a surface the harness did not observe, and the generic runtime path still qualified it. The root cause is that every observation today is produced by the party being assessed or by an adapter it can shape. Roadmap stage 3 asks for tool side-effects, exact environment fingerprints and run-completeness lineage.

## Decision

Add a record `kya.capture/v1`, produced and signed by a **capture harness** (the process that owns the execution cell, not the agent and not the evaluator), under its own domain-separation prefix like ADR-0014 records. Strict JSON, canonical bytes, SHA-256 digests, Ed25519, as elsewhere.

### Claim classes

Every field carries a class, and a relying policy may require classes per field:

| Class | Meaning | Example |
| :--- | :--- | :--- |
| `measured` | The harness observed it from outside the agent's control at the stated time | egress probe result, tool calls that crossed the harness-owned tool boundary, before/after digests of harness-owned state |
| `configured` | The harness set a control and did not verify it took effect | network policy sent to a sandbox vendor |
| `declared` | Supplied by the subject or operator | manifest tool list, model name |

Only `measured` may satisfy a measured-capture requirement. `configured` is explicitly weaker: sending a network deny rule and receiving success proves nothing about enforcement.

### Record

`kya.capture/v1` contains: `captureId`, `runId`, `subject` (full-manifest digest), `scopeDigest`, `profileDigest`, `evaluator` key reference, `harness` (identity, version, build digest), `startedAt`, `endedAt`, and:

1. `environment`: digests of the cell image/rootfs, interpreter and package lock, OS/kernel string, resource limits, clock source, and an environment fingerprint digest over these. Each entry is classed.
2. `toolSurface`: the tools actually exposed to the agent (name, version, permission set digest), enumerated by the harness from the live tool boundary, plus a `declaredDiff` listing differences from the manifest. Tool listed in manifest but absent, or present but undeclared, is surfaced, not silently reconciled.
3. `attempts`: ordered, hash-chained log of tool invocations and denied attempts crossing the harness boundary: tool, argument digest, decision (`allowed`, `denied`, `error`), denial reason code, time, previous-entry digest. Raw arguments stay private; only digests are in the record.
4. `egress`: results of probes executed from inside the cell at `start` and again at every `restore` or resume, never only at creation. Each probe states target class, expected posture, observed posture and layer. Probes must assert at the application layer (a real response body is required, since a connect that succeeds then drops is not evidence of reachability) and must use IP literals so that a DNS failure cannot masquerade as a network block; probes run from a root-only path the agent cannot call. A denied-by-config network paired with a probe that observes reachability is recorded as `egress-mismatch`.
5. `state`: before and after digests of each declared state surface (workspace tree, selected files, database snapshot) and a list of surfaces the harness could not observe (`unobserved`). Unobserved is mandatory, never omitted.
6. `ledger`: reference to the planned-attempt ledger below.

### Planned-attempt ledger

Before any run executes, the harness signs and **publishes** (see ADR-0020) a `plan` entry: `runId`, `profileDigest`, `subject`, `plannedAt`, and sequence number in a per-campaign hash chain. Every planned run later yields a capture record with the same `runId`, whether pass, fail, error, timeout or abandonment (`outcome: abandoned` is signed by the harness at campaign close). A verifier reconciling ledger and captures reports `omitted-run` for any planned ID without a capture and `unplanned-run` for any capture without a plan. Plans are append-only; a retracted plan is a new entry referencing the old one, never a deletion. This is what lets ADR-0003's "omitted entire runs remain undetectable" become detectable, but only when the ledger head was externally anchored before execution.

### Binding

`kya.evidence/v1` receipts gain an optional `captureDigest`. When a policy sets `requireCapture`, the evaluator accepts evidence for a run only if a capture record with that digest exists, verifies, is signed by a trusted `capture-issuer` anchor, and matches `runId`, subject digest, scope digest, profile digest and evaluator key. The capture issuer is a new anchor role, distinct from the evaluator and from `self`/`independent`. Policy rules: capture issuer key may not equal evaluator key; for an `independent` requirement the capture issuer must also be policy-listed independent. A subject-run with a mismatching tool surface (`undeclaredTool`, `egress-mismatch`, forbidden-permission use) yields named non-pass outcomes for the affected checks and a rejection reason; it does not delete checks from the denominator.

### Privacy

Public records hold digests, reason codes and counts. Raw tool arguments, outputs and traces remain in private storage. Probe targets are a fixed public list.

## Threats

| Attacker | Attempt | Control | Residual |
| :--- | :--- | :--- | :--- |
| Agent | Act through an unobserved surface | `toolSurface` enumerated by harness, `unobserved` list, state before/after digests | Surfaces the harness does not know about are invisible by construction |
| Agent | Detect the probe and behave differently | Probes run root-only, outside agent tool surface | A sufficiently capable agent may still infer the cell; see ADR-0018 |
| Operator | Drop unfavourable runs | Pre-execution plan chain, external anchoring | Plan itself can be withheld if never anchored |
| Operator | Reuse a capture for another run | Capture bound to runId, subject, scope, profile, evaluator | None known beyond key compromise |
| Cell vendor | Vendor silently changes isolation | Egress re-probe at restore | Probe covers only sampled destinations |

## Alternatives

Trust adapter-reported observations (status quo): cheap, unauditable. Require TEE remote attestation: a stronger root of trust but not portable, not available for subscription agent lanes, and the project cannot fund hardware dependency now; kept as a future `attested` claim class. Signing every byte of the transcript: heavy, leaks private traces, and a signature still proves only that the harness said it. Aligning with in-toto/SLSA style attestations (subject digest plus typed predicate) is attractive for tooling reuse; the predicate shape here is KYA-specific and a mapping is future work. in-toto and SLSA were not fetched for this ADR and are cited from memory (unverified): https://in-toto.io/ and https://slsa.dev/.

## Consequences

A relying party can require that environment, tool surface, denials and egress were measured by an accountable capture issuer, and can detect omitted or unplanned runs. Cost is a harness that owns the tool boundary; agents with native tool surfaces outside it (shell inside a vendor product) get only `declared` or `configured` classes, and policies requiring `measured` will mark those checks unknown. A malicious or compromised capture host can sign anything: this ADR moves trust from the agent to the capture issuer, it does not remove trust. Signature proves key possession, not truthful execution (AGENTS.md). Capture says nothing about quality of the agent's output, only about conditions of the run.

Claim ceiling: proves a trusted key signed these measurements bound to this run. Does not prove the host was honest, that unlisted surfaces were unused, that probes were representative, or that the run is typical of production.

Adapted ideas (no code, no data) from the private Gradia project's verified-egress ADR: measure the network from inside the cell at boot and at every restore rather than trusting configuration; application-layer assertion; IP-literal targets so a DNS failure is not read as a block; root-only probe unreachable by the subject; refuse enforcement rules the backend cannot apply; and retention of planned attempts with unconditional denominators.

## Validation

Test-first: schema strictness and signature tests; binding mutation tests (wrong run, subject, scope, profile, evaluator each rejected); capture-issuer equals evaluator key rejected; class downgrade (`configured` presented as `measured`) rejected under `requireCapture`; ledger reconciliation yielding `omitted-run` and `unplanned-run`; hash-chain tamper detection; egress mismatch yields non-pass, not removal; `unobserved` missing from a record rejected. Adversarial control reproducing the unobserved-surface marker experiment must change from qualifying to unresolved. Mutation controls remove each gate (issuer role, binding, reconciliation) and must be detected. Privacy test: no raw argument bytes in the public record.
