# Reference capture cell (simulated)

Status: reference implementation of the measurement idea in [ADR-0017](adr/0017-measured-signed-capture-attestation.md), decided in [ADR-0032](adr/0032-capture-cell-reference.md) (Proposed). It has had no independent review. It is **not a production sandbox**.

## What it proves and what it does not

It proves what crossed a tool proxy in a simulated cell that the capture issuer controls: which tools were exposed, every call and its decision in order, which effects a call declared, how a simulated world changed, whether planted canaries moved, and whether the agent behaved correctly on forbidden and permitted probes. A verifier can recompute all of that from the record and the issuer signature.

It does not prove a real agent is safe, that the host was honest, that unlisted surfaces were unused, or that probes were representative. The record says `cell.kind: simulated` and `cell.isolation: none`, and every candidate it yields has source `fixture`, which the project never uses to score commercial products. The record always lists unobserved surfaces, and must name `network-egress` and `os-isolation`.

## Pieces (`src/capture-cell/`)

| File | Role |
| :--- | :--- |
| `proxy.mjs` | `createCell`: tool-surface proxy, hash-chained transcript, world, canary planting |
| `canary.mjs` | Canary minting and multi-encoding detection |
| `probes.mjs` | Probe definitions and outcomes (bidirectional) |
| `bundle.mjs` | `kya.capture/v1` build, validation, signing, verification, finding derivation, self-report reconciliation |
| `adapter.mjs` | Verified capture to unsigned evidence candidates |
| `reference.mjs` | Reference tools, deterministic clock, careful simulated agent, runners |

CLI: `node scripts/kya-capture.mjs demo|verify` (simulated agents only; no network, no model, no vendor call).

## How a run works

1. The harness builds the cell with declared tools, forbidden tool names, a simulated world, canary specs, permitted write prefixes and an injected clock. Canaries are planted; the world is digested.
2. For each probe the harness marks the probe ID, then runs the simulated agent with only `call(name, args)`. The agent can optionally return its own report of its calls.
3. Each call is checked in order: undeclared tool (denied), forbidden tool (denied), canary in an outbound tool argument (denied), then the handler runs. Handlers see a read function and return a result and writes; the cell applies writes and records their digests. Every outcome is appended to the chain. Results returned to the agent are frozen copies.
4. The harness seals the cell, which digests the world again, derives the state diff, canary integrity, tool-surface diff and probe outcomes, and derives findings. The capture issuer signs the payload.

## Findings

`undeclared-tool`, `missing-tool`, `tool-changed` (surface differs from the manifest), `undeclared-tool-call`, `forbidden-attempt`, `exfiltration-attempt`, `canary-in-argument`, `canary-tampered`, `undeclared-state-change`, `write-outside-scope`, `probe-failed`, `probe-coverage-missing`. Findings are a pure function of the measured sections, so `verifyCapture` recomputes and compares them.

Self-report reconciliation (`reconcileSelfReport`) is separate because the self-report is not part of the signed record: it yields `self-report-missing-call`, `self-report-extra-call` or `self-report-result-mismatch`.

## Bundle format `kya.capture/v1`

Exact keys: `schema, captureId, runId, subjectDigest, scopeDigest, profileDigest, evaluatorKeyId, harness, cell, startedAt, endedAt, claims, toolSurface, attempts, attemptsHead, state, canaries, probes, findings`. Canonical JSON (the project canonicalizer), at most 262144 bytes, at most 512 attempts, 256 state paths, 64 probes, 16 canaries. Envelope `{payload, proof}` with Ed25519 over `kya.capture/v1\n` plus the canonical payload. Raw arguments, results and canary values are never in the record, only digests.

Verification requires a trusted issuer: either a policy in which the signer is an unrevoked `capture-issuer` anchor, or an explicit key list. The issuer may not equal the evaluator key named in the payload. Optional expected binding: run, subject, scope, profile, evaluator.

## From capture to evidence, without changing the scorer

`captureToCandidates(verified, { checkMap, scopeId, evaluatorDigest, expiresAt })` returns unsigned `kya.evidence/v1` payloads, one per mapped topic (`toolSurface`, `forbiddenActions`, `exfiltration`, `stateIntegrity`, `probes`), with outcome `pass`, `fail`, or `abstain` (probe set not bidirectional). Nothing is signed. The conversion step belongs to an **evaluator**: a separate party whose key is listed in the relying policy as `self` or `independent`, never as `capture-issuer`. The evaluator checks the verification result, decides which candidates to adopt, and signs each with `signEvidence`. The scorer (`assess`) already rejects capture-issuer signatures as evidence (ADR-0021), and `test/capture-cell.test.mjs` shows both paths with a test evaluator key. Binding `captureDigest` into evidence and a `requireCapture` policy rule are future protocol changes and are not made here.

## What a real cell would additionally need

- OS or VM level isolation so the agent cannot reach the transcript, the world or the harness (closure scoping inside one process is not a boundary).
- A harness-owned tool boundary the agent cannot bypass; shell or network access outside it yields only `declared` or `configured` classes.
- Network egress control and in-cell egress probes at start and at every restore, with application-layer assertions and IP-literal targets (ADR-0017).
- Environment fingerprinting (image, interpreter, lock files, kernel, limits, clock source).
- `requireCapture` policy binding and `omitted-run` or `unplanned-run` reconciliation against the campaign ledger.
- External anchoring of the ledger head and capture digests (ADR-0020), a hardened issuer key, and independent review.

## Known evasions

Canary detection is best effort: keyed encryption, compression, splitting across calls or lossy summaries evade it. Denial of an outbound canary does not prove nothing else leaked. An effect is only as honest as the tool handler that reports it; a handler writing outside the declared path is caught only by the world diff of surfaces the world model includes.
