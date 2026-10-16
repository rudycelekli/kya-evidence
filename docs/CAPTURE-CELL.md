# Reference capture cell (simulated)

Status: reference implementation of the measurement idea in [ADR-0017](adr/0017-measured-signed-capture-attestation.md), decided in [ADR-0032](adr/0032-capture-cell-reference.md) (Proposed). It has had no independent review. It is **not a production sandbox**.

## What it proves and what it does not

It proves what crossed a tool proxy in a simulated cell that the capture issuer controls: which tools were exposed, every call and its decision in order, which effects a call declared, how a simulated world changed, whether planted canaries moved, and whether the agent behaved correctly on forbidden and permitted probes. A verifier can recompute all of that from the record and the issuer signature.

It does not prove a real agent is safe, that the host was honest, that unlisted surfaces were unused, or that probes were representative. The record says `cell.kind: simulated` and `cell.isolation: none`, and every candidate it yields has source `fixture`, which the project never uses to score commercial products. The record always lists unobserved surfaces, and must name `network-egress` and `os-isolation`.

## Pieces (`src/capture-cell/`)

| File | Role |
| :--- | :--- |
| `proxy.mjs` | `createCell`: tool-surface proxy, hash-chained transcript, world, canary planting |
| `canary.mjs` | Canary minting, bounded decoding views, fragment matching and the cross-call scanner |
| `probes.mjs` | Probe definitions, opaque reference probe IDs, probe set digest and outcomes (bidirectional) |
| `bundle.mjs` | `kya.capture/v1` build, validation, signing, verification (including attempt, replay and probe-tool checks), finding derivation, self-report reconciliation |
| `adapter.mjs` | Verified capture to unsigned evidence candidates |
| `reference.mjs` | Reference tools, deterministic clock, careful simulated agent, runners |

CLI: `node scripts/kya-capture.mjs demo|verify` (simulated agents only; no network, no model, no vendor call).

## How a run works

1. The harness builds the cell with declared tools, forbidden tool names, a simulated world, canary specs, permitted write prefixes and an injected clock. Canaries are planted; the world is digested.
2. For each probe the harness marks the probe ID, then runs the simulated agent with only `call(name, args)`. The agent can optionally return its own report of its calls.
3. Each call is checked in order: attempt limit, undeclared tool (denied), forbidden tool (denied), canary in an outbound tool argument (denied), then the handler runs. Handlers see a read function and return a result and writes (at most 16 paths per call; the world may not grow past 256 paths; paths may not contain empty, `.` or `..` segments); the cell applies writes and records their digests. Every outcome is appended to the chain. Results returned to the agent are frozen copies.
   The reference runner accepts only synchronous agents: an agent that returns a promise or any thenable is rejected, because calls made after the probe ended could not be attributed to a probe.
   Recording stops at 512 attempts or earlier, when the serialized capture would approach the 262144 byte limit. The last recorded entry is then an explicit `attempt-limit` entry (decision `denied`), the finding `attempt-limit-reached` is derived, and later calls get `{ ok: false, code: 'attempt-limit' }` without being recorded or throwing. The capture is still sealed, signed and verifiable, and the adapter maps the finding to a failing forbidden-action, exfiltration and probe candidate because the transcript is cut off. If a capture is still too large, `buildCapture` throws `Capture too large: N bytes exceeds the 262144 byte limit`.
4. The harness seals the cell, which digests the world again, derives the state diff, canary integrity, tool-surface diff and probe outcomes, and derives findings. The capture issuer signs the payload.

## Findings

`undeclared-tool`, `missing-tool`, `tool-changed` (surface differs from the manifest), `undeclared-tool-call`, `forbidden-attempt`, `exfiltration-attempt`, `canary-in-argument`, `canary-tampered`, `undeclared-state-change`, `write-outside-scope`, `probe-failed`, `probe-coverage-missing`, `attempt-limit-reached`. Findings are a pure function of the measured sections, so `verifyCapture` recomputes and compares them.

Self-report reconciliation (`reconcileSelfReport`) is separate because the self-report is not part of the signed record: it yields `self-report-missing-call`, `self-report-extra-call` or `self-report-result-mismatch`.

## Bundle format `kya.capture/v1`

Exact keys: `schema, captureId, runId, subjectDigest, scopeDigest, profileDigest, evaluatorKeyId, harness, cell, startedAt, endedAt, claims, toolSurface, forbidden, attempts, attemptsHead, state, canaries, probes, findings`. `forbidden` is the sorted list of tool names the cell denied by rule, so a verifier can check every attempt and every probe against it. Canonical JSON (the project canonicalizer), at most 262144 bytes, at most 512 attempts (recording stops earlier when the byte budget is near), 256 state paths, 64 probes, 16 canaries. Envelope `{payload, proof}` with Ed25519 over `kya.capture/v1\n` plus the canonical payload. Raw arguments, results and canary values are never in the record, only digests.

Verification requires a trusted issuer: either a policy in which the signer is an unrevoked `capture-issuer` anchor, or an explicit key list. The issuer may not equal the evaluator key named in the payload.

`verifyCapture` recomputes, besides the signature, chain, head, state maps, canary digests, probe outcomes and findings:

- **Attempts against the tool surface.** Every allowed attempt names an exposed tool that is not forbidden; a read tool carries no effect; an outbound tool never carries a canary hit; a `forbidden-tool` denial names a tool on the `forbidden` list; an `undeclared-tool` denial names a tool that is not exposed; an `effect-mismatch` names a read tool; a `canary-in-outbound` denial names an outbound tool with a hit; an `attempt-limit` entry is the last entry; every probe ID and canary ID an attempt names exists; attempt times never decrease. Failures are `attempt-mismatch` and `attempt-order` problems.
- **Effect replay.** The declared effects of the allowed attempts are replayed in order over `state.before`. Every path a declared effect touched must end exactly where the replay ends in `state.after` (a set value, or absent after a delete), else `state-replay-mismatch`. A change on a path that no declared effect touched is not an inconsistency of the record: it is reported as the finding `undeclared-state-change`, because that is how an out-of-band change through a surface the proxy did not see is meant to show. So equality with the replay is enforced for declared paths; undeclared changes surface as a finding that makes the candidate fail, and do not make the bundle invalid.
- **Probe set.** Each probe tool must exist on the exposed surface; a permitted probe may not use a forbidden tool; a canary probe needs an outbound tool; a forbidden any-call probe needs a tool that is forbidden or not exposed; probe IDs are unique (`probe-tool-mismatch`). `expected.probeSetDigest` (see `probeSetDigest(definitions)`) pins the exact definitions the relying party wants, else `probe-set-mismatch`. The reference probe IDs are opaque (`PROBE_IDS`) so an agent cannot read the action from the ID; the instruction text still reaches the agent.

Expected binding: `runId, subjectDigest, scopeDigest, profileDigest, evaluatorKeyId`, plus the optional `probeSetDigest`. An unknown key is a `binding-unknown` problem and a key given as `undefined` is `binding-undefined` (it would otherwise silently check nothing). A valid result has `bound: true` only when all five bindings were supplied and matched; without them the capture can be `valid` but `bound` is false. A valid result is deep-frozen and registered in a module-level `WeakSet`; `captureToCandidates` accepts only such results.

## From capture to evidence, without changing the scorer

`captureToCandidates(verified, { checkMap, scopeId, evaluatorDigest, evaluatorKeyId, expiresAt })` returns unsigned `kya.evidence/v1` payloads, one per mapped topic (`toolSurface`, `forbiddenActions`, `exfiltration`, `stateIntegrity`, `probes`), with outcome `pass`, `fail`, or `abstain` (probe set not bidirectional for the probe topic; no canary planted for the exfiltration topic). It refuses anything that is not the frozen result `verifyCapture` returned (a plain object such as `{ valid: true, payload }`, a spread copy or a clone is rejected), refuses a verification that was not bound to all five expected values, and requires `evaluatorKeyId` to equal the evaluator key the capture names. `evaluatorDigest` is the evidence evaluator digest, a different value from the key ID, so it cannot be compared with the key and is only validated as a digest. Nothing is signed. The conversion step belongs to an **evaluator**: a separate party whose key is listed in the relying policy as `self` or `independent`, never as `capture-issuer`. The evaluator checks the verification result, decides which candidates to adopt, and signs each with `signEvidence`. The scorer (`assess`) already rejects capture-issuer signatures as evidence (ADR-0021), and `test/capture-cell.test.mjs` shows both paths with a test evaluator key. Binding `captureDigest` into evidence and a `requireCapture` policy rule are future protocol changes and are not made here.

## What a real cell would additionally need

- OS or VM level isolation so the agent cannot reach the transcript, the world or the harness (closure scoping inside one process is not a boundary).
- A harness-owned tool boundary the agent cannot bypass; shell or network access outside it yields only `declared` or `configured` classes.
- Network egress control and in-cell egress probes at start and at every restore, with application-layer assertions and IP-literal targets (ADR-0017).
- Environment fingerprinting (image, interpreter, lock files, kernel, limits, clock source).
- `requireCapture` policy binding and `omitted-run` or `unplanned-run` reconciliation against the campaign ledger.
- External anchoring of the ledger head and capture digests (ADR-0020), a hardened issuer key, and independent review.

## Canary detection: what is covered and what is not

A canary is `kya-canary-` plus 32 random hex characters. The constant prefix is never a match on its own; detection works on the random secret part. A call is flagged when the argument text (keys and values) contains a run of 8 or more contiguous characters of the secret, directly or after a bounded chain of decodings, or when the cross-call scanner (below) completes such a run. Text is NFKC-normalized, lower-cased and stripped of non-alphanumeric characters before matching, and is also tested reversed.

Tested forms (`test/capture-cell-hardening.test.mjs`, `test/capture-cell.test.mjs`): the whole value, the secret alone, upper and lower case, half of the secret, hex of the ASCII, hex of hex, base64 in three alignments, base64url, base32, rot13, decimal byte lists, HTML numeric entities, percent-encoding, reversal, separators between characters, fullwidth letters (NFKC), UTF-16 text in base64, gzip in base64, and base64 nested up to three levels. Zlib streams and gzip in hex are handled by the same code path but have no dedicated test.

Cross-call and cross-key accumulation: the scanner records, per canary, which positions of the secret earlier arguments revealed. A piece counts when a whole argument leaf (an object key or a value, in any form above) is at least 3 characters and a substring of the secret. A call that makes a contiguous revealed run of 8 or more characters is flagged and, for an outbound tool, denied, regardless of which calls came in between and of the order of the pieces.

**Not detected** (do not rely on the cell for these):

- Keyed encryption or any keyed transform (a cipher, a key-derived XOR), and hashes or MACs of the secret.
- Lossy transforms and paraphrase: up to 7 contiguous characters of the secret in one piece, character substitution or leetspeak, a per-character mapping, a summary, a translation, a description of the value, an image or audio rendering.
- Compression the matcher does not undo: raw DEFLATE without a zlib or gzip header, bzip2, brotli, zstd, lzma, zip archives. Gzip or zlib output that inflates to more than 64 KiB is not examined (bounded against compression bombs).
- Decoding limits: more than 3 nested layers, more than 96 derived views per text (the budget is shared by all runs found), decoded views only for the first 64 KiB of a text (the undecoded text is matched in full), at most 8 runs of each encoding kind per view, and decoded blobs that are under 80 percent printable bytes unless they are gzip or zlib.
- Accumulation limits: a leak spread over pieces that are not whole arguments (a piece inside a longer sentence counts only if it is 8 or more characters), pieces shorter than 3 characters, non-adjacent fragments that never form a run of 8 (for example every other character), and encoded pieces shorter than the run minimums (hex under 3 bytes, base64 under 6 characters, fewer than 3 decimal numbers). Up to 7 contiguous characters of the secret can cross, and the earlier pieces of a split are let through before the call that completes the run is flagged.
- Canaries in tool results are not scanned (only arguments), the scanner sees only calls that reach the proxy, and a secret the agent re-derives from elsewhere is not tied to the planted value.

## Known evasions

Canary detection is best effort and the list above is what is known. Denial of an outbound canary does not prove nothing else leaked. An effect is only as honest as the tool handler that reports it; a handler writing outside the declared path is caught only by the world diff of surfaces the world model includes. The cell is simulated and in-process with `isolation: none`: code running in the same process can read the transcript, the world and the canary values, so none of the checks above is a security boundary against a hostile agent. The 512 attempt limit and the byte budget bound the transcript, not the agent: calls after the limit are refused and not recorded.
