# KYA Passport conformance kit

This kit lets an outside implementer check Passport lifecycle verification, witnessed registry lookup verification and terminal downstream receipt verification. It contains 28 frozen lifecycle and proof cases, a separate 20-case authority supplement, and a runner that uses only Python's standard library. The hosted receipt drill is a separate integration exercise.

## Run your implementation

Copy this README, `run.py`, `vectors.json`, and `authority.json` to your test workspace. From the repository root you can run the reference or point the harness to another implementation.

```sh
python3 interop/passport-conformance/run.py --out report.json -- ./your-verifier
python3 interop/passport-conformance/run.py --vectors interop/passport-conformance/authority.json --out authority-report.json -- ./your-verifier
python3 interop/passport-conformance/run.py -- node interop/passport-conformance/reference.mjs
```

If you use the project-authored Python comparison implementation, install `cryptography==50.0.2` in an isolated environment and pass that interpreter as the candidate. It shares byte utilities with the existing Python port, consumes the frozen vectors without calling the JavaScript implementation, and supports the existing Python numeric subset.

```sh
python3 interop/passport-conformance/run.py -- /path/to/venv/bin/python interop/passport-conformance/python_candidate.py
```

Keep the unmodified vectors and report their SHA-256 from the runner alongside the exact candidate source revision and environment. These fixtures use synthetic signing keys. The generator reproduces the public corpus and is not part of candidate execution.

## Candidate contract

Each case starts a new process directly with no shell. The process receives one UTF-8 JSON object on stdin and then EOF.

```json
{"schema":"kya.passport-conformance-input/v1","operation":"passport-history","inputs":{"history":[],"registry":"https://registry.example.test"}}
```

Reply with exactly one UTF-8 JSON object and exit zero. Use the operation supplied in the input. A rejection is an explicit result. Unhandled errors, nonzero exits, timeouts, oversized output and contradictory output count as failures. Unsupported operations have their own outcome and cannot satisfy a refusal case.

```json
{"schema":"kya.passport-conformance-result/v1","operation":"passport-history","status":"reject"}
```

For acceptance, return status `accept` and one `value` field. For unsupported return status `unsupported` without a value. JSON object order is ignored. Arrays, types and member names must match exactly. The runner reports every case and exits nonzero if any case fails or remains unsupported. Run only candidates you trust or isolate the process with your own operating-system sandbox.

## Wire rules

| Operation | Input and result | Specification |
| --- | --- | --- |
| `passport-history` | `history, registry` to Passport ID, agent and principal IDs, head, status, active binding or null, and fingerprints in lifecycle order. V2 also returns controller fingerprint and recovery-enabled marker. | [Passport lifecycle](../../docs/adr/0055-passport-registry.md), [controller recovery](../../docs/adr/0059-passport-controller-recovery.md) |
| `witnessed-lookup` | `query, proof, signed, endorsements, trust, now` to `checkpointDigest, epoch, value`. All required distinct witnesses must endorse the same unexpired checkpoint. The value is the proved result or null for authenticated absence. | [Registry witnesses and lookup](../../docs/adr/0060-witnessed-registry-lookup.md), [witness handoff](../../docs/adr/0061-witness-operator-roster-and-recovery.md) |
| `paired-action` | `proof, context` to principal and agent bindings, manifest and grant digests, and action digest. Context supplies the pinned principal key, audience, permission, nonce, request digest, clock, and revocation inputs. | [Pairing profile](../../docs/PAIRING.md) |
| `witness-roster-chain` | `chain, trust` to the authenticated last roster with its digest and the retired key list in handoff order. Check each predecessor starting with genesis. This exercise verifies the roster chain; it does not prove the handoff checkpoint had valid endorsements. | [Witness handoff](../../docs/adr/0061-witness-operator-roster-and-recovery.md) |
| `downstream-receipt` | `envelope, delivery, publicKey` to `operationId, outcome, receiptDigest`. The terminal signature and original operation, request and route must all match. | [Downstream receipt format](../../docs/adr/0063-hosted-mcp-terminal-receipts.md) |

Use the [canonical byte and cryptographic rules](../../docs/SPECIFICATION.md). Supply explicit UTC time and pinned verification keys from the inputs. Accept only the documented signatures and domain prefixes. The public vectors record the exact values to compare. A successful run establishes agreement on this corpus. Independent operator evidence, live OIDC/MCP results, throughput, split-view detection across organizations and reliability under faults need their own tests.
