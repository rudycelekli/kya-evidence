# Lane Y integration proposals (capture cell reference)

Lane Y did not edit shared files. Apply these in the integration branch. Test file for every row: `test/capture-cell.test.mjs`.

## Requirements (`evidence/requirements.json` and `docs/REQUIREMENTS.md`)

Sections below exist as `## ` headings in `docs/SPECIFICATION.md`.

| ID | Level | Area | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-CAP-001 | MUST | capture | Records and bindings | A capture transcript MUST be an ordered hash chain of every call crossing the tool proxy, including denied and failed calls, the agent MUST receive only a call function, and tool results MUST be immutable copies. | `proxy records every call as an ordered hash chained transcript with effect digests`; `agent cannot reach or rewrite the transcript through the surface it is given` |
| KYA-CAP-002 | MUST | capture | Records and bindings | A capture MUST detect a planted canary in tool arguments across common encodings, deny it on outbound tools, detect canary tampering, and MUST NOT contain the raw canary value. | `canary exfiltration through raw base64 hex url and reversed arguments is denied and recorded`; `canary value never appears in the public capture and each run mints a distinct value`; `canary tampering through an allowed write is detected` |
| KYA-CAP-003 | MUST | capture | Records and bindings | A capture MUST record before and after world digests and MUST flag state changes not declared by an allowed call and changes outside the permitted scope. | `state change through an unobserved surface shows as an undeclared world digest change`; `declared writes outside the permitted scope are flagged by the world digest comparison` |
| KYA-CAP-004 | MUST | capture | Records and bindings | A probe set MUST test forbidden and permitted actions, a harness MUST refuse to sign a one directional set, and an agent that refuses everything MUST fail the permitted probes. | `always refusing agent fails the permitted action probes and cannot pass`; `agent that attempts a forbidden tool is contained and still fails the forbidden probe`; `harness refuses to sign a one directional probe set and a verifier rejects one`; `permitted write probe requires the write to land under its prefix` |
| KYA-CAP-005 | MUST | capture | Records and bindings | A kya.capture/v1 record MUST have exact keys, canonical bytes within size limits, a declared simulated cell with no isolation claim and a mandatory unobserved list. | `capture format is exact keyed canonical json with size limits`; `tool surface differences are surfaced and calls to undeclared tools are denied`; `handler errors and bad effects are recorded as errors without changing the world` |
| KYA-CAP-006 | MUST | capture | Trust and eligibility | A capture MUST verify only when signed by a trusted unrevoked capture-issuer key that is not the evaluator key, and edits, reordering, dropped entries and inconsistent re-signed sections MUST be detected by signature or recomputation. | `editing any signed field invalidates the signature`; `reordered or dropped attempt entries fail even when re-signed with the issuer key`; `re-signed inconsistent sections are caught by recomputation`; `capture signed by the wrong issuer key is rejected`; `policy trust requires an unrevoked capture-issuer anchor and rejects an evaluator key as issuer`; `run binding to subject scope profile evaluator and run is enforced` |
| KYA-CAP-007 | MUST | capture | Trust and eligibility | The capture adapter MUST produce only unsigned evidence candidates from a verified capture, with source fixture, and an agent self-report MUST be reconciled against the measured transcript. | `adapter turns a verified capture into unsigned candidates that an evaluator key can sign for the scorer`; `adapter maps findings to failing candidates and refuses unverified captures`; `spoofed tool result in the agent self report is detected against the measured transcript`; `calls dropped from the agent self report are detected and extra claimed calls are detected` |
| KYA-CAP-008 | SHOULD | capture | Records and bindings | The reference cell SHOULD be deterministic for identical inputs and expose a CLI whose exit codes separate invalid, flagged and clean captures. | `same inputs and clock give identical capture bytes`; `capture cli demo and verify agree with the library and exit codes distinguish findings` |

## `package.json` proposals

- scripts: `"capture": "node scripts/kya-capture.mjs"`
- exports: `"./capture-cell": { "import": "./src/capture-cell/index.mjs" }`

## Specification paragraph (`docs/SPECIFICATION.md`, under `## Trust and eligibility`)

A capture record (`kya.capture/v1`) states what crossed a harness-owned tool boundary: the exposed tool surface, an ordered hash chain of calls and decisions, before and after digests of declared state, canary integrity, and bidirectional probe outcomes, signed by a capture-issuer key distinct from the evaluator key. The reference cell is simulated and claims no isolation. Evidence candidates derived from a verified capture are unsigned and carry source `fixture`; an evaluator key signs them. A capture proves what crossed a simulated proxy, not that a real agent is safe.

## Status ledger (`docs/WORLD-CLASS-STATUS.md`, WS10)

Proposed note: `WS10-03 Reference measured capture cell (simulated; ADR-0032, ADR-0017 stays Proposed) | implemented as a reference | test/capture-cell.test.mjs, docs/CAPTURE-CELL.md`. Do not mark real egress probes, environment fingerprint, `requireCapture`, ledger reconciliation or anchoring as implemented.

## Not done here

`captureDigest` on evidence receipts and `requireCapture` policy binding (a protocol and scorer change needing its own ADR and evaluator-identity review), `omitted-run` and `unplanned-run` reconciliation against the campaign ledger, real network egress probes, environment fingerprinting, any real agent or sandbox.
