# Fix lane 7 integration notes

Requirement proposals for the owner. `evidence/requirements.json` is not edited by this lane.

## Proposed requirements

| Proposed ID | Statement | Test (exact title, test/core-adversarial.test.mjs) | Section of docs/SPECIFICATION.md |
| :--- | :--- | :--- | :--- |
| KYA-SEC-NEW-1 | The kya-check workspace confinement refuses an input path routed through a symlinked workspace directory even when the directory name begins with two dots. | kya-check refuses an input path routed through a workspace directory whose name starts with two dots | `## Trust and eligibility` |
| KYA-SEC-NEW-2 | The capture verify CLI accepts the five binding pins and reports `bound`, so a clean exit is not mistaken for a pinned verification. | capture cli verify takes binding pins and reports whether the capture is bound | `## Records and bindings` |

## Reproduced but deliberately not changed

- `checkCurrency` treats the instant equal to `validUntil` as current, while `assess` at that instant rejects the manifest and receipts (expiry is exclusive there). Result: `reliable: true` for one millisecond at which a fresh assessment would not qualify. The behaviour is pinned by the normative vector `currency.at-validity-boundary-is-current` (KYA-MON-001), so changing it is a specification and vector decision. Proposal: make `validUntil` exclusive (`at >= validUntil` fires `assessment-expired`) and regenerate the vector.
- `kya-capture verify` without pins still exits 0 for a valid, finding-free capture. Existing tests expect that; the output now says `bound: false`.

## Not reproduced

Parser differential and idempotence fuzz (400k mutations of parseJson against JSON.parse), Ed25519 S malleability, capture leaf mutation with re-signing by the issuer (only free labels survive), resource limits for 99k numbers, 1 MB whitespace, 30k keys, 300 distinct signing keys.
