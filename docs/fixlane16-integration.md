# Fix lane 16: deterministic gzip and diagnosable vector drift

Status: proposal for the integrator. `evidence/requirements.json` is not edited by this lane, and nothing under `src/conformance/` was touched. Nothing was published, tagged, released, dispatched or announced, and nothing used the network.

## Problem

On GitHub CI (Ubuntu x64, Node 22) the assessment vector generator produced different bytes from the committed file, while the same branch passes on macOS arm64. The first differing vector is a `verify-credential` vector whose status list was compressed with `node:zlib`. Node ships a fork of zlib whose match finder, hashing and OS header byte depend on the build and the hardware, so two machines can emit different valid GZIP streams for the same input. This lane replaces `node:zlib` compression wherever compressed bytes end up in a committed or signed artifact, and makes a drift failure readable.

## What changed

| File | Change |
| :--- | :--- |
| `src/shared/gzip-deterministic.mjs` | New zero-dependency encoder: fixed header (mtime 0, XFL 0, OS 255), greedy LZ77 with fixed parameters (window 32768, chain 64, no 3-byte match farther than 4096), one fixed-Huffman block, own CRC32 and ISIZE. |
| `src/vc-bridge/status.mjs` | `encodeList` uses it, so exported status lists and every signed credential that embeds one are byte-reproducible. Decoding still uses `node:zlib` `gunzipSync` with the same bound. |
| `scripts/lib/vectors-credential.mjs` | The list builder and the inflate-past-the-bound vector use it. |
| `scripts/lib/vector-drift.mjs`, `scripts/assessment-vectors.mjs`, `test/assessment-vectors.test.mjs` | A drift now reports the first differing byte offset and line, the first differing vector id, the JSON path, both values (truncated) and 200 characters of escaped context from each side. Both the test and `--check` use it. |
| `test/gzip-deterministic.test.mjs` | Nine tests, including a golden test that pins exact output bytes. |
| `evidence/assessment-vectors.json` | Regenerated. The earlier 485 vectors are byte for byte identical (the pinned test passes unchanged). |

## Cost, measured

The fixed-Huffman encoder compresses less than zlib level 9. A 131072 entry status list with bits 3, 77 and 99999 set: encoded list 83 characters before, 180 after. The 2097153 byte all-zero list of the inflate-past-the-bound vector is 13231 bytes of GZIP (about 17.7 thousand characters encoded), far below the 1,048,576 character limit, and still a small stream next to its 2 MiB of output. Both are small against the limits that matter; the price of the guarantee is bytes, not correctness.

## Ingredients audited

| Ingredient | Result |
| :--- | :--- |
| `gzipSync` level 9 in `encodeList` (status.mjs) | Fixed: replaced. |
| `gzipSync` in the credential vector generator (list builder and the bomb vector) | Fixed: replaced. |
| GZIP header OS byte written by zlib | Fixed with the above (the new header writes 255 always). |
| `gzipSync` in `scripts/pack.mjs` (release archive, level 9) | NOT changed: it is not in a vector or a signed credential, but the same platform dependence applies to the archive bytes and the receipt hash. Recommend the integrator decide whether to switch it to the new encoder. |
| `gzipSync` in tests (bombs, release fixtures) | Not committed bytes; they only feed decoders. Left alone. |
| Sorting (`sort()` without a comparator, comparator on `<`) | Ruled out: string order is by UTF-16 code unit, defined by the language. No `localeCompare`, `Intl` or `toLocale*` anywhere under `src/`, `scripts/lib` or the generators. |
| `readdir` order | Ruled out for the generators: the two uses (`src/suites/identity.mjs`, `src/research/application/universe.mjs`) sort by name before use; the generators read no directory. |
| `Math.*` | Ruled out: only `Math.sqrt` (Wilson interval, score card standard deviation, second implementation), which IEEE 754 requires to be correctly rounded, plus floor, min, max, round, abs. No exp, log, pow or trigonometry. The bootstrap uses a seeded sfc32 generator over SHA-256 and integer arithmetic. Basic arithmetic is IEEE double in every engine, and JavaScript does not fuse multiply-add. |
| Number formatting | Ruled out: JSON number text is the language-defined shortest round trip form; no `toFixed`, `toPrecision` or locale formatting in the score code or generators. |
| Date and time zone | Ruled out for the generators: every time is a fixed ISO string; `new Date(ms).toISOString()` is always UTC. Defaults of `new Date()` exist in the library for callers that omit `now`; no generator omits it. |
| Randomness | Ruled out: generators use public synthetic seeds. `randomBytes` and `randomUUID` live in holdout, privacy, canary and conformance runner code that no generator calls. |
| Signatures and hashes | Ruled out: Ed25519 (RFC 8032) is deterministic; SHA-256 is exact. OpenSSL or another provider cannot change the bytes. |
| `process.platform`, `process.env`, line endings | Ruled out for generators and the vector-relevant library; the only hits are probes in `src/conformance/infrastructure/probes.mjs`, which no vector calls. |

## What is NOT verified

Linux was not available. That the generator now reproduces the committed file on Ubuntu x64 is verified only by CI. The encoder is deterministic by construction (no platform input is read), and a golden test pins its output, but no run on another platform was made here.

## Requirement proposals

Not added to `evidence/requirements.json`. Each id is three letters then three digits, each test title is exact and exists once in the named file, and the section is an existing `## ` heading of `docs/SPECIFICATION.md`.

| Proposed ID | Level | Area | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-DET-001 | MUST | credential | Interoperability and versioning | The encoded status list that the reference exports MUST be a pure function of the bitstring, with a fixed GZIP header and no dependence on the platform, so that an exported credential is byte-reproducible. | `encodeList uses the deterministic encoder so exported status list bytes are pinned`; `deterministic gzip golden bytes pin the exact output so a platform difference fails loudly`; `deterministic gzip is repeatable and independent of the input container type` |
| KYA-DET-002 | MUST | credential | Interoperability and versioning | The deterministic GZIP output MUST decode to the original bytes with a standard decoder and carry a correct CRC32 and size trailer. | `deterministic gzip round trips empty zeros ones and seeded random input through node zlib`; `deterministic gzip writes a fixed header and a correct CRC32 and ISIZE trailer`; `deterministic gzip output decodes with an independent python gzip decoder` |
| KYA-DET-003 | MUST | vectors | Interoperability and versioning | A drift between the generated and the committed vectors file MUST be reported with the first differing vector id, the JSON path and bounded escaped context. | `drift description names the first differing vector id, the JSON path and bounded escaped context` |
