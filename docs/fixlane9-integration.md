# Fix lane 9: adversarial core hardening round 2, integration note

Status: proposal for the integrator. `evidence/requirements.json` is not edited by this lane. All tests live in `test/fixlane9-adversarial.test.mjs`. Round 1 is in `test/core-adversarial.test.mjs`. Nothing under `src/conformance/`, `src/kya-score/` or `scripts/kya-score.mjs` was touched.

## Surfaces, attacks tried, holes found

| Surface | Attacks tried | Result |
| :-- | :--- | :--- |
| VC bridge JWS and VC verify | alg none, alg none with a valid signature attached, HS256 keyed with the public key PEM, jwk, jku, x5u, crit with b64 false, kid pointing at another did:key, duplicate header members (plain, and with a unicode-escaped alias of the member name, both signed), detached payload, trailing and leading dot, padded and truncated base64url, empty signature, signature S plus the group order, 2 MB segment, `__proto__` payload member, vc claim inside the payload, issuer with fragment or newline, status list map keyed by `__proto__`, `toString`, `constructor` | No hole. Every case refused with a stable code (see the pin tests). |
| Interop bridge exports | Self-digested report with out-of-vocabulary decision, evidenceMode, ids, limitations, score and coverage values, with bidi, C1, zero-width, line separator and newline characters; missing members; prototype keys | Hole found: exports relayed those members verbatim. Fixed. |
| Campaign ledger and runner | Reviewed against the existing 30-plus tests: truncation and rollback need an external head pin (documented), reordering and edits break the chain, time regression and entry-before-plan are refused, a stale lock is never stolen, concurrent runs refuse, a signal releases only its own lock | Not reproduced. Replay of an older valid ledger without a pinned head stays undetectable by design and is documented in `scripts/kya-campaign.mjs` help. |
| Dossier build and verify, privacy scan | Symlink and traversal entries, redaction by case, fullwidth at sign, regex time-boxing with 20k to 100k character strings of 24 shapes | Display path with leading dots: not a hole, see below. Scanner regexes are linear (4x input, 4x time). Scanner redaction by zero-width insertion or fullwidth digits is a documented false negative class (`LIMITATIONS`), not changed. |
| Terminal and rendered output | Agent name, file name, credential member and error text carrying C1 (U+009B), bidi overrides and isolates, zero-width, U+2028, tag characters | Hole found: JSON output of the CLIs, `kya-check` text, privacy-scan text and the dossier views passed them through. Fixed with one shared helper. |
| Resource limits | 4096 evidence (1.4 s), 4097 refused, 4096 junk envelopes, 1 MB deep and wide JSON through `parseJson` (depth 32, 100k nodes) | Hole found: `kya-vc`, `kya-bridge` and `conformance-report --verify` read input files without a size or type bound (a 300 MB file used 694 MB of memory before it was rejected; a device file never ends). Fixed. |

### Display path with a leading double dot

`display()` in `scripts/privacy-scan.mjs` tests `rel.startsWith('..')`. A file inside the working directory whose first path component starts with two dots (for example `..data/x.json`) is labelled as external: `[external:<8 hex>]/x.json`. It is still scanned, the label is a hash plus the base name (no absolute path is echoed), and two such files get distinct labels. A file outside the working directory always starts with `..` plus a separator or equals `..`, so no outside path can show as relative. Decision: it does not matter for safety, only for label accuracy, so it was left unchanged.

## Fixes

1. `src/shared/terminal.mjs` (new): `terminalJson` (JSON.stringify whose output escapes DEL, C1, soft hyphen, bidi marks and overrides, isolates, zero-width and invisible characters, U+2028/9, BOM, tag characters; the parsed value is identical), `terminalText`, `stripUnsafe`, `hasUnsafe`, `escapeJsonText`. Used by `bin/kya.mjs`, `kya-bridge`, `kya-vc`, `kya-capture`, `kya-campaign`, `kya-policy-init`, `kya-check` (clean), `conformance-report` and `privacy-scan`. Files written with `--out` keep their original bytes. Digests are never computed over sanitized text.
2. Both dossier and assessment HTML views and the dossier Markdown view show invisible and reordering characters as `[U+XXXX]` markers.
3. `src/assessment/application/report-shape.mjs` (new): `checkReportFields` keeps decision, evidenceMode, ids, limitations, score and coverage inside the assessor vocabulary. The in-toto, OTel, OAuth, SPIFFE, A2A and MCP exports, `verifyBridgeExport` and the VC export call it. `serialize` writes invisible characters as JSON escapes.
4. `scripts/lib/bounded-read.mjs` (new): `readBounded` opens the file, takes the size from the handle, and refuses anything that is not a regular file of at most 2 MiB. Used by `kya-vc`, `kya-bridge` and `conformance-report --verify`.

## What was not tried

- Terminals themselves: no emulator was driven, so which terminals act on C1 controls is from the published behavior of the character set, not observed here.
- Rendered Markdown in any hosting product; only the escaped bytes were checked.
- Timing side channels in signature verification and in `timingSafeEqual` uses.
- A hostile filesystem race (path swapped between `lstat` and read) in the privacy scanner and the dossier directory writer.
- Campaign runs under real adapter processes, kill -9 recovery with a live adapter, and clock skew between machines.
- Windows path semantics for `display()` and the private directory checks.
- Fuzzing `parseJson` beyond the structure limits; very long single strings near the 1 MB cap in every CLI.
- Anything in `src/kya-score`, `src/conformance` or the pinned evaluator.

## Requirement proposals

IDs are suggestions. Spec headings exist in `docs/SPECIFICATION.md`.

### KYA-TRM-001 (MUST, display safety)

- spec: `## Reports and viewers`
- statement: Command output that can carry text from a report, manifest, credential or file name MUST escape or neutralize C1 controls, bidirectional controls, zero-width and invisible characters, and line separators, and a JSON consumer MUST read back the same value.
- test: `fixlane9 terminal json escapes C1 bidi zero width and separators and parses back identically`
- test: `fixlane9 strip and text helpers neutralize every invisible or reordering character`
- test: `fixlane9 kya assess output carries no raw bidi or C1 characters from an agent name`
- test: `fixlane9 kya-vc verify output carries no raw bidi or C1 characters from a foreign credential`
- test: `fixlane9 kya-check clean strips bidi and zero width characters`
- test: `fixlane9 privacy scan text and json output neutralize control and bidi characters in file names`

### KYA-TRM-002 (MUST, rendered views)

- spec: `## Reports and viewers`
- statement: The dossier and assessment views MUST show invisible and reordering characters from supplied text as visible markers.
- test: `fixlane9 dossier markdown and html make invisible characters in the agent name visible`

### KYA-IBR-009 (MUST, export vocabulary)

- spec: `## Interoperability and versioning`
- statement: A bridge or VC export MUST refuse a report whose decision, evidence mode, identifiers, limitations, score or coverage fall outside the assessor vocabulary, even when the report digest is consistent, and the export bytes MUST carry no raw invisible or reordering characters.
- test: `fixlane9 bridge exports refuse a self digested report whose fields leave the report vocabulary`
- test: `fixlane9 bridge serialize escapes invisible characters without changing parsed content`

### KYA-CLI-002 (MUST, bounded input)

- spec: `## Interoperability and versioning`
- statement: Every command line entry point MUST refuse an input that is not a regular file within the size limit before reading it.
- test: `fixlane9 kya-vc kya-bridge and conformance-report refuse an oversized input file before reading it`

### KYA-VCB-016 (MUST, pins of refused attacks)

- spec: `## Trust and eligibility`
- statement: VC verification MUST refuse duplicate or aliased header members, crit and b64 headers, embedded key headers, HMAC with a public key, detached payloads, non-canonical encodings, malleable signatures and prototype-keyed status list lookups.
- test: `fixlane9 vc verify refuses duplicate header members even when the signature covers them`
- test: `fixlane9 vc verify refuses crit b64 false jwk and HMAC with the public key as secret`
- test: `fixlane9 vc verify refuses detached payloads trailing dots padding and a malleable signature`
- test: `fixlane9 vc status lookup ignores prototype keys in the supplied status list map`

### KYA-PRV-006 (SHOULD, scanner cost)

- spec: `## Reports and viewers`
- statement: The privacy scanner SHOULD stay linear in input size on adversarial strings.
- test: `fixlane9 privacy scan stays linear on adversarial one hundred thousand character strings`
