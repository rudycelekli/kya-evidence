# Fix lane 22: adversarial hardening, round 3

## What changed

Branch `redteam3`, from merge commit 7d50ed3 (PR #47). New attack tests are in `test/redteam3-adversarial.test.mjs`; each hole below had a failing test first (13 of the first 24 tests failed on the unfixed code; the others record attacks that were already refused), then a minimal fix. Nothing under `src/conformance/` or `interop/python-impl/` was touched, and the vectors file is unchanged.

Holes found and fixed:

- GZIP in status lists accepted more than one stream. `node:zlib` joins concatenated members and ignores trailing zero bytes, other decoders refuse one or both, so the same `encodedList` text was valid for one implementation and invalid for another. `src/shared/gunzip-strict.mjs` now reads exactly one RFC 1952 member (CRC-32, size trailer, reserved flags, header checksum, nothing after the member). The reference and the second implementation both use it (the second implementation has its own copy, written from the RFC text). `docs/SPECIFICATION.md` "Status list check" says so.
- `checkStatus` treated a status list without an `id` as matching an entry without a list URL (both undefined). It now refuses unless both are strings. The contract operation was not reachable this way because it only looks a list up by a string URL.
- `scripts/run-vectors.mjs` hung past its own timeout when the implementation left a child holding stdout (it waited for the pipe to close). The result is now settled on the timeout, the output limit or the exit event, the implementation runs in its own process group and is killed with its children, and it receives only `PATH`, `LANG` and `LC_ALL` (plus the Windows system variables), no tokens and no `NODE_OPTIONS`. A synchronous spawn failure (for example a NUL in the command) read a variable before its declaration and crashed the harness; it is now a normal `cannot start implementation` failure.
- `scripts/lib/package-guard.mjs`: path segments are matched without regard to case (`.ENV`, `.Claude`, `NODE_MODULES`), any name starting `.env` is private, and `.aws`, `.ssh`, `.gnupg`, `.netrc`, `.pypirc`, `.docker`, `.git`, `.jks` and `.keystore` are added. Text markers now include Anthropic style keys (`sk-ant-`), fine grained GitHub tokens, Slack tokens, AWS `ASIA` keys, Google API keys, live Stripe keys, PGP private key blocks, and home paths written with backslashes or in another letter case.
- `scripts/lib/ustar.mjs` (release verification): entries that differ only in letter case are duplicates, and the receipt `sourceCommit` must be a lowercase 40 or 64 character hex Git object name (it was echoed to the terminal unvalidated, so a receipt could carry control or bidi characters into the log).
- `scripts/verify-release.mjs` reads the receipt and the archive through `readBounded` (regular file, bounded size) instead of `readFile`, so a FIFO placed at `dist/release-receipt.json` no longer blocks it.
- `scripts/review-kit-check.mjs`: the command pattern `^\s*` was quadratic on a long run of blank lines (80000 lines took 4.3 s, a megabyte would take minutes); it is now `^[ \t]*`. A path named by a kit counts as present only when it is inside the checkout after `..` and symbolic links are resolved (a kit could cite `docs/../../x` and pass).
- Quoted review kit numbers (`testFiles`, `testDeclarations`, `srcFiles`, `srcLines`) were refreshed with `node scripts/review-kit-check.mjs --print`.

## Not reproduced

- Score card: NaN, Infinity, negative zero (normalised to 0 by canonical form), duplicate item ids and run ids, prototype keys at any depth, held out and item floors, lowering the floor on an edited card, extra floor members, huge counts (stopped by the 100000 value limit of the strict parser), float formatting (the Python verifier already uses an explicit half-up rounding). Passing tests record these.
- GZIP encoder: no input shape made it super linear (1 MB zero, period 7, near periodic and noise inputs finish in tens of milliseconds); output buffer sizing holds for all shapes tried. Deflate bombs and multi-member totals are bounded by the 2 MiB ceiling.
- `KYA_CAMPAIGN_HOLD_FILE` only delays the run until a file exists; it cannot change a result. `KYA_PORT` is validated. No other production code reads the environment.
- Tar traversal, absolute paths, duplicates, symlink and link entries, pax and long name headers, non-ASCII names, a swapped archive and a wrong expected commit were all refused already.
- `describeDrift` prints at most two 120 character values and two 200 character contexts; deep nesting is caught.

## Not tried, or left as a known limit

- A card with three identical repeated runs verifies: the repeat floor counts runs, not independence, and a verifier cannot tell a deterministic subject from copied data. This is stated by the non-claims; no check can close it.
- The package guard remains a blocklist: zero width characters inside a name, base64 or line split secrets are not caught, and the older pattern `sk-` followed by 24 letters also matches inside longer words.
- The harness treats any non-zero exit as a refusal, so an implementation that crashes on every input passes vectors whose only expectation is a refusal. It reads implementation output with a lossy UTF-8 decode. Neither was changed.
- The second implementation adapter reads standard input without a bound before checking its length (the harness never sends more than 4 MiB).
- Python 3 subprocess behaviour of the Python implementation was not attacked (another lane extends it). Windows paths for the process group kill were not run.
- No full test suite and no full mutation harness were run.

## Requirement proposals

Not added to `evidence/requirements.json`. Each id is three letters then three digits in the repository format, each test title is exact and exists once in `test/redteam3-adversarial.test.mjs`, and the section is an existing `## ` heading of `docs/SPECIFICATION.md`.

| Proposed ID | Level | Area | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-VCB-020 | MUST | vcb | Interoperability and versioning | A status list `encodedList` MUST be exactly one GZIP member with a correct CRC-32 and size trailer, clear reserved flags and no bytes after it; a second member or trailing bytes is `STATUS_LIST_INVALID`. | `redteam3 status list decoder refuses a second gzip member and bytes after the member`; `redteam3 status list decoder accepts one member from other encoders and agrees with the second implementation`; `redteam3 status list decoder refuses damaged members and reserved header flags`; `redteam3 status list decoder bounds deflate bombs including across members` |
| KYA-VCB-021 | MUST | vcb | Interoperability and versioning | A status check MUST NOT match an entry to a list when either the entry list URL or the list id is missing. | `redteam3 status check refuses a list without an id when the entry names no list` |
| KYA-VEC-015 | MUST | vec | Interoperability and versioning | The vector harness MUST settle each vector within its timeout even when the implementation leaves children holding its pipes, MUST stop those children, MUST give the implementation no inherited secrets, and MUST report an implementation that cannot start as a failure. | `redteam3 harness settles on timeout when the implementation leaves a child holding its pipes`; `redteam3 harness does not wait for a background child after the implementation exits`; `redteam3 harness gives the implementation a minimal environment`; `redteam3 harness reports an implementation that cannot start instead of crashing`; `redteam3 harness fails every hostile output shape instead of passing or crashing` |
| KYA-REL-013 | MUST | rel | Interoperability and versioning | The package guard MUST match private path segments without regard to case and MUST flag the secret shapes and home path styles listed in the tests. | `redteam3 package guard matches private paths regardless of case and for more credential files`; `redteam3 package guard flags more secret shapes and home paths written in other styles` |
| KYA-REL-014 | MUST | rel | Interoperability and versioning | Release verification MUST refuse entries that differ only in letter case, MUST require the receipt commit to be a Git object name, and MUST NOT block on a receipt that is not a regular file. | `redteam3 release verification refuses entries that differ only in letter case`; `redteam3 release verification refuses a receipt commit that is not a Git object name`; `redteam3 verify-release script refuses a receipt that is not a regular file instead of waiting on it` |
| KYA-RVK-009 | MUST | rvk | Interoperability and versioning | The review kit checker MUST finish in bounded time on a kit with a long run of blank lines and MUST NOT count a path outside the checkout as present. | `redteam3 review kit checker stays fast on a kit with a very long run of blank lines`; `redteam3 review kit checker does not count a path outside the checkout as present` |
