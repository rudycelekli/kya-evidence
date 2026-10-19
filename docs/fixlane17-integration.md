# Fix lane 17: deterministic release archive

## What changed

`scripts/pack.mjs` compressed the release tar stream with `gzipSync` level 9. The tar stream was already deterministic (entries sorted by path, uid and gid 0, mtime 0, mode 0644 or 0755 for `bin/kya.mjs`, no clock, no host fields), but the gzip bytes of node zlib depend on the build and the hardware. The archive and `archiveSha256` could therefore differ between machines. The archive now uses `gzipDeterministic` from `src/shared/gzip-deterministic.mjs`.

## Measured on the real package

| | zlib level 9 | repository encoder |
| :--- | :--- | :--- |
| Tar stream | 12,925,952 bytes | same |
| Compression only | 164 ms | 293 ms |
| Archive | 1,310,568 bytes | 1,597,168 bytes (371 files after this change; the encoder alone gives 1,595,365 on the old tar) |
| `node scripts/pack.mjs` wall time (loaded machine) | 8.4 s | 8.6 s |

The new archive is about 22 percent larger and the time cost is a fraction of a second, so the single fixed-Huffman block choice is kept and documented in `docs/RELEASING.md`. The decompressed tar stays well under the 20,000,000 byte limit of the verifier.

## What is not verified

Linux was not available. That two machines now produce the same archive is verified only by CI, and the CI step packs twice on one runner. The receipt records `build.node`, so it is not byte-identical across Node versions.

## Requirement proposals

Not added to `evidence/requirements.json`. Each id is three letters then three digits, each test title is exact and exists once in the named file, and the section is an existing `## ` heading of `docs/SPECIFICATION.md`.

| Proposed ID | Level | Area | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-DET-004 | SHOULD | release | Interoperability and versioning | The release archive SHOULD be a pure function of the committed blobs, with a fixed GZIP encoder, so that the same commit gives the same archive bytes on any machine. | `pack builds the release archive twice in clean directories with byte identical output`; `pack golden archive over a tiny fixed file tree pins the exact bytes`; `pack source does not call node zlib gzip so the archive bytes do not depend on the build of zlib` |
