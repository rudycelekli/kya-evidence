# Claim-boundary codes

Every KYA artifact states its limits as English sentences: assessment `limitations`, currency `limits`, dossier limitations, benchmark and catalog limitations, bridge export `limits`, declaration-import and inventory limitations, universe limitations, the SPIFFE association note and the credential warning. Free text cannot be filtered, diffed or checked by a program. This registry gives each sentence a stable code.

## What a code means

A claim-boundary code states something the artifact does NOT show. `NOT_AUTHORIZATION_GRANT` means the artifact grants no permission; it does not mean anything was verified. A code never raises confidence. A missing code is not evidence that a limit does not apply: it only means this artifact kind does not state that limit in its text. Codes are a classification of existing text; they do not change any assessment, currency result or record format.

## Registry

`evidence/claim-boundaries.json` (`kya.claim-boundaries/v1`) lists each code with a one-sentence meaning, the artifact kinds it appears on, and the exact current English strings it covers. A string may carry more than one code. `committedCodes` is the append-only list: a code may be added, never removed or renamed, because relying parties may have stored codes.

`src/claim-boundaries/index.mjs` exports `CLAIM_BOUNDARY_CODES`, `codesForLimitStrings(strings)` (sorted unique codes; throws on an unknown string) and `describe(code)`. It is not yet in the package `exports` map; import it by path.

## How a relying party reads the codes

1. Take the limit strings from the artifact and call `codesForLimitStrings`. An unknown string throws: treat the artifact as carrying a limit this registry version has not classified, and read it as text.
2. Treat the resulting set as a minimum list of what the artifact does not show. Check your own use against each code, for example do not use an artifact carrying `NOT_AUTHORIZATION_GRANT` as a permission.
3. Do not treat code absence as a claim. Do not use codes to compute a score or a pass.
4. A code is only as trustworthy as the artifact carrying the text. Checksums are unauthenticated (`CHECKSUM_UNAUTHENTICATED`); verify bytes from trusted inputs.

## Enforcement

`test/claim-boundaries.test.mjs` enforces the registry in four ways.

1. It scans the known emitting arrays and constants (including the native adapter limitations, the conformance run limitations and the bridge `NOT_ASSERTED` list) and fails if an emitted limit string has no code.
2. It scans every `.mjs` file under `src` (`test/claim-scan.mjs`) for sentence-like string literals (three words or more, fifteen characters or more, any quote style, templates without expressions; comments and regular expressions are skipped; lines that raise or build an error are skipped). Each such literal must be a registered string or a reviewed entry of `evidence/claim-boundary-allowlist.json`, the explicit list of sentence-like strings that are not limit statements (reasons, labels, instructions, recommendations). A new sentence in `src` therefore fails the test until someone either gives it a code or reviews it into the allowlist. The scan is lexical, not a parser: a limit sentence that is built by concatenation, assembled in a template with an expression, or kept outside `src` is not seen, and a short phrase of fewer than three words is not seen unless it sits in one of the known arrays.
3. It fails if a registry string is no longer present in `src`, and if an allowlist entry no longer exists, is unsorted, duplicated, or also registered.
4. Append-only: a code may never be removed or renamed. The in-file `committedCodes` list can be edited together with the codes, so the test also compares with git: the current commit, the merge base with `main` (or `origin/main`) and the last 25 commits that touched the registry. Any code present in one of those versions must still exist. Outside a git checkout the comparison is skipped with a message, and under `CI=1` a missing baseline fails the test instead of passing silently. A shallow clone with a single commit compares only with that commit.

## Not done

Codes are not yet carried inside any artifact or bridge export. Adding a member to an export changes its bytes and the exact-match verification in `verifyBridgeExport`, so it needs a versioned decision; see ADR-0031.
