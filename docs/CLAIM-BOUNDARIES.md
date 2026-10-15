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

`test/claim-boundaries.test.mjs` scans the known emitting modules, fails if any emitted limit string has no code, fails if a registry string is no longer emitted, and fails if a committed code is removed. Adding limit text to a new module requires adding that module to the test scan list; the scan is a list of known emitters, not a repository-wide guarantee.

## Not done

Codes are not yet carried inside any artifact or bridge export. Adding a member to an export changes its bytes and the exact-match verification in `verifyBridgeExport`, so it needs a versioned decision; see ADR-0031 and `docs/lane-x-integration.md`.
