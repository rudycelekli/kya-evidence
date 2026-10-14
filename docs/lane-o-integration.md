# Lane O integration notes

Shared-file edits this lane could not make (they are outside the allowed file list). Apply them in the integration step.

## package.json

1. Add a script: `"sbom": "node scripts/sbom.mjs"`. No new `files` entries are needed; `docs/`, `scripts/` and `test/` are already in the frozen list, so `docs/CRYPTO-AGILITY.md`, `docs/SUPPLY-CHAIN.md`, `docs/VULNERABILITY-DISCLOSURE.md`, `docs/security.txt`, `docs/adr/0025-*.md`, `scripts/sbom.mjs` and both tests ship automatically. `scripts/pack.mjs` scans packaged text for a private home-directory path, API-key-like strings and private-key PEM markers; none appear in this lane's files.
2. No `exports` change.

## .github/workflows/ci.yml

1. After the pack steps add: `- run: node scripts/sbom.mjs --out dist/sbom.cdx.json` and, optionally, a second run to compare byte equality, as the pack step does.
2. Replace `actions/checkout@v4` and `actions/setup-node@v4` with full commit SHAs plus a version comment (as `action/action.yml` already does for setup-node). The SHAs must be resolved and reviewed at integration time; this lane did not resolve them.

## evidence/requirements.json

Merge `docs/lane-o-requirements-proposal.json` (KYA-SUP-001 to KYA-SUP-003, KYA-CRY-001). Each cited test title exists verbatim. The section `Interoperability and versioning` already exists in `docs/SPECIFICATION.md`. Regenerate `docs/REQUIREMENTS.md` with `npm run requirements` and re-pin anything that digests the registry (the conformance report names the registry digest).

## Other

- `docs/adr/0025-*.md`: run `npm run adr:index` and keep the regenerated `evidence/adr-index.json` if the integration wants the index to include ADR-0025 (this lane restored the file with `git checkout`, as instructed).
- `docs/THREAT-MODEL.md` and `docs/CRYPTO-AGILITY.md` must keep the strings the inventory test searches for; changing a domain prefix or adding a hash in `src/` fails `test/crypto-inventory.test.mjs` until the document is updated.
- Follow-up outside this lane: ADR-0022 says KYA canonical JSON differs from RFC 8785 in "number formatting and string ordering rules". Tests in `test/crypto-inventory.test.mjs` show identical output for accepted values and differences only in accepted inputs (unsafe integers, lone surrogates, reserved member names, limits). Correct the ADR wording and the comment in `src/vc-bridge/jws.mjs` only if the owner agrees (comment says "not RFC 8785", which is still true).
- `docs/security.txt` and `docs/VULNERABILITY-DISCLOSURE.md` carry placeholders the owner must set (contact, expiry, policy URL, canonical URL) and counsel must review. Do not publish before then.
- `test/sbom.test.mjs` needs `git` on the PATH, like `scripts/pack.mjs`. One test builds the SBOM of the repository from HEAD and therefore also needs the tests to run inside a Git checkout; it takes about six seconds.
- Mutation harness: not extended. SBOM refusal of a dirty tree is covered by plain tests; consider a mutant that removes the dirty check if the owner wants that gate mutation-tested.
