# Supply-chain security

Status: partly implemented, partly a plan. This document says which is which. Nothing here claims that a release has been signed, attested or published: as of this writing none has. Related: [THREAT-MODEL.md](THREAT-MODEL.md) (boundary TB9, abuse case AC9), [CRYPTO-AGILITY.md](CRYPTO-AGILITY.md), [VULNERABILITY-DISCLOSURE.md](VULNERABILITY-DISCLOSURE.md).

## What exists today

| Control | State | Evidence |
| :--- | :--- | :--- |
| Zero runtime dependencies | Implemented. `package.json` declares no `dependencies`, `devDependencies`, `peerDependencies` or `optionalDependencies`, and requires Node 22 or later | `scripts/sbom.mjs` refuses a package that declares any |
| Deterministic release archive | Implemented. `scripts/pack.mjs` builds a ustar plus gzip archive from committed Git blobs with fixed uid, gid and mtime, refuses a dirty tree, refuses private paths and secret markers in packaged text | `scripts/pack.mjs`, `test/release.test.mjs` (KYA-REL-001) |
| Reproducibility check | Implemented in CI. The workflow packs twice and compares `archiveSha256` | `.github/workflows/ci.yml` |
| Release receipt | Implemented but unsigned. `dist/release-receipt.json` has status `prepared-local-unpublished` and states "no publisher authorization or artifact signature" | `scripts/pack.mjs`, `scripts/verify-release.mjs` |
| Receipt verifier | Implemented. Frozen regular-file subset, rejects duplicate paths, traversal, checksum and padding changes | `scripts/lib/ustar.mjs`, KYA-REL-001 |
| SBOM | Implemented by this change: `scripts/sbom.mjs` | `test/sbom.test.mjs` |
| Least-privilege CI token | Implemented: `permissions: contents: read` | `.github/workflows/ci.yml` |
| Action input handling | Implemented: inputs reach the script through environment variables, not shell interpolation | `action/action.yml`, KYA-ACT-003 |
| One pinned third-party action | `action/action.yml` pins `actions/setup-node` to a full commit SHA with a version comment | `action/action.yml` |

## Known gaps

1. **Mutable action references in the project's own CI.** `.github/workflows/ci.yml` uses `actions/checkout@v4` and `actions/setup-node@v4`, which are tags a maintainer of those actions can move. Pin both to full commit SHAs, as `action/action.yml` already does for setup-node. Not changed here because `.github/**` is outside this change; see `docs/lane-o-integration.md`.
2. **No signed tags.** Nothing proves which maintainer created a release tag.
3. **No build provenance.** There is no attestation linking the archive digest to the workflow run and source commit.
4. **No signed release receipt.** The receipt is an inventory, not a statement by a publisher.
5. **SBOM is not yet part of the release.** It is produced on demand, not in CI, and is unsigned.
6. **Repository settings unknown.** Whether branch protection, required reviews, required status checks and a protected workflow path exist on the hosting repository is UNVERIFIED. The CI gate's pin model depends on them (threat model AC4).
7. **No vulnerability reporting channel is set.** See the draft disclosure policy; the owner must set the contact.

## The SBOM tool

```
node scripts/sbom.mjs                 # CycloneDX 1.5 style JSON on stdout
node scripts/sbom.mjs --out sbom.json # write a file
node scripts/sbom.mjs --timestamp 2026-10-15T00:00:00.000Z   # opt in to a metadata timestamp
```

Properties, each covered by `test/sbom.test.mjs`:

- Deterministic: identical commits give byte-identical output. No clock is read, so `metadata.timestamp` is absent unless supplied. No network access.
- Refuses a dirty tree with exit 1, like `scripts/pack.mjs` (modified, staged or untracked files).
- Reads committed blobs, not the working tree.
- Lists the package (`pkg:npm/kya-evidence@<version>`, Apache-2.0), the Node.js engine requirement as a `platform` component (property `kya:engines.node`), and one `file` component per entry of the frozen release list, which is `package.json` plus the `files` entries of `package.json`, exactly the list `scripts/pack.mjs` reads. Each file has a SHA-256 hash and the Git blob id.
- States no runtime dependencies (the dependency graph lists only the Node.js platform under the package; property `kya:runtimeDependencies` is `none`) and refuses a package that declares dependencies it cannot enumerate.
- The `serialNumber` is a UUID-shaped value derived from the SBOM content, so it is stable.

Limits: it is an inventory of this repository's committed files. It does not inventory Node.js, the operating system, GitHub Actions, or the build host. The schema was checked by hand against the CycloneDX 1.5 JSON schema (https://cyclonedx.org/schema/bom-1.5.schema.json, fetched 2026-10-14): required members `bomFormat` and `specVersion`, component `type` values `library`, `platform` and `file`, hash shape and the serial number pattern. No schema validator or third-party SBOM consumer was run, so "CycloneDX 1.5 style" is a claim of shape only. It does not prove the archive contents: the archive digest is in the release receipt, and the SBOM digests are of source files, so compare both when verifying a release.

## How a release SHOULD be signed (not done)

None of the steps below has been performed for any KYA Evidence release. They describe the intended process so an owner can adopt it.

1. **Prepare.** On a clean, committed tree, run the full checks (`npm test`, `npm run check`), then `node scripts/pack.mjs` and `node scripts/verify-release.mjs`. Build twice and compare `archiveSha256` (CI already does this).
2. **SBOM.** Run `node scripts/sbom.mjs --out dist/sbom.cdx.json` on the same commit.
3. **Signed tag.** Create an annotated, signed tag for the release commit, for example `git tag -s v0.1.0-alpha.3 -m "KYA Evidence 0.1.0-alpha.3"`, using a maintainer key whose public part is published through a channel independent of the repository host. Git can sign with an OpenPGP key or an SSH key (`gpg.format`). Verify with `git tag -v`. The key and signing method are owner decisions; nothing is chosen here.
4. **Provenance.** Generate a build-provenance attestation for the archive and SBOM in CI, binding digests to the workflow run, commit and builder identity. Candidate mechanisms are GitHub artifact attestations and in-toto or SLSA provenance. Their exact commands, permissions and the SLSA level achieved are UNVERIFIED here; confirm against current documentation before adopting, and record the level actually reached rather than a target level.
5. **Publish digests out of band.** Publish the archive SHA-256, the SBOM digest and the tag fingerprint in the release notes and in a second channel.
6. **Consumer verification.** A consumer verifies the tag signature, recomputes the archive digest, runs `verify-release`, checks the SBOM digests against the archive contents, and verifies any attestation. `verify-release` checks integrity against the unsigned receipt only; it never authenticates a publisher (`authenticatedPublisher: false`).
7. **Pin consumers.** Consumers of the GitHub Action should pin it to a full commit SHA that belongs to a signed tag.

Registry publishing (for example npm) is not covered and is not done: the package is `prepared-local-unpublished`. If published, evaluate registry-side provenance options at that time. UNVERIFIED.

## Hardening backlog

| Item | Benefit | Needs |
| :--- | :--- | :--- |
| Pin `actions/checkout` and `actions/setup-node` in `ci.yml` by SHA | Removes mutable-tag risk | Edit `.github/workflows/ci.yml` |
| Add an SBOM step and archive it with the pack output | Inventory with every build | `package.json` script, CI edit |
| Automated updates for pinned action SHAs | Keeps pins current with review | Hosting-side configuration, UNVERIFIED |
| Branch protection and required status checks | Makes the CI gate and requirement gate binding | Hosting-side configuration, UNVERIFIED |
| Signed tags and provenance | Publisher authenticity | Owner decision on keys and platform |
| Sign the release receipt | Binds the inventory to a publisher | Key management decision (see CRYPTO-AGILITY section 4) |
| Check that `scripts/sbom.mjs` and `scripts/pack.mjs` agree on the file list in a test | Prevents drift | `test/sbom.test.mjs` already compares the SBOM list to `git ls-tree`; a direct pack comparison would need pack to export its list |
