# Releasing an alpha

This is the exact procedure for cutting a `0.1.0-alpha.N` release of KYA Evidence. It exists so that publishing is one reviewed decision by the owner, not a series of improvised commands.

State today: nothing has been published. There are no git tags, no GitHub releases, and the package name returned "not found" from the npm registry when checked on 2026-10-16. Nothing in this document has been run against npm or GitHub releases. Steps marked **[OWNER ONLY]** need the owner's accounts, keys or a decision that no tool or agent may take. Everything not so marked can be run by anyone with a clone.

What a release does and does not mean: it publishes bytes with a recorded origin. It is not a certification, not an outside review, and not a claim that the software is safe to rely on for any real decision. The readiness report (`npm run release:readiness`) lists the outside gates that remain open; publishing with those open is the owner's call, and the release notes must say so.

## 1. Version

Rules for this project's pre-release versions:

- Format `0.1.0-alpha.N`. Each published artifact gets a new `N`. A version is never reused, even if it was never published, once its label has appeared in a public document for different bytes.
- Bump `N` for any change to released behaviour, to the data formats that evidence signs, to the files listed in `package.json` `files`, or to documented security behaviour. A documentation-only change to a repository that has no published release does not need a bump.
- Move to `0.1.0-beta.1` or `0.1.0` only when the owner decides the outside gates (see the readiness report) justify it. This procedure does not cover that.
- The protocol label `kyaVersion: "0.1.0-alpha"` that appears inside records is a format label, not the package version. Do not change it in a package bump. Changing it is a format change that needs an ADR.

**Next version: `0.1.0-alpha.4`.** Reasons:

1. `0.1.0-alpha.3` is the label that `package.json` has carried since the commit "Add evidence-replayed dossiers and exact scope comparison gates" (2026-10-13). Since then more than 100 commits changed behaviour, formats and security properties (see `CHANGELOG.md`, section Unreleased). Reusing `alpha.3` for those bytes would attach an old label to new content.
2. `alpha.3` was never tagged or published, so there is no published alpha.3 to confuse. Skipping to alpha.4 costs nothing and keeps one rule: one label, one set of bytes.
3. The changes are still pre-1.0 and still unreviewed from outside, so another alpha (not a beta) is the honest label.

### Files that carry the version

Edit all of these in one commit (the "release commit"). `npm run release:readiness` checks the first four agree.

| File | What to change |
| :--- | :--- |
| `package.json` | the `version` field |
| `bin/kya.mjs` | the first line of the `HELP` text (`KYA Evidence 0.1.0-alpha.N`) |
| `docs/governance/VERSIONING.md` | the "currently" version in the software package row |
| `README.md` | the bold `v0.1.0-alpha.N` in the sentence that begins "The current deliverable is" |
| `CHANGELOG.md` | rename `## [Unreleased]` to `## [0.1.0-alpha.4]`, add the date, add a fresh empty `## [Unreleased]` above it, update the compare links at the bottom |
| `docs/RELEASE-NOTES-ALPHA.md` | the version named in the text and the commands |
| `docs/SUPPLY-CHAIN.md` | the example tag in the "How a release SHOULD be signed" section (an example only; keep it current) |

Not changed: `test/privacy.test.mjs` (a fixture string that happens to look like a version), `test/imports.test.mjs` and the `kyaVersion` label (format label), and anything under `src/conformance/` (the evaluator identity is pinned; a release commit must not touch it).

There is no lockfile and no dependency to update: the package has zero runtime dependencies.

## 2. Gate sequence

Run on a clean checkout of `main` at the release commit, after the release-commit pull request is merged. Every command must succeed. Do not skip, edit or `todo` a test to make a gate pass.

```sh
git switch main && git pull --ff-only
git status --porcelain            # must print nothing
npm test                          # all tests pass, skipped 0, todo 0 in CI's TAP check
npm run check
npm run privacy:scan
npm run privacy:scan:vectors
node scripts/adr-index.mjs        # commit evidence/adr-index.json if it changes
npm run profiles:registry:check
npm run vectors:assessment:check
node scripts/requirements.mjs --check
node scripts/mutation-check.mjs   # slow; CI runs it. This is the full mutation gate
npm run release:readiness         # automated gates plus the list of open outside gates
```

`release:readiness` re-checks most of the above itself, builds and verifies the package, and prints the outside gates it cannot check. It exits 0 only when every automated gate passes on a real run; `--branch` accepts only `main`, and `--observed FILE` (injected observations, for tests) always reports `OBSERVATIONS INJECTED`, ready false and exit 1, so a file can never produce the ready line. The package content scan (`scripts/lib/package-guard.mjs`, shared with `pack.mjs`) refuses private config and key paths, GitHub, npm and AWS token shapes, private key headers and absolute home directory paths other than documented placeholders; it is a blocklist, not a secret scanner. Exit 0 means "ready for an owner decision", never "approved". A failing automated gate blocks the release.

The same sequence runs on GitHub as the manual workflow `.github/workflows/release.yml` with `dry_run` left at its default `true`. That run publishes nothing; see section 7.

## 3. Release commit and review

1. Branch from `main`, make the version edits from section 1, update `CHANGELOG.md` and the release notes.
2. Open a pull request. A reviewer other than the author reads the diff, the changelog and the release notes, and checks that no statement claims certification, safety, authorization or outside validation.
3. Merge. **[OWNER ONLY]** The owner decides to proceed. The readiness report is the input to that decision, together with the open outside gates.

## 4. Tag

**[OWNER ONLY]** Creating and pushing a tag publishes a public pointer to the commit, and signing needs the owner's key. Nobody else, and no agent, should do this.

```sh
git tag -s v0.1.0-alpha.4 -m "KYA Evidence 0.1.0-alpha.4" <release-commit-sha>
git tag -v v0.1.0-alpha.4
git push origin v0.1.0-alpha.4
```

The signing key and the channel that publishes its public part are the owner's decision (`docs/SUPPLY-CHAIN.md`). If no signing key is set up, an unsigned annotated tag (`git tag -a`) is possible but must be described as unsigned in the release notes. The tag name is `v` plus the package version exactly. No workflow in this repository triggers on a tag; creating the tag releases nothing by itself.

## 5. Build and verify the tarball

Anyone can do this, and it publishes nothing. It must be the release commit, with a clean tree.

```sh
node scripts/pack.mjs             # writes dist/kya-evidence-0.1.0-alpha.4.tgz and dist/release-receipt.json
node scripts/verify-release.mjs   # checks the tarball against the receipt
node scripts/sbom.mjs --out dist/sbom.cdx.json
shasum -a 256 dist/*.tgz dist/sbom.cdx.json
```

What `pack.mjs` does: reads committed Git blobs only, refuses a dirty tree, refuses private paths and secret markers in package text, fixes owner, mode and mtime, and writes a SHA-256 for every file into the receipt. Building twice must give the same `archiveSha256` (CI checks this). The receipt is unsigned and says so: it is an inventory, not a statement by a publisher. `verify-release` proves the tarball matches the receipt, not who made either.

Record the archive SHA-256 and the SBOM SHA-256. They go in the GitHub release notes and, ideally, in a second channel the owner controls.

Delete `dist/` when finished (it is git-ignored, but old tarballs cause confusion).

## 6. npm publish with provenance

**[OWNER ONLY]** setup, none of which this repository or any agent can do:

1. Own the package name on npm. Check the name `kya-evidence` is free or yours (`npm view kya-evidence` should say 404 before the first publish, as of 2026-10-16).
2. Have an npm account with two-factor authentication enabled in "authorization and publishing" mode. Do not publish from an account without 2FA.
3. Choose how the workflow authenticates, and set up only one:
   - **Trusted publisher (preferred, no stored token).** On npmjs.com, open the package settings and add a trusted publisher for the GitHub repository `rudycelekli/kya-evidence`, workflow file `release.yml`, environment `release`. This needs npm CLI 11.5.1 or newer and Node 22.14 or newer on the runner; the workflow checks `npm --version`. Then set the repository variable `NPM_TRUSTED_PUBLISHER` to `true` so the workflow knows it is configured. Not verified here: the first publish of a new package name may need a manual token publish before trusted publishing can be attached; check npm's current documentation.
   - **Token.** Create a granular npm access token limited to this one package with publish permission and a short expiry, and store it as the secret `NPM_TOKEN` in the `release` environment, not in repository-wide secrets.
4. In the GitHub repository settings create the environment `release` with required reviewers (the owner) and, if possible, a deployment branch rule limiting it to `main`. The `attest` and `publish` jobs both use that environment, so each waits for an approval (two approvals per real run). The workflow also refuses to run its jobs on any ref other than `refs/heads/main`, but that is a check inside the workflow file, not a repository setting.
5. Confirm branch protection on `main` (required review, required status checks). Both the branch protection and the `release` environment reviewers are owner-configured settings. They are unverified: nothing in this repository can read them, so none of this procedure's tests show that they are set.

Publishing, after the tag exists and the dry run succeeded:

1. In GitHub Actions open the `release` workflow, choose "Run workflow", set `dry_run` to false. The build job (read-only token, no attestation or publish permission) repeats the gates and uploads the tarball, receipt and SBOM as workflow artifacts. The `attest` job waits for the owner's approval of the `release` environment, re-verifies the downloaded tarball against its receipt and the workflow commit (`verify-release.mjs --expect-commit "$GITHUB_SHA"`) and then creates the provenance attestation. The `publish` job waits for a second approval, runs the same verification and then runs `npm publish dist/kya-evidence-<version>.tgz --provenance --access public --tag alpha`.
2. Confirm on npmjs.com that the version shows the provenance badge, and that `npm view kya-evidence@0.1.0-alpha.4 dist.integrity` matches what you expect. Compare the tarball bytes with the SHA-256 you recorded. Note that npm computes its own `dist.integrity` over the tarball it stored; npm may re-serialize a package on publish, so the SHA-256 of the file npm serves can differ from `archiveSha256` in the receipt. Which happens has not been tested for this package. Whatever the result, record it in the release notes rather than hiding it.

An alpha should be published under a non-default dist-tag so that `npm install kya-evidence` does not fetch it as `latest` by accident. Recent npm versions are said to refuse publishing a pre-release version without an explicit `--tag` (not verified here), so the workflow passes `--tag alpha` either way.

Manual fallback, if the workflow cannot be used: `npm publish dist/kya-evidence-0.1.0-alpha.4.tgz --access public --tag alpha` from the owner's machine. Provenance is generated only in a supported CI provider, so a manual publish has none and the release notes must say so.

## 7. The release workflow

`.github/workflows/release.yml` is `workflow_dispatch` only: it has no push or tag trigger. Inputs: `dry_run`, default `true`.

- Only on `refs/heads/main`: every job carries that condition, so starting the workflow from a branch or tag runs nothing.
- Always (the `build` job, `contents: read` only): checks out, runs the gates, builds and verifies the tarball, generates the SBOM and uploads the tarball, receipt and SBOM as workflow artifacts. A dry run makes no attestation and no publish: it creates nothing in the public Sigstore transparency log.
- Only when the event is a manual dispatch with `dry_run` false and the `release` environment is approved by the owner (the `attest` job, permissions `contents: read`, `id-token: write`, `attestations: write`): verifies the artifact against its receipt and the workflow commit, then creates a provenance attestation for the tarball. The attestation is recorded in the public Sigstore transparency log.
- Only under the same conditions, after the `attest` job and a second approval, and when either `NPM_TOKEN` or `NPM_TRUSTED_PUBLISHER` is configured: `npm publish --provenance --access public --tag alpha`.
- Every action is pinned by full commit SHA. `test/release-workflow.test.mjs` fails if a trigger, default, pin or gate drifts.

The workflow has not been run. Its first run is a dry run by the owner; treat any failure as information, not as something to bypass.

## 8. GitHub release notes

**[OWNER ONLY]** Creating a GitHub release announces the version.

1. After the npm publish succeeds (or if not publishing to npm, after the tag), create a release from the tag, marked as a pre-release.
2. Body: start from `docs/RELEASE-NOTES-ALPHA.md` and the matching `CHANGELOG.md` section. Add the archive SHA-256, the SBOM SHA-256, the commit SHA, the tag fingerprint if signed, the provenance status (attested in CI, or none), and the security contact. Attach the tarball, receipt and SBOM from the workflow artifacts.
3. State the open outside gates plainly: no outside review, no outside implementation, no relying-party pilot.

Do not post the announcement anywhere (social posts, mailing lists, standards groups) as part of this procedure.

## 9. Security contact

`SECURITY.md` currently promises no monitored mailbox and no response time, and `docs/security.txt` is a draft with owner placeholders. **[OWNER ONLY]** Before announcing a release, set a real, monitored private reporting channel (for example the repository host's private vulnerability reporting, enabled and tested), update `SECURITY.md`, and replace the placeholders in `docs/security.txt`. Do not publish `security.txt` with placeholders. The readiness report fails its security-contact gate while `SECURITY.md` contains no recognizable real contact.

## 10. Rollback

- **Before publishing:** delete the unpushed tag (`git tag -d v0.1.0-alpha.4`) and fix forward in a new commit. A pushed tag should also be removed (`git push origin :refs/tags/v0.1.0-alpha.4`) only if nobody could have used it; **[OWNER ONLY]**.
- **After publishing to npm:** a published version number can never be reused, even after removal. Options, in order of preference:
  1. `npm deprecate kya-evidence@0.1.0-alpha.4 "<reason and the fixed version>"` **[OWNER ONLY]**. The version stays installable but npm prints the message. Fix forward with `0.1.0-alpha.5` through this procedure.
  2. `npm unpublish kya-evidence@0.1.0-alpha.4` **[OWNER ONLY]**. npm allows it only in limited cases: broadly, within 72 hours of publish, or if no other package depends on it and it has few downloads. The rules change; read npm's current unpublish policy before relying on it. Unpublishing does not recall copies already downloaded or mirrored.
  3. For a security defect, deprecate first, publish a fixed version, and follow the disclosure policy. The project has no live revocation service; consumers of signed evidence learn about a bad release only through the channels the owner uses (release notes, advisory).
- **GitHub release:** edit it to say it is superseded, or delete it **[OWNER ONLY]**. A deleted release does not remove the tag or the npm version.
- **Attestations** recorded in the transparency log cannot be removed. A superseded release's attestation stays; say so in the notice.

## 11. After the release

1. Delete `dist/`.
2. Open the next `## [Unreleased]` section if it was not created, and move the readiness outside gates forward as they close (record each closure with its evidence, not a checkmark).
3. If anything about the release surprised you, change this document in the same week.
