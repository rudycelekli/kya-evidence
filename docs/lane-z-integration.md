# Lane Z integration notes (release readiness)

Proposals only. This lane did not edit `evidence/requirements.json`, `docs/REQUIREMENTS.md` or `docs/SPECIFICATION.md`. Test titles below are exact. Section names are existing `## ` headings of `docs/SPECIFICATION.md`. The existing KYA-REL-001 is taken, so the proposals start at 002.

After adding the traces to `evidence/requirements.json`, run `node scripts/requirements.mjs --write`, then `node scripts/requirements.mjs --check`.

| Proposed id | Level | Section | Statement | Test file and exact titles |
| :--- | :--- | :--- | :--- | :--- |
| KYA-REL-002 | MUST | Interoperability and versioning | The release workflow MUST start only on manual dispatch, MUST default its dry run input to true, and MUST pin every action reference to a full commit SHA. | test/release-workflow.test.mjs: `the workflow runs only on manual dispatch and has no push tag schedule or pull request trigger`, `the dry run input is a boolean that defaults to true`, `every action reference is pinned to a full commit SHA and none is local or unpinned` |
| KYA-REL-003 | MUST NOT | Interoperability and versioning | The release workflow MUST NOT run `npm publish` unless the dry run input is false, the `release` environment is approved and a publisher is configured, and MUST NOT grant write permission to repository contents. | test/release-workflow.test.mjs: `npm publish appears only in steps gated on a real run, in a job that needs the release environment`, `permissions are least privilege with read only contents by default`, `the workflow never tags pushes or creates releases and keeps untrusted context out of the file` |
| KYA-REL-004 | MUST | Interoperability and versioning | The readiness report MUST exit 1 and MUST NOT print the ready line when any automated gate fails, and MUST treat a missing or malformed observation as a failure. | test/release-readiness.test.mjs: `each broken observation fails its own gate and the report is not ready`, `missing or malformed observations fail closed`, `exit code is 1 and no ready line when an automated gate fails`, `exit code is 0 with the ready line when every automated gate passes`, `exit code is 2 for usage errors` |
| KYA-REL-005 | MUST NOT | Interoperability and versioning | The readiness report MUST NOT mark any outside gate as passed, whatever its inputs say. | test/release-readiness.test.mjs: `outside gates are always open whatever the observations claim` |
| KYA-REL-006 | MUST NOT | Interoperability and versioning | The readiness script MUST NOT use the network and MUST NOT publish, tag or push; it spawns only node and read-only git commands. | test/release-readiness.test.mjs: `the script uses no network and publishes nothing` |

## Facts the registry should not claim

- None of this shows a release is safe, reviewed or approved. KYA-REL-004 is about the report refusing to say "ready" when it observed a failure.
- The workflow text tests read the file by indentation. They do not run GitHub Actions. The workflow has never run.
- `scripts/release-readiness.mjs` observes `SECURITY.md` for a contact by form (an address or a private advisory URL, not a placeholder). It cannot show that anyone reads it, which is why the outside gate `security-contact-monitored` stays open.

## Version carriers (for the release commit, see docs/RELEASING.md)

`package.json`, the first line of the `HELP` text in `bin/kya.mjs`, `docs/governance/VERSIONING.md`, the bold version in the README opening paragraph, then `CHANGELOG.md` and `docs/RELEASE-NOTES-ALPHA.md`. The readiness script checks the first four agree and that `CHANGELOG.md` has a heading for the package version.

## Open items for the owner

1. A real, monitored security contact (the readiness gate `security-contact-form` fails until `SECURITY.md` names one).
2. npm account with 2FA, the package name, and a trusted publisher or a scoped token; the `release` environment with required reviewers.
3. Decide whether the dry run attestation (recorded in the public transparency log for a public repository) is acceptable, or gate that step on a real run too.
4. First dry run of `.github/workflows/release.yml` from the GitHub UI; it has never run.
