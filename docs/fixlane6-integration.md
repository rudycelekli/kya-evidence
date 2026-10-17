# Fix lane 6: requirement proposals

Status: proposals only. `evidence/requirements.json` is not edited by this lane; the integrator decides whether to add these. Each proposal uses an existing `## <section>` heading of [SPECIFICATION.md](SPECIFICATION.md) and names a test that already exists in this branch.

| Proposed ID | Level | Section | Exact statement | Test file and exact title |
| :--- | :--- | :--- | :--- | :--- |
| KYA-DOC-009 | MUST | Interoperability and versioning | Relative markdown links in top-level and docs markdown files MUST resolve to a tracked path. | test/docs-claims.test.mjs: every relative markdown link in top-level and docs markdown files resolves to a tracked path |
| KYA-DOC-010 | MUST | Governance documents | Tracked markdown files MUST NOT carry an owner placeholder, except the file the release readiness gate watches. | test/docs-claims.test.mjs: no tracked markdown file carries an owner placeholder except the file the readiness gate watches |
| KYA-DOC-011 | MUST | Interoperability and versioning | Public documents MUST NOT cite a private same-team detection run that cannot be reproduced from the repository. | test/docs-claims.test.mjs: no public doc cites a private same-team detection run |
| KYA-DOC-012 | MUST | Governance documents | The code of conduct MUST NOT claim a monitored reporting channel or carry a bracketed placeholder contact, and MUST NOT contain an email address. | test/governance-docs.test.mjs: code of conduct claims no monitored channel and has no email address |
| KYA-DOC-013 | MUST | Interoperability and versioning | Interim security wording MUST NOT turn the readiness gate `security-contact-form` green; only a recognizable real contact may. | test/release-readiness.test.mjs: the interim security wording cannot turn the contact form gate green |

Notes for the integrator:

- The existing KYA-DOC-006 trace points at the test title "the six-gate detection claim is labelled as not reproducible from the repository". That title is unchanged so the trace stays valid. The claim itself was removed from the README, VALIDATION and BENCHMARKS, so the test now only requires the caveat if such wording returns. KYA-DOC-011 is the stricter replacement; consider restating KYA-DOC-006 and retiring its old title in the same change.
- The existing test "code of conduct has an enforcement placeholder and no email address" was renamed because the placeholder is gone. Nothing in `evidence/requirements.json` traces it.
