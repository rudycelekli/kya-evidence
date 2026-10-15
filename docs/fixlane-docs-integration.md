# Docs fix lane: requirement proposals

These proposals are not added to `evidence/requirements.json`. Each names a test in `test/docs-claims.test.mjs` by its exact title and an existing `## <section>` heading of `docs/SPECIFICATION.md`. They describe documentation guards, so they are low value as protocol requirements; the integration owner may prefer to leave them as plain tests.

| Proposed ID | Section | Statement | Test title |
| :--- | :--- | :--- | :--- |
| KYA-DOC-001 | Interoperability and versioning | The action README usage example MUST carry the pin inputs and MUST say a bare call exits 1 with `PINS_REQUIRED` | the action README example carries the pin inputs and says a bare call needs pins |
| KYA-DOC-002 | Interoperability and versioning | The policy pin MUST be described as the canonical policy digest, not the file hash | the policy pin is described as the canonical policy digest and not the file hash |
| KYA-DOC-003 | Governance documents | Markdown files MUST NOT reference a nonexistent lane integration or requirements proposal note | no markdown file references a nonexistent docs lane integration or requirements proposal note |
| KYA-DOC-004 | Interoperability and versioning | Documentation MUST NOT describe the manifest as a passport | README does not call the manifest a passport or promise portable passports |
| KYA-DOC-005 | Interoperability and versioning | The conformance document MUST NOT say no second implementation has run the vectors, and MUST say none is independent | CONFORMANCE no longer says no second implementation has run the vectors |
| KYA-DOC-006 | Interoperability and versioning | A detection result that is not reproducible from the repository MUST be labelled so and MUST point at the mutation check | the six-gate detection claim is labelled as not reproducible from the repository |
| KYA-DOC-007 | Interoperability and versioning | The stated mutation control count MUST match the mutation check script | the stated mutation control count matches the mutation check script |
| KYA-DOC-008 | Interoperability and versioning | Documented VC bridge commands MUST resolve to an existing script or the `kya vc` subcommand | every VC bridge command in the documentation resolves to an existing script or subcommand |

Other tests in the file (second implementation byte match wording, roadmap credential bridge wording, quickstart file list and received assessment step, unsupported reply to a refusal vector) are wording guards with no proposed requirement.
