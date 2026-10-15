# Contributing

Bring a replayable boundary failure, a sharper evaluator or a working adapter. This Apache-2.0 project is clean-room: no private product code, client records, credentials, internal paths or unapproved traces.

Use Node.js 22 or later:

```sh
node --test test/*.test.mjs
node scripts/check.mjs
node bin/kya.mjs benchmark --out ./artifacts/benchmark
```

A fix includes minimal sanitized input, exact expected behavior, relevant tests and remaining limits. An adapter documents official invocation, isolation responsibility, response contract, evidence origin, version probes and real-versus-fixture verification. No fixture can become a commercial product score.

Scoring, eligibility, schema or evaluator changes need a substantive ADR, adversarial regression and mutation test that fails when the gate is weakened. Freeze baseline/candidate cases and expected outcomes. Do not replace failing cases with easier ones or remove unknowns from the denominator.

## Test first

Write the failing test before the change. A behaviour change is shown by a test that fails on the old code and passes on the new code. Run `npm test` and `npm run check` before you ask for review. The command-transport and native-adapter tests are timing sensitive and need a quiet machine; under load, re-run a single failing test file alone before judging it a regression. Documentation-only changes still run `npm run check`.

## Code under src/conformance

Code under `src/conformance/` must not change without an ADR. The evaluator digest in `evidence/evaluator-identity.json` changes with that code, and a change to the digest is breaking for evidence issued under the old digest. The change also needs the migration note described in [VERSIONING.md](docs/governance/VERSIONING.md). Code that is not evaluator logic belongs outside that directory.

## Developer Certificate of Origin

Every commit proposed for this repository must carry a `Signed-off-by:` line with your real name and a working email address. By adding it you certify the Developer Certificate of Origin (https://developercertificate.org). Use `git commit -s`. A pull request without the sign-off will not be merged. An AI co-author trailer does not replace the sign-off. The full terms are in [IPR-POLICY.md](docs/governance/IPR-POLICY.md), which also covers the Apache-2.0 patent grant, essential-patent disclosure, employer permission and prohibited material.

## Governance documents

- [CHARTER.md](docs/governance/CHARTER.md): purpose, roles, decision rules, conflicts of interest, hand-over
- [IPR-POLICY.md](docs/governance/IPR-POLICY.md): licence, DCO, patents, third-party material
- [TRADEMARK-AND-CLAIMS.md](docs/governance/TRADEMARK-AND-CLAIMS.md): what a conformance claim may and may not say
- [VERSIONING.md](docs/governance/VERSIONING.md): stability levels, compatibility, deprecation, requirement IDs
- [EXTENSION-REGISTRY.md](docs/governance/EXTENSION-REGISTRY.md): namespaced extension identifiers and limits
- [DECISION-PROCESS.md](docs/governance/DECISION-PROCESS.md): proposals, ADR lifecycle, acceptance evidence, errata
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): expected behaviour and reporting

These documents are drafts for review by qualified legal counsel and are not yet adopted by any body.

Use identity, evidence, assessment and conformance bounded contexts. Public exports expose domain/application; filesystem/process infrastructure stays explicit. Runtime dependencies need measured justification and an ADR. A child process is not an OS sandbox.

README SVGs are self-contained and readable with motion disabled. The offline viewer uses no remote fonts/CDNs, works by keyboard, renders text safely and labels imported reports unverified. Fixtures are explanatory and distinct from signed assessments.

Contributions are proposals until reviewed. Maintainers retain merge and publication authority. Read [GOVERNANCE.md](docs/GOVERNANCE.md) for correction and appeal rules; report sensitive defects through [SECURITY.md](SECURITY.md).
