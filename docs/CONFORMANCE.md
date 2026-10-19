# Conformance reports

A conformance report (`kya.conformance-report/v1`) lets an implementation state which normative `KYA-*` requirements it passes, with what evidence, and which it did not run. The registry is [`evidence/requirements.json`](../evidence/requirements.json); the rendered list is [`REQUIREMENTS.md`](REQUIREMENTS.md). Format rationale: [ADR-0015](adr/0015-conformance-report-format.md).

## What a claim means

An entry says: for this requirement ID, under this registry digest, this implementation recorded one of four results.

| Result | Meaning |
| :--- | :--- |
| `pass` | Every listed test or vector ran and passed. Needs evidence `executed-test` or `portable-vector` and at least one executed ID. |
| `fail` | At least one listed test or vector ran and failed (or the implementation declares failure). |
| `not-run` | Not executed, skipped, absent or unknown. Stays in the denominator. |
| `not-applicable` | Allowed only when the implementation's own `declaredSubset` excludes the ID. Leaves the applicable count. Without a declared subset an unrun requirement is `not-run`. |

When a `declaredSubset` is present, IDs outside it must be `not-applicable` (or carry real executed results); they cannot be `not-run`.

## Evidence classes

- `executed-test`: a test in the implementation's own suite ran; its ID is listed as `file :: title`.
- `portable-vector`: a shared vector (for example `evidence/golden-vectors.json`) was reproduced by the implementation; list the vector IDs.
- `declaration`: the implementation asserts behavior without running anything. It is recorded for transparency, can never be `pass`, and is counted separately (`declarationEntries`).

## Summary counts

`total`, `pass`, `fail`, `notApplicable`, `notRun`, `applicable = total - notApplicable`, `passPermille = floor(1000 * pass / applicable)` (null when `applicable` is 0) and `declarationEntries`. Validators recompute them; a mismatch is rejected. There is no hidden clock: `runAt` is supplied by the caller.

Assessment semantics have a language-neutral vector set (`evidence/assessment-vectors.json`). To produce `portable-vector` evidence for an implementation, follow `docs/IMPLEMENTERS-GUIDE.md` and `interop/impl-contract/README.md`, then run `node scripts/run-vectors.mjs`. Two same-team implementations (the JavaScript reference and `interop/second-impl/`, which are not independent) pass all 799 vectors byte for byte (272 for `assess` and `currency`, 213 for the four contract version 2 building-block operations and 314 for the credential and score card operations). No outside implementation has run them. The public key spelling and Ed25519 point rules (canonical SPKI PEM only; no small-order or non-canonical points) are now enforced identically by the reference, `interop/second-impl/` and the Python byte checker, checked by a differential test; that is agreement between same-team implementations, not independent confirmation.

## Producing a report

JavaScript reference (runs every cited test file for real, so it takes as long as the traced suites):

```bash
node scripts/conformance-report.mjs --now 2026-10-14T12:00:00.000Z --out report.json
node scripts/conformance-report.mjs --verify report.json
```

`npm run conformance-report -- --now ...` is equivalent. A requirement passes only if all its traced tests pass and none is skipped; a host-conditional trace that was skipped yields `not-run`. Without `--out` the full report is printed to stdout.

Another implementation (for example the Python byte checker or a third party):

1. Pin `evidence/requirements.json`; compute its digest as `digest(registry)` (SHA-256 of its canonical JSON, the digest printed at the end of `REQUIREMENTS.md`).
2. Run your own tests or the shared vectors. Record, per requirement, the exact test or vector IDs executed and the outcome.
3. Build the report with `buildReport` from `kya-evidence/conformance`, or write JSON validated by `schemas/conformance-report.schema.json` plus `validateReport` (which also enforces uniqueness, ordering, summary arithmetic and, given the registry, no unknown or missing IDs). Every registry ID must appear exactly once.
4. Optionally sign with `signReport` (Ed25519, domain `kya.conformance-report/v1\n`) and submit the file by pull request or issue. Submitting is not endorsement.

## What a report does not prove

- Not truthfulness: the producer chose what to run and report; a signature does not show the tests ran as stated.
- Not independence: an implementation by the same team is a secondary implementation, not independent review.
- Not sufficiency: a passing trace shows a test exists and passed, not that the requirement is fully covered.
- Not authenticated unless signed, and then only integrity and key possession; nothing links a key to an identity or authority.
- Not a certification, standards-body acceptance, an authorization grant or a score of any product.
