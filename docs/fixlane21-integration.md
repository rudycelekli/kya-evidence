# Fix lane 21: Python assess and currency

## What changed

`interop/python-impl/adapter.py` now implements `assess` and `currency` besides the four operations it already had, so a second language reproduces the scoring semantics and not only the byte level building blocks. No file under `src/` changed and no expected value of any vector changed. The specification gained the text the reference followed and nobody had written (`docs/SPECIFICATION.md`, "Assessment report layout and arithmetic" and the incident evaluation paragraph of "Currency result layout and reason vocabulary"; one sentence in `docs/SCORING.md`; a CHANGELOG clarification). `test/python-impl.test.mjs` pins per operation counts for `assess` (212) and `currency` (60) and three differential tests against the reference adapter. The Python section of `docs/IMPLEMENTERS-GUIDE.md` records every disagreement.

## Result

Measured with `scripts/run-vectors.mjs` on `python3` 3.13.5 (`/opt/anaconda3`) and `/usr/bin/python3` 3.9.6, identical:

| Run | Vectors | Requirements |
| :--- | :--- | :--- |
| First draft, whole file | 391 pass, 126 fail, 282 unsupported | 12 pass, 26 fail |
| Final, whole file | 517 pass, 0 fail, 282 unsupported | 38 pass, 0 fail, 254 not-run of 292 |
| JavaScript reference after the specification edits | 799 of 799 | 60 pass, 232 not-run |
| Second implementation after the specification edits | 799 of 799 | 60 pass, 232 not-run |

Of the 272 `assess` and `currency` vectors the first draft passed 146 (`assess` 89 of 212, `currency` 57 of 60) and the final code passes 272. The three operations Python does not implement are `not-run`.

## Disagreements

Four groups from vectors (report layout for 123 `assess` vectors, two listing rules and one refusal for `currency`) and six from reading the reference source after the vectors passed (freshness boundary, `validUntil`, bundle digest, coverage rounding, the checks `currency` makes of an assessment, incident lists and entry bounds). Each is in `docs/IMPLEMENTERS-GUIDE.md`. No vector remains failing.

## What is not verified

- Same team, different language. No outside party reviewed or ran it.
- The first draft was independent of the reference source; everything after the first harness run was informed by the vectors, and the six edge case corrections by the reference source.
- The vectors pin little of the boundary behaviour (freshness boundary, `validUntil`, incident lists); those rules are pinned only by the new tests and by a bounded differential run of 406 `assess` and 1200 `currency` mutated inputs with no difference, which is a sample and not a proof.
- Not run on Linux or Windows.
- The Ed25519 code is not constant time and is for verifying public data.

## Requirement proposals

Not added to `evidence/requirements.json`. Each id is three letters then three digits, each test title is exact and exists once in `test/python-impl.test.mjs`, and the section is an existing `## ` heading of `docs/SPECIFICATION.md`.

| Proposed ID | Level | Area | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-PYA-001 | SHOULD | interoperability | Run selection and qualification | A second-language implementation of the version 2 operations assess and currency SHOULD reproduce every published vector of those operations, and an operation it does not implement MUST be answered with the exact unsupported reply so that the harness records not-run. | `python passes every assess vector through the harness`; `python passes every currency vector through the harness` |
| KYA-PYA-002 | MUST | interoperability | Reports and viewers | Two implementations MUST agree on the rules the specification states for the assessment report, namely the freshness boundary of a receipt, the validity bound of an assessment, the digest of every supplied evidence entry in the bundle digest, and the bounds on the number of evidence and incident entries. | `python and the reference agree at the freshness boundary of a receipt and on the validity bound of an assessment`; `python and the reference agree on the evidence bundle digest with entries that are not envelopes and on the entry bounds` |
| KYA-PYA-003 | MUST | interoperability | Trust and eligibility | Two implementations MUST agree on incident evaluation when records are reordered, delivered twice or moved in time, including the grouping of conflicting records and the lists open, resolved, appealed and observed. | `python and the reference agree on incident handling when records are reordered duplicated or moved in time` |
