# Second implementation of KYA assessment and currency (team-built, NOT independent)

Files: `kya2.mjs` (canonical JSON, strict parse, Ed25519 verification, validators, `assess`), `currency.mjs` (`checkCurrency` and incident handling), `adapter.mjs` (the `kya.impl-input/v1` command). Zero dependencies, Node 22 `node:crypto` only. It imports nothing from `src/`.

```text
node scripts/run-vectors.mjs --impl "node interop/second-impl/adapter.mjs" --name second-impl --language javascript
```

## Read this first: what this is not

This was written by the same team, in the same repository, by an agent that has the same background as the reference's author. It is a second implementation, not an independent one. Agreement with the vectors shows the vectors and the written sources are enough to rebuild the decision semantics; it does not show correctness against intent and it is not external review. It is not a claim of conformance to any standard.

## Result

| Measure | Value |
| :--- | :--- |
| Vectors, decision and every semantic field (`--semantic-only`) | 111 of 111 |
| Vectors, byte-exact including `reportDigest` and `resultDigest` | 79 of 111 (12 refusals plus 67 others) |
| Digest-only failures | 32 |

The 32 failures differ only at `$.reportDigest` or `$.resultDigest`. After the spec-gaps-2 texts were implemented (and only those texts, not digest guessing) the remaining causes are the fixture limitation string, the trigger `detail` strings and the four `limits` strings of the currency result, none of which is written down (`AMBIGUITIES.md` section A). A semantic pass cannot make a requirement `pass` in the harness report, so this implementation does not claim any requirement as passed.

## Sources used

Second pass: also `docs/SCORING.md` "Blocker wording in the reference" and `docs/SPECIFICATION.md` "Currency result layout and reason vocabulary" (merged from `spec-gaps-2`). Their companion tests `test/scoring-wording.test.mjs` and `test/spec-reason-vocabulary.test.mjs` were not opened.

Written from `docs/SPECIFICATION.md`, `docs/IMPLEMENTERS-GUIDE.md`, `interop/impl-contract/README.md` and `evidence/assessment-vectors.json`.

Off limits and not read: `src/assessment/**`, `src/conformance/**`, `interop/impl-contract/js-reference.mjs`. Also not read, because it holds the generator's per-vector claims: `scripts/assessment-vectors.mjs`.

Read beyond the four named sources, in the interest of honesty:

- `docs/SCORING.md`: the specification delegates the formulas, gates and blocker code table to it. It does not contain the human blocker strings the contract says it contains.
- Excerpts of `docs/BUILD-CONTRACT.md`, `docs/CRYPTO-AGILITY.md`, `docs/INTEROPERABILITY.md`, `docs/DOSSIERS.md`, `docs/EVALUATOR.md` and `docs/ADAPTERS.md` that a keyword search of `docs/` printed (the Ed25519 signing-domain prefix `kya.evidence/v1\n` and `kya.incident/v1\n` came from `docs/CRYPTO-AGILITY.md`; the shape of the report fields was confirmed by `docs/BUILD-CONTRACT.md`).
- The beginning of `evidence/golden-vectors.json` (canonical byte cases and the signing-input example).
- `scripts/run-vectors.mjs` (the harness), to know how output is compared.

The shape of the `kya.assessment/v1` report (field names, dimension fields, limitations strings, the evidence bundle digest rule) was read off the complete assessments that the `currency.*` vectors carry as input, and checked by recomputing their `reportDigest`.

## Tests

`test/second-impl.test.mjs` runs the harness against the adapter. It asserts 111 of 111 semantic passes, 12 refusals, and that every non-passing vector fails only on a digest field with the byte-exact count (floor 79) not regressing. It deliberately does not assert that all vectors pass byte for byte, because they do not.
