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
| Vectors, byte-exact including `reportDigest` and `resultDigest` | 111 of 111 |
| Digest-only failures | 0 |

After the `spec-gaps-2` texts (rounds 1 and 2) were implemented, and only those texts, every vector passes byte for byte. This is still a same-team second implementation: passing the published vectors shows the written text plus the vectors are enough to rebuild the reference output for these vectors, not that the specification is complete or that the expected values are right. Behaviour that no vector pins is still guesswork (`AMBIGUITIES.md` sections B and C).

## Sources used

Round 2 added the trigger detail strings, `limits` strings, limitations list and grammar exemptions from `docs/SPECIFICATION.md` and `docs/SCORING.md` (merged from `spec-gaps-2`).

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

`test/second-impl.test.mjs` runs the harness against the adapter. It asserts 111 of 111 semantic passes, 12 refusals, and that every non-passing vector fails only on a digest field with the byte-exact count (floor 111) not regressing. It deliberately does not assert that all vectors pass byte for byte, because they do not.
