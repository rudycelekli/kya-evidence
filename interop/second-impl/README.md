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
| Vectors, decision and every semantic field (`--semantic-only`) | 799 of 799 (272 for assess and currency, 527 for the seven version 2 operations) |
| Vectors, byte-exact including `reportDigest` and `resultDigest` | 799 of 799 |
| Digest-only failures | 0 |

After the `spec-gaps-2` texts (rounds 1 and 2) were implemented, and only those texts, every vector passes byte for byte. This is still a same-team second implementation: passing the published vectors shows the written text plus the vectors are enough to rebuild the reference output for these vectors, not that the specification is complete or that the expected values are right. Behaviour that no vector pins is still guesswork (`AMBIGUITIES.md` sections B and C).

## Round 3: fix lane 11

The vector file grew from 111 to 272 vectors, 161 of them written from the specification text before the reference was consulted. Before this round the implementation failed 26 of the 161 (four dimension digests, nine field rule refusals, six run rule cases, five reason precedence cases, two blocker code checks). It now passes all 272 byte for byte. The fixes correspond to eight rules that the reference enforced but the text did not state clearly; those rules are now in `docs/SPECIFICATION.md` ("Field rules" and the run rules paragraph) and `docs/SCORING.md` (dimension list, `blockerCodes` cross-checks), and this implementation was changed against that text. The list is in `docs/IMPLEMENTERS-GUIDE.md`, "Spec gaps found while writing the vectors", items 6 to 13. Same-team work; not independent review.

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

`test/second-impl.test.mjs` runs the harness against the adapter. It asserts a semantic pass on every published vector (799 of 799 at this writing), a refusal on every refusal vector (275), and that the byte-exact count equals the published count. It reads the count from the vectors file, so a vector added later is held to the same bar.

## Contract version 2

`ops.mjs` implements `canonicalize`, `digest`, `verify-envelope` and `compare` from the specification text and the contract README (`adapter.mjs` dispatches to it; an unknown operation still replies `unsupported`). `parseStrict` follows "Canonical form and strict parsing" (refused names, depth 32, number judgement, 100000 values, strict UTF-8 on stdin). First run, before any expected value of the new vectors was read: 205 of 205 new vectors and the 272 old ones passed byte for byte. The guesses the vectors do not pin are in `AMBIGUITIES.md`, section E. Same-team implementation, not independent review.
