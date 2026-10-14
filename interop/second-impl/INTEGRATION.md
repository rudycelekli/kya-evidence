# Integration proposals (nothing here is applied)

This lane did not edit `package.json`, `evidence/requirements.json`, CI or any file outside `interop/second-impl/` and `test/second-impl.test.mjs`. `npm test` already picks the new test up through its `test/*.test.mjs` glob. Proposals for the owner:

## 1. Requirement KYA-VEC-009 (proposed, not added)

`KYA-VEC-009` is unused (the registry runs `KYA-VEC-001` to `KYA-VEC-008`). Section names below exist as headings in `docs/SPECIFICATION.md`.

```json
{
  "id": "KYA-VEC-009",
  "level": "SHOULD",
  "area": "vectors",
  "section": "Interoperability and versioning",
  "statement": "A team-built second implementation of assessment and currency semantics SHOULD reproduce the decision and every semantic field of all published assessment vectors, and any gap between its output and the byte-exact digests MUST be documented rather than hidden. It is not an independent implementation and MUST NOT be described as one.",
  "tests": [
    { "file": "test/second-impl.test.mjs", "title": "second implementation matches the decision and every semantic field of all 111 vectors" },
    { "file": "test/second-impl.test.mjs", "title": "second implementation refuses every refusal vector and never crashes on an accepted vector" },
    { "file": "test/second-impl.test.mjs", "title": "second implementation digest failures are limited to the two digest fields and are listed honestly" }
  ]
}
```

A SHOULD is used on purpose: the byte-exact result is 43 of 111, so a MUST for full parity would fail today. Do not add this requirement as a vector citation (`requirements` on a vector): vector citations feed `pass` in portable-vector reports, and a semantic pass must never record a requirement as pass (KYA-VEC-008).

## 2. Specification and contract changes that would close the gaps

These are the editor-level fixes that follow from `AMBIGUITIES.md`. Each would let a second implementer reach byte-exact digests from prose alone.

1. In `docs/SPECIFICATION.md` section "Reports and viewers", define `evidenceBundleDigest` (digest of the array of envelope digests in input order) and give the full `kya.assessment/v1` field list with the dimension and check entry shapes.
2. Add a table of every `blockers` string (or, better, drop the strings from `reportDigest` and digest the codes) to `docs/SCORING.md` next to the code table. The contract currently says the strings are there; they are not.
3. Add the reason vocabulary for `rejectedEvidence` and `incidents.ignored` as a normative table with the precedence when several apply, and state that `id` is `null` before shape and signature validation succeed.
4. State the complete `kya.currency/v1` result layout (including any detail text on triggers) in the section "Reports and viewers", or digest only the `impl-result` projection.
5. State the blocker short circuit (a critical failure suppresses insufficiency blockers) and the recency rule for future-dated receipts in "Run selection and qualification".
6. Publish the validator grammars (identifier pattern and bounds) so refusal behaviour is not guesswork.

## 3. Suggested wording for the claim boundary

Any document that cites this directory should say: a team-built second implementation of the decision semantics passes all published vectors on decision and semantic fields (111 of 111) and 43 of 111 byte for byte, written from the specification and vectors without reading the reference source. It is not independent, not external review and not a conformance claim.
