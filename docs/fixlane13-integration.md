# Fix lane 13: conformance contract version 2

Status: proposal for the integrator. `evidence/requirements.json` is not edited by this lane, and neither is anything under `src/conformance/`. Nothing was published, tagged, released, dispatched or announced, and nothing used the network. The design is [ADR-0034](adr/0034-conformance-contract-version-2.md), status Proposed.

Review boundary: the JavaScript reference and `interop/second-impl/` were written by the same team and both run on one JavaScript runtime. The specification text for the new operations was written first and the vectors second, both by the lane author, who had read the reference. The second implementation was then extended by a separate agent session instructed not to read the reference source, the operation module, the generator or the expected values of the new vectors before its first run. That is not independent review, and no outside implementation has run any vector.

## Result, with every number taken from running the harness

| Measure | Before | After |
| :--- | ---: | ---: |
| Contract operations | 2 | 6 |
| Vectors | 272 | 485 |
| of which `assess` | 212 | 212 |
| of which `currency` | 60 | 60 |
| of which `canonicalize` | 0 | 72 |
| of which `digest` | 0 | 38 |
| of which `verify-envelope` | 0 | 68 |
| of which `compare` | 0 | 35 |
| of which refusals (must reject) | 83 | 166 |
| Reference: vectors passing | 272 | 485 |
| Second implementation: vectors passing (byte exact) | 272 | 485 |
| Requirements in the registry | 252 | 252 |
| Requirements `pass` in the harness report | 37 | 39 |
| Requirements `not-run` | 215 | 213 |

Both columns come from `node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs"` (the second implementation gives the same numbers with `--impl "node interop/second-impl/adapter.mjs"`). The before column was measured by running the new harness and reference over the committed 272 vector file of the parent commit. The registry holds 252 requirements; the 245 and 247 quoted in earlier texts were stale.

The 213 new vectors are 72 `canonicalize` (45 refusals), 38 `digest` (21), 68 `verify-envelope` (5) and 35 `compare` (12): 83 refusals, 39 percent, above the one third asked for. Newly passing requirements: KYA-INT-003 (golden canonical bytes and signing input) and KYA-BND-003 (comparison). Only two, because a vector may cite only a requirement already in the registry; the other effect is depth, for example KYA-ENV-001 now has 19 more citing vectors, KYA-INT-002 sixty and KYA-INT-004 a hundred and two (most of them refusal vectors, which any non-zero exit satisfies; read that count as thin).

## What was added

| Operation | Input | Result | Normative text |
| :--- | :--- | :--- | :--- |
| `canonicalize` | a JSON text | canonical text and SHA-256, or a refusal | "Canonical form and strict parsing" |
| `digest` | artifact name and a record | preimage and SHA-256, or a refusal | "Digests and signing inputs" |
| `verify-envelope` | kind and an envelope | `valid` with key ID, envelope digest and signing input digest, or the first failing step code | "Envelope verification" |
| `compare` | two assessments | a comparison or the first of eight reason codes; reports that fail their own checks are refused | "Comparison of assessments" |

The contract stays backward compatible: the envelope and result schema strings are unchanged, an implementation that predates version 2 answers `unsupported` and those vectors are `not-run` for it (a test runs exactly that), and the 272 earlier vectors are byte for byte unchanged (their combined digest is pinned in `test/contract-operations.test.mjs`). One harness rule was extended and is documented: for a refusal vector of a version 2 operation, the exact `unsupported` reply is `not-run`.

Specification clarifications written before the code (listed in the CHANGELOG as clarifications): the three refused member names, UTF-16 code unit order of names, number judgement and the shortest round-trip form, escape spelling, depth and size bounds, that record digests carry no domain prefix, the one accepted public key spelling and point rules (previously only in the implementers guide), the order of the eight verification steps, the field rules of an incident payload, and the comparison rules. One library change followed: `compareAssessments` is now built on `describeComparison` and refuses a report that lacks a digest, identifier, mode, decision, score or check shape it reads, instead of comparing absent members as equal.

## Disagreements between the reference and the second implementation

Honest count: none on the vectors. The second implementation passed all 205 vectors of the first batch on its first run, and the eight incident vectors added afterwards. What the exercise found instead:

| Finding | Kind | Resolution |
| :--- | :--- | :--- |
| The specification gave no field rules for an incident payload, yet `digest` and `verify-envelope` need them. The second implementation guessed them from its own currency code. | spec gap (guess matched) | Rule written into "Field rules"; eight vectors added (valid resolution and appeal, report with a reference, resolution without one, unknown severity, unknown kind, extra member, bad details digest). |
| The second implementation's stdin parser refused only one of the three prototype names, allowed depth 64 (text: 32), had no value count, string length or size bound, accepted integer-valued numbers above 2^53-1 only by accident, and decoded ill-formed UTF-8 leniently. | second implementation bug against its own text; the text for "prototype keys" had not named them | Names written into the specification; parser rewritten from the text; the new `canonicalize` refusal vectors cover each name. |
| The contract README said input of up to 4 MiB; the reference parser refused above 1 MiB. | contract text bug | README states the parser limits; a test sends 1,048,576 and 1,048,577 byte inputs to both adapters. |
| Type of a check `status` in a comparison, whether `blockers` must be an array when `blockerCodes` is present, whether a mandatory minimum name is checked when a policy is only digested. | spec silences | Written into the comparison and field rules text. |
| A high surrogate directly followed by a low one when each was written differently. | spec silence | One sentence added: the judgement is on decoded characters. |

Still guesses no vector pins (see `interop/second-impl/AMBIGUITIES.md`, section E): the range of check weights in a comparison, whether a check entry needs a `critical` member, the observable order of the two parts of the key step, and that the scalar-below-group-order rule is exercised by a single vector.

## What is NOT verified

- No outside implementation has run any vector. The second implementation is same-team, so agreement shows the text plus the contract README were enough for a same-team reader, not that the text is complete or the expected values right.
- Both implementations are JavaScript on one runtime, so number formatting, string escaping and Ed25519 verification (including the check that rejects a scalar of `S + L`) agree partly by construction. A non-JavaScript implementation is the real test of the shortest round-trip number rule and of UTF-16 name ordering. The Python checker under `interop/python/` supports only a smaller numeric subset and was not run against the new operations.
- The 1 MiB input bound and the 100000 value bound are not exercised by a committed vector (too large); one test covers the input bound for both adapters, nothing covers the value count.
- `NO_OBSERVED_CHECKS` is still unreachable (unchanged).
- `verify-envelope` does not consult trust, revocation or subject binding by design; those stay in `assess`.
- Expected values were produced by the reference and checked against hand-written claims in the generator (object subset or function claims); they are not independently derived.

## Next operations by value (ranked, not started)

| Rank | Operation | Unlocks | Why not now |
| ---: | :--- | :--- | :--- |
| 1 | `verify-credential` | the 16 credential bridge requirements | needs a bridge document model in the contract |
| 2 | `verify-capture` | the 19 capture requirements | needs the capture record, hash chain and canary rules written as pure inputs |
| 3 | `build-dossier` and `verify-dossier` | KYA-RPT-002 to KYA-RPT-004 and KYA-REF-003 | large output; needs a size and rendering decision |
| 4 | `validate-conformance-report` | the conformance report format requirements | a record check only; low effort once a second implementation exists |
| 5 | `verify-score-card` | the score card requirements | needs the seeded resampling stated as a pure function |

## Requirement proposals

For the integrator to add to `evidence/requirements.json`; this lane did not edit it. Section names are existing headings of `docs/SPECIFICATION.md`. Test titles are exact declarations in `test/contract-operations.test.mjs`.

| Proposed ID | Level | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- |
| KYA-INT-005 | MUST | Records and bindings | Canonical form MUST sort object members by UTF-16 code unit, MUST write numbers by value in the shortest round-trip form with escapes in lowercase, and strict parsing MUST refuse duplicate members, the member names `__proto__`, `prototype` and `constructor`, integer-valued numbers above 9007199254740991, non-finite numbers, trailing text and nesting deeper than 32. | `canonicalize sorts members by UTF-16 code units and writes numbers by value`; `canonicalize writes escapes in lowercase and leaves DEL and the line separators literal`; `canonicalize refuses duplicates, prototype names, bad numbers, trailing text and deep nesting`; `canonicalize accepts a value at depth 32 and refuses one at depth 33` |
| KYA-INT-006 | MUST | Records and bindings | A record digest MUST be the SHA-256 of the canonical form of a valid record without a domain prefix, a signing input MUST be the domain text, a line feed and the canonical payload, and a record that breaks its field rules MUST have no digest. | `digest of a signing input is domain separated and a record digest is not`; `operations refuse unknown input members and wrong input types` |
| KYA-ENV-007 | MUST | Records and bindings | Envelope verification MUST apply its steps in the specified order and name the first failing step, and a valid envelope MUST NOT be treated as trusted. | `verify-envelope reports a tampered payload as an invalid signature and trust is not consulted`; `verify-envelope applies its steps in the order the specification lists`; `every specified failure code and reason code appears in at least one vector` |
| KYA-BND-004 | MUST | Reports and viewers | Comparison MUST refuse a report that fails its checksum, blocker code rules or shape checks, MUST name the first failing comparability rule, and MUST NOT compare an incomplete population. | `compare refuses a resealed report that lacks a digest member and compareAssessments agrees`; `compare gives a reason code for each rule and the first failing rule wins` |
| KYA-VEC-012 | MUST | Interoperability and versioning | Contract version 2 MUST leave the vectors of earlier operations byte for byte unchanged, MUST score an operation an implementation does not claim as not-run and not fail, and at least a third of the vectors of the new operations MUST be refusals. | `the vectors file is version 2, adds the four operations and keeps the 272 version 1 vectors byte for byte`; `at least a third of the new vectors are refusals and every new vector cites a requirement and names it in its rationale`; `an implementation that predates version 2 scores its version 1 vectors as before and the new vectors are not-run`; `the new operations do not change the result of a version 1 assessment` |
| KYA-VEC-013 | MUST | Interoperability and versioning | The reference adapter and the second implementation MUST refuse stdin above 1048576 bytes and accept an input just inside the bound, and the reference adapter MUST answer the four operations. | `both adapters refuse stdin above one mebibyte and accept an input just inside it`; `the reference adapter answers the four operations and still refuses malformed input` |
