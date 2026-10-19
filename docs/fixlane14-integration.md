# Fix lane 14: conformance contract operations for credentials and score cards

Status: proposal for the integrator. `evidence/requirements.json` is not edited by this lane, and neither is anything under `src/conformance/`, `docs/review/` or `docs/pilot/`. Nothing was published, tagged, released, dispatched or announced, and nothing used the network. The design is [ADR-0035](adr/0035-conformance-contract-credentials-and-score-cards.md), status Proposed.

Review boundary: the JavaScript reference and `interop/second-impl/` were written by the same team and both run on one JavaScript runtime. The specification text was written first, then the reference adapter, the generators and the vectors, by the lane author, who had read the reference. The second implementation was then written by a separate agent session instructed not to read the reference source, the operation module, the generator, the score verifier or the vectors before its first run, and given the specification text and the contract README only. That is not independent review, and no outside implementation has run any vector.

## Which operations, and why

The ranked list of lane 13 gave `verify-credential` (16 requirements) first, `verify-capture` (19) second, dossiers third and score cards fifth. Counting what a vector can reach: the credential rules (KYA-VCB) and the score card rules (KYA-SCR) are pure functions of their inputs, while the capture requirements describe a runtime cell (a proxy, a world and a canary), not a function of a record, and the dossier operations still need a size and rendering decision. So this lane took the credential and the score card requirements together. Together they have 30 requirements; 21 now have vectors, and the rest need an export operation, a status index function, a CLI test or a source scan that is not a contract operation.

## Result, with every number taken from running the harness

| Measure | Before | After |
| :--- | ---: | ---: |
| Contract operations | 6 | 9 |
| Vectors | 485 | 799 |
| of which `verify-credential` | 0 | 223 |
| of which `verify-score-card` | 0 | 72 |
| of which `compare-score-cards` | 0 | 19 |
| of which refusals (must reject) | 166 | 275 |
| Reference: vectors passing | 485 | 799 |
| Second implementation: vectors passing (byte exact) | 485 | 799 |
| Requirements in the registry | 258 | 258 |
| Requirements `pass` in the harness report | 39 | 60 |
| Requirements `not-run` | 219 | 198 |

Both columns come from `node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs"` (the second implementation gives the same numbers with `--impl "node interop/second-impl/adapter.mjs"`). The before column was measured by running the current harness and reference over the committed vector file of the parent commit. The registry holds 258 requirements (lane 13 quoted 252).

The 314 new vectors hold 109 refusals, 35 percent, above the third asked for. Per operation: `verify-credential` 79 of 223 (35 percent), `verify-score-card` 22 of 72 (31 percent, below a third on its own), `compare-score-cards` 8 of 19 (42 percent). Of the refusals, 32 are text the strict stdin parser refuses (`rawInput`: duplicate members, prototype names, an unsafe integer, depth 33, text after the object, a byte order mark, `NaN`, hexadecimal, a trailing comma, a bad escape, a raw control character); the others are input of the wrong shape or type or a policy that breaks its field rules. Read the refusal share narrowly: any non-zero exit satisfies a refusal vector, so a vector that only expects a refusal says little about why.

Newly `pass`: KYA-VCB-002, 003, 004, 005, 006, 007, 008, 009, 010, 012, 013, 014, 016 and KYA-SCR-001 to 008. A requirement is `pass` when every vector citing it passed. None of these 21 is cited only by refusal vectors.

## What was added

| Operation | Input | Result | Normative text |
| :--- | :--- | :--- | :--- |
| `verify-credential` | a `vc+jwt`, the time, expected issuer `did:key`s, an optional policy, status list tokens, a flag and an optional source report | `valid`, the ordered error codes (never messages), issuer trust and role, the sorted names that differ from the report, and the status of each entry | "Credential verification" |
| `verify-score-card` | any JSON value | `valid`, the ordered problem codes, and for a valid card the score and the card digest | "Score card verification" |
| `compare-score-cards` | two values | a comparison or the reasons it is not allowed | "Score card verification" |

The contract stays version 2 and byte compatible: no schema string and no earlier vector changed (their combined digest is pinned), an implementation that does not know the operations answers `unsupported` and gets `not-run`, and tests run exactly that (a wrapper of the six earlier operations, and a pre-version-2 wrapper). The version number changes only when a schema string or the vector file schema must change, so it does not.

## Library changes found by writing the text

Writing the rule down exposed four behaviours a second implementation could not have guessed. Each was fixed in the library, with a test, instead of being written into the text as a quirk (see CHANGELOG, Changed):

- ill-formed UTF-8 in a token header or payload is `MALFORMED` (it was replaced and parsed);
- the evidence block is element 0 of an array (an object keyed `0` was read as one);
- a status list is found by own member and string URL only (`toString` or a coerced key was found);
- a report that passes its checksum but lacks a member the rebuild copies is `REPORT_INVALID` (the verifier threw), and a status entry without `statusPurpose` cannot be rebuilt.

`verifyAssessmentCredential` also returns `reportMismatch`.

## Disagreements between the reference and the second implementation, and with my own claims

First real run of the second implementation (after one syntax error of its own that made every vector crash): `verify-credential` 219 of 219, `verify-score-card` 70 of 71, `compare-score-cards` 19 of 19. Its second run, after the specification was changed, on a file with five more vectors: 222 of 223, 72 of 72, 19 of 19.

| # | Where | Kind | Resolution |
| ---: | :--- | :--- | :--- |
| 1 | `verify-score-card.items-out-of-id-order-in-a-run`: the text said items are in ascending id order; the second implementation refused an unsorted run, the reference sorts and then reports the difference | spec silence (refuse or normalise) | Written: a verifier rebuilding a card sorts the items, an unsorted card differs from its rebuild and is not refused. Vector kept. |
| 2 | `verify-credential.report-status-entry-without-a-purpose`: an entry with no `statusPurpose` | spec silence; the second implementation omitted the member, the reference cannot rebuild it | Written ("the member must be present"), library made to match (`statusEntry` insists), vector added. |
| 3 | `verify-credential.report-lacks-a-copied-member-but-passes-its-checksum`: my hand claim expected a mismatch; the reference said `REPORT_INVALID` because any absent copied member breaks the rebuild | my claim was wrong and the first text was incomplete | Spec now lists the rule (a report lacking any copied member is `REPORT_INVALID`), the claim was corrected to the rule, not to the observed bytes. The second implementation passed by luck, because its own check was stricter than the text; it was aligned to the text. |
| 4 | The second implementation's `REPORT_INVALID` test reused the whole comparison shape check | spec silence; reference uses only checksum and `blockerCodes` rules | Written: only those two checks, the comparison shape checks do not apply. |

Gaps the second implementation reported where no vector forced a difference, now written into the text: the member names inside `outcomes`, `repeatVariance`, `cost`, `runtime`, `integrity` and each aggregate (and that an aggregate has no label), that `version` members are identifiers, that the rebuilt `credentialStatus` is an array, that issuer trust stays as opening left it after `ISSUER_NOT_TRUSTED`, that malformed shape is judged before the floor, and that `unverifiable` keeps the earlier problems. Items it chose without a vector deciding them, still not pinned: a report with `blockerCodes` but no `checks` array is treated as invalid by the second implementation (the text now says `blockers` must be an array; whether `checks` is read is not stated), and the exact behaviour for a status list GZIP stream with trailing data.

Fixture slips found by the generator (reference against my claims, none an expected-value edit): a baseline whose standard deviation was zero (so an "edited sd" vector did not differ) and a 29-item vector that held 31 items.

## What is NOT verified

- No outside implementation has run any vector. The second implementation is same-team: agreement shows the text and the README were enough for a same-team reader, not that the text is complete or the expected values right. After the first batch the text was changed in response to its reports, so the final 799 agree with a text written partly after seeing the second implementation's questions.
- Both are JavaScript on one runtime. Ed25519 verification (including the scalar bound), GZIP, base64url, UTF-8 decoding and number formatting agree partly by construction. A non-JavaScript implementation is the real test of the sfc32 arithmetic, the round-half-up rule and the shortest round-trip form. The Python score verifier under `interop/score-verifier/` was not run against the new operation.
- The score card vectors use cards of 32 items and at most 20000 resamples; the card size bounds (2000 items, 32 runs) and the 1 MiB canonical limit (the `unverifiable` problem) have no vector.
- No vector pins GZIP with trailing data or concatenated members, a signature whose `R` is a non-canonical point, torsion components in a valid issuer key, or cofactored against cofactorless verification.
- Several requirements are `pass` while their statement has parts no vector tests: KYA-VCB-002 and 003 (export refusal and determinism), KYA-VCB-009 (decoding bounds are tested, not every malformed entry), KYA-VCB-013 (revocation mapping from a policy), KYA-SCR-005 (the builder refusal, only the verifier side), KYA-SCR-006 (a SHOULD about report members), KYA-SCR-008 (the import ban). Read `pass` as "the vectors citing it passed".
- `verify-credential` does not check the status index assignment, the CLI trust flags (KYA-VCB-011, 015) or the VC bridge export (KYA-VCB-001); no vector cites them.
- Expected values were produced by the reference and checked against hand-written claims in the generators; they are not independently derived.

## Next operations by value (ranked, not started)

| Rank | Operation | Unlocks | Why not now |
| ---: | :--- | :--- | :--- |
| 1 | `verify-capture` | the 19 capture requirements | the record, hash chain, canary encodings and world replay must first be written as pure inputs |
| 2 | `export-credential` | KYA-VCB-001, 003 and KYA-IBR-001 to 007 | needs a signing key in the vector (public synthetic seeds are possible) and a decision on whether signing belongs in the contract |
| 3 | `build-dossier` and `verify-dossier` | KYA-RPT-002 to 004, KYA-REF-003 | large output; size and rendering decision |
| 4 | `validate-conformance-report`, `validate-profile-entry` | the report format and profile registry requirements | record checks only |
| 5 | `allocate-status-index` | KYA-VCB-011 | one HMAC function, needs a secret in the vector |

## Requirement proposals

For the integrator to add to `evidence/requirements.json`; this lane did not edit it. Section names are existing headings of `docs/SPECIFICATION.md`. Test titles are exact declarations in `test/contract-credential-score.test.mjs` and `test/contract-operations.test.mjs`.

| Proposed ID | Level | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- |
| KYA-VCB-017 | MUST | Interoperability and versioning | Credential verification MUST apply its opening steps in the specified order and name the first failing step by code, and MUST NOT infer issuer trust from a valid signature: trust is relative to expected issuers or a policy anchor that is not revoked. | `verify-credential applies its opening steps in the order the specification lists`; `verify-credential never infers trust from a signature and trust by policy needs a live anchor` |
| KYA-VCB-018 | MUST | Interoperability and versioning | Credential verification MUST refuse ill-formed UTF-8 in a token, MUST read the evidence block only from an array, MUST look a status list up by own member and string URL only, and MUST report a report that cannot be rebuilt from as invalid instead of failing; without the source report it MUST claim internal consistency only. | `the credential library refuses ill-formed UTF-8 and reads only an array as the evidence block`; `verify-credential status checks use own members of statusLists only and name each failure`; `verify-credential reports internal consistency only without the report and names the differing member with it` |
| KYA-VCB-019 | MUST | Interoperability and versioning | The credential verification operation MUST refuse input of the wrong shape, type or policy field rules and MUST NOT return a result for it. | `verify-credential refuses input outside the contract and never returns a result for it` |
| KYA-SCR-015 | MUST | Interoperability and versioning | Score card verification MUST recompute every derived number from the embedded items and manifest, MUST judge a value that is not a card as invalid without refusing, and MUST accept a re-sealed edit of a manifest member that no computation reads. | `verify-score-card recomputes every number from the items and judges a value that is not a card without refusing` |
| KYA-SCR-016 | MUST | Interoperability and versioning | Score card verification MUST fail a card below the evidence floor or with a lowered floor, and comparison MUST NOT compare cards unless both are valid and their suite and evaluator digests match. | `verify-score-card fails a card whose evidence is below the floor or whose floor was lowered`; `compare-score-cards compares only valid cards of one suite and evaluator` |
| KYA-VEC-014 | MUST | Interoperability and versioning | Adding operations to contract version 2 MUST leave the earlier vectors and the keys byte for byte unchanged, MUST score an operation an implementation does not claim as not-run and not fail, at least a third of the later vectors MUST be refusals, and every specified code MUST appear in at least one vector. | `the vectors file lists nine operations and keeps the earlier 485 vectors and the keys byte for byte`; `at least a third of the later vectors are refusals and every one cites a requirement and names it in its rationale`; `an implementation of the six earlier operations scores the three later ones as not-run and keeps every other result`; `every specified credential code, score card problem code and comparison reason appears in at least one vector` |
