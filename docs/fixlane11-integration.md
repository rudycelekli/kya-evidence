# Fix lane 11: portable conformance vectors and the unwritten rules they exposed

Status: proposal for the integrator. `evidence/requirements.json` is not edited by this lane, and neither is anything under `src/conformance/`, `src/evidence` or `test/property-*`. Nothing was published, tagged, released or announced, and nothing used the network.

Review boundary: the JavaScript reference, `interop/second-impl/` and `interop/python/` were all written by the same team. The new vectors were written by one agent from `docs/SPECIFICATION.md` and `docs/SCORING.md` before the reference was consulted, and then checked against the reference and the second implementation. That shows the text is now precise enough for the same team to rebuild the reference output. It is not independent review, and no outside implementation has run these vectors.

## Result, with every number taken from running the harness

| Measure | Before | After |
| :--- | ---: | ---: |
| Vectors | 111 | 272 |
| of which `assess` | 76 | 212 |
| of which `currency` | 35 | 60 |
| of which refusals (must reject) | 12 | 83 |
| of which carry `rawInput` | 0 | 9 |
| Reference: vectors passing | 111 | 272 |
| Second implementation: vectors passing (byte exact) | 111 | 272 |
| Requirements in the registry | 245 | 245 |
| Requirements `pass` in the harness report | 31 | 37 |
| Requirements `not-run` | 214 | 208 |

`node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs"` and the same with `--impl "node interop/second-impl/adapter.mjs"` both print 272 vectors passing, none failing, and 37 requirements `pass`, 208 `not-run`, 245 in total. The earlier guide text said 31 of 211 and 180 `not-run`; that was stale (the registry already had 245 requirements and the harness said 31 and 214). The guide now carries the measured numbers.

The 161 new vectors are 136 `assess` and 25 `currency`; 71 of them (44 percent) are refusals, so refusals are well over a third of the new set. Newly passing requirements: KYA-INT-001, KYA-INT-002, KYA-ENV-001, KYA-ENV-002, KYA-SCO-003 and KYA-RPT-005. Three of those are partial passes; see the table.

## Step 1: ranked coverage table

Method: each of the 245 requirements was classified by whether a pure input to output vector over the documented contract (`assess` and `currency`, `interop/impl-contract/README.md`) can test it. Ranks 1 to 6 are the expressible requirements that no vector cited before this lane, then the thinly cited ones, then the well covered ones. All 37 expressible (or partly expressible) requirements are now cited. The other 208 cannot be reached through the two operations today.

| Rank | Requirement | Level | Area | Expressible over assess or currency | Vectors before to after | Effort | Note |
| ---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | KYA-RPT-005 | SHOULD | reporting | yes | 0 to 29 | low |  |
| 2 | KYA-ENV-001 | MUST | envelope | yes | 0 to 18 | low |  |
| 3 | KYA-INT-002 | MUST | integrity | partly | 0 to 10 | low | Duplicate members, prototype keys and trailing text via rawInput; the size and depth bounds are not exercised (a 4 MiB vector is too large to commit). |
| 4 | KYA-SCO-003 | SHOULD | scoring | yes | 0 to 9 | low | Order is expressible; the wording is visible only through reportDigest. |
| 5 | KYA-ENV-002 | MUST | envelope | partly | 0 to 5 | low | Trust anchors are covered; the proof layer is covered only by the Python checker and test/second-impl-strictness.test.mjs, because a small-order proof key is rejected whether or not the verifier checks the point. |
| 6 | KYA-INT-001 | MUST | integrity | partly | 0 to 4 | low | Member order and string escapes are expressible; accessors, cycles, symbols and resource limits need in-process objects. |
| 7 | KYA-PRN-001 | MUST | principal | yes | 1 to 8 | done |  |
| 8 | KYA-MIN-004 | MUST | minimums | yes | 2 to 7 | done |  |
| 9 | KYA-TRU-005 | MUST | trust | yes | 2 to 6 | done |  |
| 10 | KYA-MON-003 | MUST | monitoring | yes | 2 to 5 | done |  |
| 11 | KYA-REF-002 | MUST | refusal | yes | 1 to 5 | done |  |
| 12 | KYA-INC-001 | MUST | incidents | yes | 1 to 4 | done |  |
| 13 | KYA-MIN-003 | MUST NOT | minimums | yes | 2 to 4 | done |  |
| 14 | KYA-RUN-002 | MUST | run-selection | yes | 2 to 4 | done |  |
| 15 | KYA-MIN-001 | MUST | minimums | yes | 2 to 2 | done | Present and absent field are covered; the absent case equals the base vector. |
| 16 | KYA-RPT-001 | MUST | reporting | partly | 1 to 2 | done | Checksum tamper refusal is expressible; replay from trusted inputs is a verify operation. |
| 17 | KYA-INT-004 | MUST | integrity | yes | 9 to 80 | done |  |
| 18 | KYA-TRU-004 | MUST | trust | yes | 13 to 27 | done |  |
| 19 | KYA-SCO-001 | MUST | scoring | yes | 18 to 23 | done |  |
| 20 | KYA-INC-002 | MUST | incidents | yes | 14 to 22 | done |  |
| 21 | KYA-TRU-002 | MUST | trust | yes | 4 to 17 | done |  |
| 22 | KYA-BND-001 | MUST | binding | yes | 9 to 16 | done |  |
| 23 | KYA-INC-003 | MUST | incidents | yes | 7 to 16 | done |  |
| 24 | KYA-MIN-002 | MUST | minimums | yes | 9 to 15 | done |  |
| 25 | KYA-TRU-001 | MUST | trust | yes | 10 to 15 | done |  |
| 26 | KYA-RUN-001 | MUST | run-selection | yes | 3 to 14 | done |  |
| 27 | KYA-MON-001 | MUST | monitoring | yes | 12 to 13 | done | Boundary behaviour of expiry and age is deliberately not extended here (another lane is changing currency semantics). |
| 28 | KYA-REF-004 | MUST | refusal | yes | 9 to 10 | done |  |
| 29 | KYA-RUN-004 | MUST | run-selection | yes | 5 to 10 | done |  |
| 30 | KYA-SCO-002 | MUST | scoring | yes | 9 to 10 | done |  |
| 31 | KYA-BND-002 | MUST | binding | yes | 3 to 9 | done |  |
| 32 | KYA-REF-001 | MUST | refusal | yes | 5 to 8 | done |  |
| 33 | KYA-INC-004 | MUST | incidents | yes | 5 to 7 | done |  |
| 34 | KYA-MON-002 | MUST | monitoring | yes | 3 to 7 | done |  |
| 35 | KYA-PRN-002 | MUST | principal | yes | 3 to 7 | done |  |
| 36 | KYA-RUN-003 | MUST | run-selection | yes | 6 to 7 | done |  |
| 37 | KYA-TRU-003 | MUST | trust | yes | 5 to 6 | done |  |

Not expressible, per requirement (the ones a reader would otherwise expect to be vectors):

| Requirement | Level | Area | Class | Effort to make a vector | Why not now |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-INT-003 | MUST | integrity | needs new operation | medium | Golden canonical bytes and signing input: a canonicalize or sign operation, or the golden file, not assess or currency. |
| KYA-BND-003 | MUST | binding | needs new operation | medium | Comparison of two assessments (compare). |
| KYA-TRU-006 | MUST | trust | not a vector | n/a | A Proxy object substituted in process; there is no JSON form of that attack. |
| KYA-RPT-002 | MUST | reporting | needs new operation | high | Dossier build and verify. |
| KYA-RPT-003 | MUST | reporting | needs new operation | high | Dossier. |
| KYA-RPT-004 | MUST | reporting | needs new operation | high | Dossier reseal. |
| KYA-CON-001 | MUST | conformance | needs new operation | high | The conformance suite runner (agent behaviour). |
| KYA-EVL-001 | MUST | evaluator | repository property | n/a | Digest pin over source files. |
| KYA-REF-003 | MUST | refusal | needs new operation | medium | Report comparison, dossier validation and the viewer. |
| KYA-CRY-001 | MUST | integrity | repository property | n/a | Inventory of signing sites in the source tree. |
| KYA-ENV-003 | MUST | envelope | implementation-specific | n/a | About one named second implementation. |
| KYA-ENV-004 | MUST | envelope | implementation-specific | n/a | About one named second implementation. |
| KYA-ENV-005 | SHOULD | envelope | implementation-specific | n/a | A three-way differential test. |
| KYA-ENV-006 | MUST | envelope | implementation-specific | n/a | A count claim about the second implementation. |

Not expressible, by group (every remaining requirement; 194 in total):

| Prefix | Count | MUST | SHOULD | Area | Why not vectors over assess or currency |
| :--- | ---: | ---: | ---: | :--- | :--- |
| UNI | 2 | 2 | 0 | research | Research universes (replay of a frozen universe). |
| BEN | 2 | 2 | 0 | benchmarks | Embedded benchmark catalogue. |
| REL | 12 | 10 | 2 | release | Release process and evidence. |
| REQ | 1 | 1 | 0 | requirements | Properties of the registry. |
| CNF | 5 | 5 | 0 | conformance | Conformance report format (a record, not an assess or currency input). |
| SUI | 5 | 5 | 0 | suites | Scenario suites. |
| HLD | 4 | 4 | 0 | holdout | Protected holdouts. |
| CMP | 20 | 19 | 1 | campaign | Campaign ledger. |
| ACT | 16 | 16 | 0 | adoption | GitHub Action and adoption tooling. |
| VCB | 16 | 16 | 0 | vcb | Verifiable credential bridge (would need a verify operation). |
| GOV | 4 | 4 | 0 | GOV | Governance documents. |
| SUP | 3 | 3 | 0 | release | Supply chain. |
| VEC | 9 | 8 | 1 | vectors | Properties of the harness and generator themselves. |
| XWK | 5 | 4 | 1 | crosswalks | Regulatory crosswalks (documents). |
| ASR | 4 | 3 | 1 | ASR | Assessor records. |
| PRF | 5 | 4 | 1 | PRF | Profile registry. |
| PRV | 6 | 1 | 4 | privacy | Privacy scanner. |
| IBR | 9 | 8 | 1 | ibr | Interoperability bridges. |
| CAL | 6 | 6 | 0 | calibration | Calibration. |
| CLB | 7 | 7 | 0 | claim-boundaries | Claim boundary codes. |
| CAP | 19 | 18 | 1 | capture | Capture cell (would need a verify-capture operation). |
| DOC | 13 | 13 | 0 | docs | Documentation claims. |
| CLI | 2 | 2 | 0 | cli | Command line. |
| CAM | 3 | 3 | 0 | campaign | Campaign adapters. |
| SCR | 14 | 13 | 1 | benchmarks | Score card and benchmark profile. |
| TRM | 2 | 2 | 0 | terminal | Terminal rendering. |

Reading the tables: the ceiling for the current contract is 37 of 245, and it is reached. The real gap is the contract, not the vectors. Making more requirements portable needs new operations (candidates, in value order: `canonicalize` for KYA-INT-003 and the rest of KYA-INT-001; `compare` for KYA-BND-003; `verify` of a credential for the 16 KYA-VCB requirements; `verify` of a capture for the 19 KYA-CAP requirements; dossier build and verify for KYA-RPT-002 to KYA-RPT-004). Each is a contract change with its own reference adapter and second implementation work, so none was attempted here.

## Step 2: vectors added per area

Areas are assigned by vector ID pattern, so treat the split as approximate; the totals are exact. Refusals in parentheses.

| Area | New vectors | What they pin |
| :--- | ---: | :--- |
| Blocker order and short circuit | 8 (0) | Table order of the insufficiency blockers, critical failure suppressing them, minimum entries appended, expired and revoked subjects short circuiting, score not judged under insufficient coverage |
| Scoring arithmetic | 4 (0) | Floor on thirds, coverage display rounded while the decision uses the ratio (0.666667 against 2/3), upper bound floor |
| Run selection and run rules | 22 (0) | Which receipts count toward recency (disallowed source, untrusted signer, other subject, future dated), latest run by time and not by ID, three runs, three-way tie, run recency as the latest observation, issuer, repeated-check and duplicate-ID rules over bound receipts, duplicates across runs, older-run rules |
| Rejection reason order | 12 (0) | Adjacent pairs of reasons in the specification's list |
| Envelope key strictness | 26 (17) | Eight non-canonical spellings of a proof key (each must be rejected), the same eight as a trust anchor (each must refuse), long form DER, trailing bytes, identity point, order two point, off-curve y, non-canonical y, a forged identity-key signature |
| Canonical form and strict parsing | 11 (7) | Reversed member order, unicode and escapes, number spellings, duplicate members (top level, manifest, receipt, escaped spelling, input envelope), prototype key, trailing text |
| Field rules and grammars | 28 (28) | Unknown fields, identifier, hash, text and timestamp grammars, numeric ranges, enumerations, containment, temporal order, duplicates |
| Receipt shape | 4 (0) | A validly signed receipt with an extra member, an unknown outcome, an expiry before observation or a bad check ID is rejected for that receipt |
| Principal binding | 11 (7) | Both kinds, coverage before principal in blocker order, adding or changing the principal after signing invalidates receipts, malformed declarations, case variation of the agent ID |
| Mandatory minimums | 10 (5) | Older run, rejected receipt, error outcome, independent fail, not met and unproven in policy order, five malformed shapes |
| Incidents and currency | 25 (7) | Two open reports, partial resolution, resolution dated before the report, delivery order, untrusted or revoked resolver, other subject, reason order, severity classes, appeals, narrative member, malformed entries, blocker code checks, a legacy report without codes |

Negative vectors for every MUST NOT covered. The harness cites a vector as evidence for a requirement, so each MUST NOT below has at least one vector in which the forbidden behaviour is attempted and must not happen:

| Requirement | MUST NOT | Negative vectors (examples; the file has more) |
| :--- | :--- | :--- |
| KYA-TRU-001 | a receipt makes its own key trusted or independent | `assess.recency-ignores-run-from-untrusted-signer`, `assess.reason-order-untrusted-signer-before-wrong-subject` |
| KYA-TRU-003 | a declaration satisfies a scored check | `assess.reason-order-check-outside-profile-before-declaration` |
| KYA-TRU-005 | an untrusted duplicate removes a trusted result; duplicates boost score | `assess.duplicate-id-counts-a-copy-that-is-expired`, `assess.duplicate-id-across-runs-is-quarantined` |
| KYA-RUN-001 | checks from several runs are composed | `assess.older-pass-cannot-rescue-newer-critical-failure`, `assess.recency-follows-observation-time-not-run-id-order` |
| KYA-RUN-002 | tied runs qualify | `assess.three-way-tie-is-ambiguous` |
| KYA-RUN-003 | invalidating a newer failure revives an older pass | `assess.older-pass-cannot-rescue-newer-critical-failure` |
| KYA-RUN-004 | a repeated check repairs or refreshes | `assess.repeated-check-pass-then-fail-cannot-qualify`, `assess.repeated-check-counts-a-copy-that-is-expired` |
| KYA-SCO-001 | removing a check improves the score | `assess.score-upper-bound-floors`, `assess.score-not-judged-when-coverage-insufficient` |
| KYA-PRN-001 | an agent is its own accountable party (also under case variation) | `assess.refuse-agent-is-own-accountable-party-in-another-case` |
| KYA-PRN-002 | a policy requiring an accountable party qualifies without one | `assess.order-ambiguous-runs-then-principal-unbound`, `assess.principal-unbound-after-coverage-in-order` |
| KYA-MON-002 | a non qualified decision is reported reliable | `currency.blocked-assessment-is-current-but-never-reliable` |
| KYA-INC-002 | untrusted, revoked, misdirected or malformed records trigger | `currency.reason-order-untrusted-key-before-other-subject`, `currency.entry-that-is-not-an-envelope-ignored` |
| KYA-INC-004 | input order changes the outcome | `currency.resolution-listed-before-its-report-still-resolves` |
| KYA-REF-002 | a code list contradicts the report | `currency.refuse-resealed-blocker-codes-contradict-the-critical-failure` |
| KYA-MIN-003 | a declaration or removed evidence satisfies a minimum | `assess.minimum-met-only-in-older-run-is-unproven`, `assess.minimum-pass-from-untrusted-signer-is-unproven` |
| KYA-ENV-001, KYA-ENV-002 | a second spelling or a small order key is accepted | the 18 spelling vectors and the 5 point vectors |
| KYA-INT-002 | a duplicate member is accepted | the five duplicate member vectors |

Each refusal vector was checked to refuse for the stated reason, not for some other defect: the reference error text of every new refusal names the intended rule (for example `Expected canonical public SPKI PEM only`, `Duplicate or forbidden JSON member`, `Invalid Ed25519 public key: small-order point`, `Agent ID: invalid identifier`), and the unmutated input of each is an accepting vector.

## Disagreements and findings

Method: expected values come from the reference, but every vector also has a hand-written claim made from the text before the reference was consulted; the generator refuses to write when they differ. No claim and no expected value was edited to turn a run green.

### Reference against hand-written claims (2 mismatches in 161 vectors)

1. `assess.score-not-judged-when-coverage-insufficient`: my claim said coverage 0.7 and upper bound 700; the right values are 0.6 and 800. An arithmetic mistake in the claim.
2. A revoked key signing one extra receipt of a run: the reference raised `MIXED_RUN_ISSUERS` in addition to `RUN_INVALIDATED`, which my claim did not expect. This was the first sign of an unwritten rule (finding D6 below), not a reference bug. The vector was rebuilt so that its claim is true, and the rule got its own vectors.

### The second implementation against the vectors

Run against the final vector file, the second implementation as committed before this lane failed 26 of the 161 new vectors; the reference failed none.

| Finding | Vectors failed | Kind | Resolution |
| :--- | ---: | :--- | :--- |
| D1 The assessment lists the six fixed dimensions in order, zeros for an unused one | 4 | Spec ambiguity (SCORING.md silent) | Text added to `docs/SCORING.md`; second implementation fixed |
| D2 Identifier fields use the identifier grammar: agent ID (hyphen, space, 129 characters), accountable party reference | 4 | Spec ambiguity (which fields are identifiers was unwritten) | "Field rules" paragraph in `docs/SPECIFICATION.md`; second implementation fixed |
| D3 Tool IDs unique; `approvalRequired` inside `permissions`; trust anchor ID is the key fingerprint; dimension enumeration | 4 | Bug against the text for duplicate tool IDs; spec ambiguity for the other three | Text added; second implementation fixed |
| D4 Accountable party differs from the agent ID without regard to case | 1 | Bug (KYA-PRN-001 says so) | Second implementation fixed |
| D5 `blockerCodes` must be known codes and agree with the failed critical checks | 2 | Bug against SCORING.md (unknown codes); spec ambiguity (the critical count rule was only in the registry) | Rule added to `docs/SCORING.md`; second implementation fixed |
| D6 Issuer and repeated-check rules use all bound receipts of the selected run, including later rejected ones | 3 | Spec ambiguity | Paragraph added to `docs/SPECIFICATION.md`; second implementation fixed |
| D7 Evidence IDs are duplicated across the whole bundle, in any run, and an expired copy still counts | 3 | Spec ambiguity | Same paragraph; second implementation fixed |
| D8 Revocation, expiry and freshness reasons apply to receipts of older and tied runs, ahead of the run exclusion | 5 | Bug against the written reason order | Clarified in the same paragraph; second implementation fixed |
| D9 `RUN_INVALIDATED` also covers a quarantined duplicate | 0 (both implementations agreed) | Text inaccuracy in the `SCORING.md` table | Table row corrected |

Total: 4 dimension digests, 9 field rule refusals (D2, D3, D4), 6 run rule cases (D6, D7), 5 reason precedence cases (D8) and 2 blocker code checks (D5) is 26 failing vectors. Each fix was made against the new text, and `test/second-impl.test.mjs` plus the harness now hold the second implementation to all 272.

### Probes that found no disagreement but a silent text

Run recency is the latest observation among a run's bound receipts (both implementations agreed; now written and pinned by `assess.run-recency-is-the-latest-observation-in-the-run`). Trust anchors listed in any order, and an evidence array in reverse order, give the same decision in both implementations (not pinned: the text is silent and the digests differ by `index`). A byte order mark is refused by both (not pinned). A lone surrogate escape gave no distinguishing result in the probe (not pinned). Free-text reasons for malformed entries differ between the two implementations, as the text allows.

### The Python checker

`interop/python/kya_portability.py` works on the proof byte layer only. Run through `signature_bytes` over the evidence envelopes of the vectors that concern proofs, it accepted all 72 valid envelopes among them (including the reversed member order ones) and rejected the nine mutated proof keys of the new vectors and the three existing tamper vectors, in agreement with the core and the second implementation. It cannot run assess vectors: its declared numeric subset refuses values such as `0.8` and it has no assessment logic. The number spelling vector `assess.raw-number-spellings-equal-by-value-are-accepted` is therefore checked only by the two JavaScript implementations; Python canonicalises its integer-valued spellings (`7e2`, `86400.0`, `0.0`) to the plain text but reports `unsupported` for `0.8`.

### Harness and generator weaknesses found and fixed

- The generator never checked that a `reasonContains` keyword occurs in the reference reason, so a vector could carry a keyword that the reference itself fails. My first keywords for the eight key spelling vectors did exactly that; the harness run caught them, the generator did not. The generator now throws.
- The generator compared its two runs with `canonical()` over the whole file, which has a 1 MiB bound; the file is now larger than that. It compares per vector.
- A vector could not hold input that JSON parsing of the vectors file would destroy (duplicate members). `rawInput` was added, test first (`test/assessment-vectors.test.mjs`).
- Text reasons that the specification leaves free (a malformed receipt, a non-canonical key spelling) forced a keyword. An empty `reasonContains` now means any non-empty reason; the entry's `index` and `id` are still compared, which is what separates a strict verifier (record never validated, `id` null) from a lenient one (record rejected later, `id` set).

## Requirement proposals

Not applied; for the integrator. IDs are three letters then three digits; the section is an existing `##` heading of `docs/SPECIFICATION.md`; test titles are exact.

| Proposed ID | Level | Area | Section | Statement | Tests (file, exact title) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-FRL-001 | MUST | fieldrules | Reports and viewers | Every record has exactly the members its schema lists, and the identifier, text, hash, timestamp, range, enumeration, uniqueness and containment rules stated in the Field rules paragraph of the specification MUST be enforced as refusals of the whole input, except that an invalid evidence or incident entry is a rejection. | `test/spec-field-rules.test.mjs`: `the specification states the field rules and the scoring document states the dimension layout`; `stated numeric ranges are enforced at both edges by the reference`; `stated profile rules are enforced by the reference`; `stated manifest rules are enforced by the reference`; `stated policy list and trust anchor rules are enforced by the reference` |
| KYA-DIM-001 | MUST | scoring | Reports and viewers | An assessment MUST list the six fixed dimensions in the stated order, and a dimension with no frozen checks MUST report zero for earned, possible, upper bound, coverage and weight. | `test/spec-field-rules.test.mjs`: `an assessment always lists the six fixed dimensions in order and a dimension without checks is all zero` |
| KYA-RUN-005 | MUST | run-selection | Reports and viewers | The issuer, repeated-check and duplicate-ID rules MUST be evaluated over the bound receipts, including those later rejected, an evidence ID MUST be duplicated across the whole bundle, and eligibility reasons MUST take precedence over run exclusion reasons for every run. | `test/spec-field-rules.test.mjs`: `the specification states which receipts the run rules are evaluated over` |
| KYA-VEC-010 | MUST | vectors | Interoperability and versioning | A vector MUST carry exactly one of `inputs` and `rawInput`, the harness MUST send `rawInput` verbatim as stdin, and an empty `reasonContains` MUST accept any non-empty reason and refuse a missing or empty one. | `test/assessment-vectors.test.mjs`: `a vector with rawInput sends exactly that text on stdin and a vector needs exactly one of inputs and rawInput`; `an empty reasonContains accepts any non-empty reason text and refuses a missing or empty reason` |
| KYA-VEC-011 | SHOULD | vectors | Interoperability and versioning | Vectors that restate one input in another spelling (member order, escapes, number spellings, indentation) SHOULD expect exactly the result of the plain spelling. | `test/assessment-vectors.test.mjs`: `vectors that restate the same input in another spelling expect exactly the same result and the spelling really differs` |

KYA-DIM-001 and KYA-RUN-005 cite behaviour that is pinned by the vectors through the harness and by the reference; their listed tests cover the text and the reference rule, and the run rules are exercised by the vector tests (`the JS reference passes every vector through the harness CLI and the report is valid`) as well.

Splits and rewordings the registry needs so that a harness `pass` is not read as more than it shows:

- KYA-INT-001 and KYA-INT-002 each name more than a vector can test. Split into (a) member order and string escapes, and duplicate members and prototype keys (vector-testable, now covered), and (b) accessors, cycles, symbols and resource bounds (in-process, covered by `test/canonical.test.mjs`).
- KYA-ENV-002 covers the core verifiers; the vectors cover trust anchors only. Either split proof layer and anchor layer, or state the partial scope.
- KYA-ENV-006 ("all 111 assessment vectors") and the test titles `second implementation matches the decision and every semantic field of all 111 vectors` (traced by KYA-VEC-009) and `second implementation still matches all 111 assessment vectors` (traced by KYA-ENV-006) now carry a stale number. The tests assert the published count read from the file, so they are correct, but the registry text and titles still say 111. Reword both to "every published assessment vector" and rename the titles together with the registry traces.

## What is NOT verified

- No outside implementation has run any vector. The second implementation and the Python checker are same-team code; this lane's author also made the second implementation fixes, from the new text, so agreement shows consistency of two readings by one team.
- The expected values of the 161 new vectors are the reference output, cross-checked against hand-written claims by the same author who wrote the text additions. They are not independently derived, and the text additions were themselves written from the reference validators (the Field rules paragraph) where the specification was silent. If the reference is wrong about intent, the vectors and the text now agree with it.
- A `pass` for KYA-INT-001, KYA-INT-002 and KYA-ENV-002 is partial (see the table). A `pass` for KYA-SCO-003 and KYA-RPT-005 shows the stated order and vocabulary are reproducible, not that the prose is the best interface.
- Not exercised by any vector: the 4 MiB input and 1 MiB output bounds, nesting depth, a byte order mark, lone surrogates, Unicode normalisation of text, number spellings beyond those used, the tie-break used to report `selectedRunId`, and memorisation resistance (the vectors are public and fixed; there are still no private held-out vectors).
- Wording of blockers is visible only through `reportDigest`, so a wording difference reports at `$.reportDigest` without a finer path.
- The Python checker was not run on assess vectors (it cannot), and was run on proof envelopes only.
- Time boundary behaviour (evidence age equality, manifest expiry equality, currency age equality) was deliberately not extended, because another lane is changing currency semantics; the existing boundary vectors are unchanged.

## Integration notes

- Files changed: `scripts/assessment-vectors.mjs` (161 vectors, `post` and `raw` hooks, per-vector determinism, keyword guard), `scripts/run-vectors.mjs` (`rawInput`, empty `reasonContains`), `evidence/assessment-vectors.json` (regenerated; the first 111 IDs and expected values are unchanged, and the file is now about 3.9 MB), `interop/second-impl/kya2.mjs` and `currency.mjs` (fixed against the new text), `docs/SPECIFICATION.md`, `docs/SCORING.md`, `docs/IMPLEMENTERS-GUIDE.md`, `interop/impl-contract/README.md`, `interop/second-impl/README.md` and `AMBIGUITIES.md`, ADR-0026 (dated update), `CHANGELOG.md`, `docs/CONFORMANCE.md`, `docs/INTEROPERABILITY.md`, `docs/RELEASE-NOTES-ALPHA.md`, `docs/WORLD-CLASS-STATUS.md` and `evidence/world-class-status.json` (the count only), tests `test/assessment-vectors.test.mjs`, `test/second-impl.test.mjs`, `test/second-impl-strictness.test.mjs`, `test/docs-claims.test.mjs` and the new `test/spec-field-rules.test.mjs`.
- Every assess vector's expected result carries `validUntil` and the report digest, so a change of validity semantics in `src/` by the other lane will change the expected values. Regenerate with `node scripts/assessment-vectors.mjs` after that lane lands; the generator will stop on any hand-written claim the new semantics contradict, which is the intended check. Expect `docs/SPECIFICATION.md` to need a manual merge near the new Field rules and run rules paragraphs if that lane edits the same section.
- Test titles that name 111 were left unchanged because `evidence/requirements.json` traces them by exact title.
- Verified here: `node scripts/assessment-vectors.mjs --check`, `node scripts/check.mjs`, both harness runs, and the touched test files (`assessment-vectors`, `second-impl`, `second-impl-strictness`, `spec-field-rules`, `docs-claims`, `privacy`, `scoring-wording`, `spec-reason-vocabulary`). The whole suite and the mutation run were not run.
