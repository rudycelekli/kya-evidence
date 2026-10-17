# Implementers guide

For someone building a second implementation of KYA assessment semantics from the specification, in any language. The reference implementation is JavaScript. Two independent implementations passing shared vectors is the critical path to a credible standard ([work-stream WS3](WORLD-CLASS-PLAN.md)); this guide and the golden assessment vectors are the first piece of that path.

## What you are building

Two pure functions over JSON, with no clock, network or state:

1. `assess(manifest, profile, policy, evidence[], evaluatorDigest, now)` returns a `kya.assessment/v1` report. Selection, trust, scoring, blockers.
2. `checkCurrency(assessment, manifest, policy, incidents[], now)` returns a `kya.currency/v1` result. Change triggers and signed incident handling.

Prerequisites you must also build: the bounded canonical JSON subset and SHA-256 digests (`docs/SPECIFICATION.md`, `evidence/golden-vectors.json`), strict JSON parsing, Ed25519 verification with the `kya.evidence/v1` and `kya.incident/v1` domain prefixes, and the record validators. Start with the existing byte and signature vectors in `evidence/golden-vectors.json`; they are the foundation for everything here.

## Build order that works

1. **Bytes.** Pass `evidence/golden-vectors.json` (canonical bytes, digests, signing input, incident vectors). If your digests differ, nothing above can match.
2. **Validators.** Manifest, profile, policy, evidence, incident: exact keys, identifier and timestamp grammars, list rules. Invalid top-level input is a refusal (non-zero exit); an invalid individual receipt is a rejection with a reason.
3. **Eligibility** per receipt, in the order of `docs/SPECIFICATION.md` "Trust and eligibility". Order matters because some receipts count toward run recency even though they are later rejected.
4. **Run selection**, duplicate quarantine, whole-run rules (`docs/SPECIFICATION.md` "Run selection and qualification", `docs/SCORING.md`).
5. **Scoring and gates**, then mandatory minimums, then blockers in the order the table in `docs/SCORING.md` lists them.
6. **Report assembly** and `reportDigest` (needed for byte-identical digests, not for decisions).
7. **Currency** and incidents.
8. Wrap it in the contract of [`interop/impl-contract/README.md`](../interop/impl-contract/README.md), run the harness, read failures from the first differing path.

Work from the written specification. Reading the JavaScript source is allowed, but then you have a derived implementation, not an independent one; say so when you report.

## Run the harness

```text
node scripts/run-vectors.mjs --impl "python3 my_impl.py" --name my-impl --language python --impl-version 0.1 --out report.json
```

Needs Node 22 and this repository. The summary is one JSON line: vector counts (pass, semantic-pass, fail, unsupported), the conformance summary and the first failing vectors with the first differing JSON path. The exit code is 0 only when every vector passed. Useful options: `--vectors FILE`, `--now ISO` (report time; default is fixed in the vectors file because the harness never reads a clock), `--timeout-ms N`, `--jobs N`, `--semantic-only` (ignore digests while you get decisions right).

To check the harness itself against the reference: `node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs"`.

## Read the report

The output is a `kya.conformance-report/v1` (`docs/CONFORMANCE.md`) with evidence class `portable-vector`; executed IDs are vector IDs.

| Result | Meaning |
| :--- | :--- |
| `pass` | Every vector that cites this requirement passed, byte-exact. |
| `fail` | At least one vector citing it failed or crashed. |
| `not-run` | No vector cites it, a cited vector was unsupported, or you ran `--semantic-only`. |

Read `pass` narrowly. It means the published vectors for that requirement passed. It does not mean the requirement is fully implemented: a requirement that is cited by only a few vectors, or only by refusal vectors (which any non-zero exit satisfies), is thinly tested. The count of vectors per requirement is in the file. `not-run` is not a weaker pass; it stays in the denominator. Vectors cite only a subset of the requirements, so most requirements stay `not-run` by design: running the harness against the JavaScript reference (and against `interop/second-impl/`) gives 111 of 111 vectors passing, 31 of 211 requirements `pass` and 180 `not-run`. An `unsupported` reply to a vector whose expected result is a refusal is a `fail` (exit 0 is not a refusal); refuse with a non-zero exit instead.

The report is unsigned and self-run. Anyone can run the harness on themselves, edit the output or run a different binary. A claim of conformance is credible only when a third party reruns the harness on the exact released implementation and publishes the report, ideally signed with `signReport`.

## The vector file

`evidence/assessment-vectors.json` (`kya.assessment-vectors/v1`) holds 111 deterministic vectors: 76 `assess` and 35 `currency`, of which 12 are refusals. Each has `id`, `description`, a one-line `rationale` tied to the requirement it tests, the cited `requirements`, complete `inputs` and the `expected` result. Keys are public synthetic Ed25519 keys derived from published seeds. Times are fixed. Regenerate with `node scripts/assessment-vectors.mjs`; `--check` fails on drift. The generator also holds a hand-written claim per vector and refuses to write if the reference disagrees, so the file is not only a snapshot of the code.

Coverage in the file: every blocker code except `NO_OBSERVED_CHECKS` and every currency trigger code. Scenario families: mandatory minimums (pass, fail, omitted, abstain, independent-pass, declaration, stacking), principal binding, revoked key, subject and evidence, expiry, ambiguity between tied runs, cross-run cherry-picking, duplicate evidence IDs, declaration laundering, fixture versus runtime, capture-issuer rejection, critical failures, empty evidence, and incidents (open, resolved, appealed, ambiguous, untrusted, revoked key, other subject, duplicate delivery, future dated, invalid record).

## What the vectors do NOT cover

Be explicit; a green run is silent on all of these.

- **Runtime capture.** Whether the evidence came from a real observation of the agent (ADR-0017 capture, campaign ledger, adapters).
- **Truthfulness.** A valid signature proves bytes and key possession. No vector shows an issuer told the truth or was independent.
- **Privacy.** Redaction, minimisation, retention, selective disclosure.
- **Performance and resource limits.** Bounds on size, depth and time beyond the harness limits. Denial of service, memory and timing behaviour are untested.
- **VC bridge** (`docs/VC-BRIDGE.md`), **campaign ledger**, **scenario suites and holdouts**, dossiers, universes, dashboard, CLI, GitHub Action.
- **Verification-only entry points** such as `verifyAssessment` as a standalone operation (it is exercised indirectly by the currency refusals) and `compareAssessments`.
- **Report fields not compared individually.** Dimensions, limitations text, accepted evidence digests and blocker text are covered only through `reportDigest`, so a mismatch there is reported at `$.reportDigest` without a finer path. Use `--semantic-only` to separate decision bugs from layout bugs.
- **Memorisation.** The vectors are public and fixed. An implementation could return stored answers keyed by input. Credibility needs independent review of the source and, later, private held-out vectors; neither exists today.
- **Independence of the expected values.** They come from the JavaScript reference, cross-checked against hand-written claims by the same authors. Two implementations that agree on a vector prove consistency, not correctness against intent.
- **Unreachable code.** `NO_OBSERVED_CHECKS` cannot be produced by any input (qualification needs known weight above zero, which needs at least one selected check). It is listed under `unreachableBlockerCodes`; you need not emit it.

## Spec gaps found while writing the vectors

These are behaviours the vectors pin that the prose specification does not state. Treat them as open questions for the editors, not settled rules.

1. **Tie-break among equally recent runs.** The reference prefers a run with a failed critical check, then the smaller run ID, and reports it as `selectedRunId` even when ambiguous.
2. **Rejection reason strings** are free text in the reference. The vectors treat 22 assess reasons and 12 incident reasons as exact strings because they feed `reportDigest`. A reason code vocabulary would be a better interface.
3. **Error text for malformed envelopes** is implementation specific; those vectors match a keyword and carry no digest.
4. **Within-run conflict handling.** A repeated check keeps the most conservative outcome, then the earlier observation, then the run cannot qualify.
5. **Evidence mode** is `none`, `runtime`, `fixture` or `mixed`, and the fixture limitation string is part of the digest.

## Reporting disagreements

A disagreement is a vector where your result differs from `expected`, or a requirement you believe is mis-specified. Do not edit the vectors to make your implementation pass.

1. Re-run the failing vector alone (`--vectors` with a one-vector file) and keep the harness output, including the first differing path.
2. Decide which side is wrong by reading the cited requirement and the vector rationale. If your implementation is wrong, fix it.
3. If the vector or the specification is wrong or ambiguous, open an issue with the vector ID, the requirement ID, both outputs and your reading of the text. Do not describe the reference as correct merely because it exists.
4. Resolutions are recorded in an ADR and, if semantics change, in a new vector with a regression test; a change to evaluator or protocol follows `AGENTS.md` (substantive ADR, adversarial regression, a test that detects the weakened gate).
5. Report an implementation that crashes or hangs on a vector as a failure, not a skip.

## Claiming conformance

State: the implementation name, version and source digest; the vectors file digest; the harness version; the full report; and which requirements are `not-run` and why. Do not claim conformance to the standard, to Open-KYA, W3C VC, A2A or MCP, or independent review. A passing run claims only that those published vectors passed.

## Second implementation findings

A team-built second implementation (`interop/second-impl/`, not independent, written without reading the reference source) matches the decision and every semantic field of all 111 vectors and now matches all 111 byte for byte. It first matched 43 of 111 byte for byte, then 79, then all 111. The earlier digest gaps came from specification text that is missing: the blocker wording strings, the full `kya.currency/v1` result layout, the `evidenceBundleDigest` definition, the reason vocabulary for rejected evidence and ignored incidents, the blocker short circuit, future-dated recency, and validator grammars. See `interop/second-impl/AMBIGUITIES.md` for the vector-level table. The blocker wording and ordering are now in `docs/SCORING.md`, and the currency result layout, reason vocabularies, validator grammars and future-dated recency rule are in `docs/SPECIFICATION.md` ("Currency result layout and reason vocabulary"). After those additions the team-built second implementation, using only the documented text, reproduced all 111 vectors byte for byte (it reached 43 before, then 79). That shows the text is sufficient for this vector set, not that it is complete or that the implementation is independent; choices no vector pins remain guesses (see `interop/second-impl/AMBIGUITIES.md`).

## Public key strictness

A proof or trust-anchor key has exactly one accepted spelling: `-----BEGIN PUBLIC KEY-----`, a line feed, the 60 base64 characters of the 44-byte Ed25519 SPKI (canonical padding bits, no line wrapping), a line feed, `-----END PUBLIC KEY-----` and a final line feed. CRLF, re-wrapped lines, a missing final newline, blank lines, non-canonical trailing base64 bits, long-form DER lengths and bytes after the SPKI are all refused. The 32-byte key must also decode as an Ed25519 point (RFC 8032 section 5.1.3): a non-canonical `y`, a point off the curve, a non-canonical `x` sign and any small-order point (8P is the identity, so the identity key with signature `01` followed by zero bytes would otherwise verify any payload) are refused. The JavaScript core, `interop/second-impl/` and `interop/python/` now all apply this rule, each with its own point arithmetic (neither the second implementation nor the Python checker imports `src/`). `test/second-impl-strictness.test.mjs` feeds all three the same 60 or more mutated envelopes and requires the same accept or reject decision; the Python checker works at the proof byte layer only, so payload-schema mutations are outside that comparison. These are same-team implementations, so this shows the text is enough to build the rule, not independent confirmation.
