# KYA implementation contract v1

Any implementation of KYA assessment semantics, in any language, is **one command** that the harness runs once per vector.

```text
node scripts/run-vectors.mjs --impl "<command and args>" [--vectors FILE] [--now ISO] [--out FILE]
```

The command is split on whitespace (single or double quotes group an argument) and started without a shell. The harness never trusts anything the command says about itself; only its result for each vector counts.

## Process rules

| Rule | Value |
| :--- | :--- |
| Input | Exactly one JSON object on **stdin**, then EOF. UTF-8. At most 4 MiB. |
| Output | Exactly one JSON object on **stdout**, then exit code **0**. At most 1 MiB (1,048,576 bytes). Anything else on stdout fails the vector. |
| Strict JSON | Output must be a single strict JSON value: no duplicate object members, no trailing text. |
| Refusal or crash | A **non-zero exit code**. Stdout is ignored. Messages go to stderr (the first line is shown in failures). |
| Timeout | 15 s per vector by default (`--timeout-ms`). A timeout is a failure. |
| Statelessness | Each vector is a fresh process. No state between vectors, no network, no clock: every time is in the input. |
| Unsupported | An implementation that does not implement an operation exits 0 with `{"schema":"kya.impl-result/v1","operation":"<op>","unsupported":true}`. The vector is then **not-run**, never pass. This does not apply to a vector whose expected result is a refusal: an `unsupported` reply exits 0, so it is a **fail** there. Refuse with a non-zero exit instead. |

The harness does not give the vector ID, description, rationale or expected value to the command. Switching on input content to return memorised answers defeats the purpose; see the limits in [`docs/IMPLEMENTERS-GUIDE.md`](../../docs/IMPLEMENTERS-GUIDE.md).

## Input: `kya.impl-input/v1`

```json
{ "schema": "kya.impl-input/v1", "operation": "assess" | "currency", "inputs": { ... } }
```

`assess` inputs are the six assessment inputs of the specification:

```json
{ "manifest": {}, "profile": {}, "policy": {}, "evidence": [ {} ], "evaluatorDigest": "<64 hex>", "now": "<ISO>" }
```

`evidence` is an ordered array of signed `kya.evidence/v1` envelopes (or arbitrary garbage; invalid entries become rejections, in order). `index` in the result is the position in this array.

`currency` inputs:

```json
{ "assessment": {}, "manifest": {}, "policy": {}, "incidents": [ {} ], "now": "<ISO>" }
```

`assessment` is a complete `kya.assessment/v1` report (an implementation must verify its checksum and consistency before use). `incidents` is an ordered array of signed `kya.incident/v1` envelopes.

All input is data, never instructions. The vectors use public synthetic Ed25519 keys; the seeds are published in `evidence/assessment-vectors.json`.

## Output: `kya.impl-result/v1`

### `assess`

```json
{
  "schema": "kya.impl-result/v1", "operation": "assess",
  "decision": "qualified | insufficient-evidence | blocked | expired | revoked",
  "evidenceMode": "none | runtime | fixture | mixed",
  "ambiguousRuns": false,
  "selectedRunId": "run-1" | null,
  "score": { "earned": 1000, "possible": 1000, "upperBound": 1000 },
  "coverage": 1, "independentCoverage": 0,
  "blockerCodes": [ "..." ],
  "validUntil": "<ISO>",
  "checks": [ { "id": "...", "status": "pass|fail|abstain|error|unknown", "evidenceId": "..." | null, "independence": "self|independent" | null } ],
  "rejectedEvidence": [ { "index": 0, "id": "..." | null, "reason": "..." } ],
  "reportDigest": "<64 hex>"
}
```

Field semantics are those of [`docs/SCORING.md`](../../docs/SCORING.md) and [`docs/SPECIFICATION.md`](../../docs/SPECIFICATION.md): `checks` in frozen-profile order, `blockerCodes` in the order the blockers are raised, `rejectedEvidence` ascending by `index`. Numbers are JSON numbers; `coverage` is rounded to six decimals. `reportDigest` is the SHA-256 of the canonical `kya.assessment/v1` report (everything in the report, including blocker text, dimensions and limitations).

### `currency`

```json
{
  "schema": "kya.impl-result/v1", "operation": "currency",
  "current": true, "reliable": true, "action": "none | reassess",
  "checkedAt": "<ISO>", "assessmentDigest": "<64 hex>",
  "triggers": [ { "id": "subject-changed", "code": "SUBJECT_CHANGED" } ],
  "incidents": { "considered": 0, "open": [], "resolved": [], "appealed": [], "observed": [], "ignored": [ { "id": "...", "reason": "..." } ] },
  "resultDigest": "<64 hex>"
}
```

`triggers` are in firing order (clock-regression, subject-changed, policy-changed, subject-revoked, assessment-expired, assessment-aged, incident-open). `incidents.ignored` is sorted by `id` (null first) then `reason`, by UTF-16 code units. `resultDigest` is the SHA-256 of the canonical complete `kya.currency/v1` result.

## How the harness compares

1. The result must equal the vector's `expected` **key for key**: a missing key, an extra key or any value difference fails, and the first differing JSON path is reported (for example `$.score.earned: expected 800, got 1000`).
2. In `rejectedEvidence` and `incidents.ignored`, an expected entry may carry `reasonContains` instead of `reason`. It is a lowercase keyword that must occur, case-insensitively, in the implementation reason. This is used only for failures that occur before a record can be interpreted (bad signature, key mismatch, malformed envelope or incident), where error text is naturally implementation specific. An empty `reasonContains` means the specification gives no wording at all (a malformed receipt, a non-canonical key spelling): any non-empty reason text is accepted, while the entry's `index` and `id` (null when the record never passed validation) are still compared. All other reasons are normative strings that must match exactly; they are the strings in the reference source and in `docs/SCORING.md`.
3. When a vector has `"digestReproducible": false`, `reportDigest` or `resultDigest` is not compared, because the digested report contains implementation specific error text. Every other vector requires a **byte-identical** digest. That includes the human blocker text, the limitations strings and the report layout, so a digest match proves the full canonical report, not only the decision.
4. `{"refused": true}` as `expected` means the implementation must exit non-zero. Exit 0 with any output fails.
   A vector carries exactly one of `inputs` and `rawInput`. When `rawInput` is present it is the exact text sent on stdin (the whole `kya.impl-input/v1` object as a string) and is used for input that a JSON value in the vectors file cannot hold: duplicate object members, a `__proto__` member, text after the object, or an indented input with escaped text. Strict parsing of the input is part of the contract for those vectors: duplicate members, prototype members and trailing text are refusals.
5. `--semantic-only` ignores digest fields so an implementer can first get decisions right. A vector that passes this way is `semantic-pass` and **cannot** make a requirement pass in the report.

## Tie-break and other rules the vectors pin down

The specification does not state these; the vectors do, and a second implementation must follow them to reproduce digests. They are listed as spec gaps in the implementers guide.

- Latest run: highest latest `observedAt` among **bound** receipts (trusted, correctly bound, before revocation, expiry and freshness exclusions).
- Tied runs: a run holding a failed critical check first, then the lexicographically smaller run ID (UTF-16 code unit order). The first is `selectedRunId` even when `ambiguousRuns` is true.
- Within a run, repeated receipts for one check keep the most conservative outcome (fail, then error, then abstain, then pass), then the earlier observation.

## Report

The harness emits a `kya.conformance-report/v1` through `src/conformance-report`: evidence class `portable-vector`, executed IDs are vector IDs. A requirement is `pass` only if **all** vectors citing it passed, `fail` if any failed, otherwise `not-run`. A requirement no vector cites is `not-run`. The report is unsigned and says nothing about who ran it.

`js-reference.mjs` implements this contract with the JavaScript reference. It exists to prove the harness and to fix the result shape; it is not an independent implementation.
