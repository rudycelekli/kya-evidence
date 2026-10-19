# KYA implementation contract, version 2

Contract version 2 adds four pure operations (`canonicalize`, `digest`, `verify-envelope`, `compare`) to the two of version 1 (`assess`, `currency`). It is a strict superset: the envelope schema stays `kya.impl-input/v1` and the result schema stays `kya.impl-result/v1`, the two version 1 operations are unchanged byte for byte, and an implementation that predates version 2 already replies `unsupported` to an operation it does not know (see the process rules), so it scores its version 1 vectors exactly as before and the new vectors are `not-run` for it, never `fail`. The version is carried by the vectors file (`kya.assessment-vectors/v2`, member `contract`), not by the envelope, so that older implementations keep working without a change.

Contract version 2 was later extended with three more pure operations (`verify-credential`, `verify-score-card`, `compare-score-cards`). No schema string and no vector file schema changed, so the version number stays 2: an implementation that does not know one of them already answers `unsupported` (see the process rules) and those vectors are `not-run` for it, never `fail`, and every vector that existed before is byte for byte unchanged. The version number changes only when a schema string or the vector file schema must change; operations are added by listing them in the `contract.operations` member of the vectors file.

Any implementation of KYA assessment semantics, in any language, is **one command** that the harness runs once per vector.

```text
node scripts/run-vectors.mjs --impl "<command and args>" [--vectors FILE] [--now ISO] [--out FILE]
```

The command is split on whitespace (single or double quotes group an argument) and started without a shell. The harness never trusts anything the command says about itself; only its result for each vector counts.

## Process rules

| Rule | Value |
| :--- | :--- |
| Input | Exactly one JSON object on **stdin**, then EOF. UTF-8 (ill-formed UTF-8 is a refusal). The harness sends at most 4 MiB, and the object is read by the strict parser of the specification ("Canonical form and strict parsing"), so its limits apply to the whole input: more than 1,048,576 bytes, nesting deeper than 32 or more than 100,000 values is a refusal. (An earlier text said "at most 4 MiB" and the reference already refused above 1 MiB; this states what was always so.) |
| Output | Exactly one JSON object on **stdout**, then exit code **0**. At most 1 MiB (1,048,576 bytes). Anything else on stdout fails the vector. |
| Strict JSON | Output must be a single strict JSON value: no duplicate object members, no trailing text. |
| Refusal or crash | A **non-zero exit code**. Stdout is ignored. Messages go to stderr (the first line is shown in failures). |
| Timeout | 15 s per vector by default (`--timeout-ms`). A timeout is a failure. |
| Statelessness | Each vector is a fresh process. No state between vectors, no network, no clock: every time is in the input. |
| Unsupported | An implementation that does not implement an operation exits 0 with `{"schema":"kya.impl-result/v1","operation":"<op>","unsupported":true}`. The vector is then **not-run**, never pass. This does not apply to a vector of a version 1 operation (`assess`, `currency`) whose expected result is a refusal: an `unsupported` reply exits 0, so it is a **fail** there. Refuse with a non-zero exit instead. For a refusal vector of a version 2 operation, the exact reply `{"schema":"kya.impl-result/v1","operation":"<the vector's operation>","unsupported":true}` (those three members, operation echoed) is **not-run**, so that an implementation that predates version 2 is not marked as failing refusals it never claimed to implement; any other exit-0 reply is still a **fail**. |

The harness does not give the vector ID, description, rationale or expected value to the command. Switching on input content to return memorised answers defeats the purpose; see the limits in [`docs/IMPLEMENTERS-GUIDE.md`](../../docs/IMPLEMENTERS-GUIDE.md).

## Input: `kya.impl-input/v1`

```json
{ "schema": "kya.impl-input/v1", "operation": "assess" | "currency" | "canonicalize" | "digest" | "verify-envelope" | "compare" | "verify-credential" | "verify-score-card" | "compare-score-cards", "inputs": { ... } }
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

## Version 2 operations

For every operation the `inputs` object has exactly the members listed, no more and no fewer, and each has the stated type; anything else is a refusal. The semantics are normative in `docs/SPECIFICATION.md` ("Canonical form and strict parsing", "Digests and signing inputs", "Envelope verification", "Comparison of assessments").

### `canonicalize`

```json
{ "text": "<a JSON text, as a string>" }
```

Strictly parses `text` and writes its canonical form. Result:

```json
{ "schema": "kya.impl-result/v1", "operation": "canonicalize", "canonical": "<canonical text>", "sha256": "<64 hex of the UTF-8 bytes of canonical>" }
```

A text the strict parser refuses (duplicate or prototype members, trailing text, numbers outside the supported subset, depth or size limits, bad escapes) is a **refusal** (non-zero exit).

### `digest`

```json
{ "artifact": "manifest | scope | profile | policy | evidence-signing-input | incident-signing-input", "value": { } }
```

Result: `{ "schema": "kya.impl-result/v1", "operation": "digest", "artifact": "<as given>", "preimage": "<exact text hashed>", "digest": "<64 hex>" }`. `value` is a manifest (`manifest`, `scope`), a profile, a policy, an evidence payload or an incident payload; a value that breaks the field rules of its record type is a refusal, as is an unknown `artifact`. Only the two signing input artifacts are domain separated.

### `verify-envelope`

```json
{ "kind": "evidence | incident", "envelope": { } }
```

Result:

```json
{ "schema": "kya.impl-result/v1", "operation": "verify-envelope", "kind": "evidence", "valid": true, "failure": null, "keyId": "<64 hex>", "envelopeDigest": "<64 hex>", "signingInputSha256": "<64 hex>" }
```

When the envelope fails a step of the specification, `valid` is `false`, `failure` is the code of the first failing step (`MALFORMED_ENVELOPE`, `INVALID_PAYLOAD`, `MALFORMED_PROOF`, `UNSUPPORTED_ALGORITHM`, `INVALID_KEY`, `KEY_ID_MISMATCH`, `INVALID_SIGNATURE_ENCODING`, `SIGNATURE_INVALID`) and `keyId`, `envelopeDigest` and `signingInputSha256` are `null`. An envelope that is not valid is a **result**, not a refusal; only an unknown `kind` or a malformed `inputs` object is a refusal. `valid: true` says nothing about trust.

### `compare`

```json
{ "left": { }, "right": { } }
```

Both are complete `kya.assessment/v1` reports. A report that is not a well-formed assessment for comparison (checksum, `blockerCodes` rules, missing or mistyped members, a legacy report without a full-scope digest) is a refusal. Otherwise:

```json
{ "schema": "kya.impl-result/v1", "operation": "compare", "comparable": true, "reason": null, "left": "<report digest>", "right": "<report digest>", "scoreDelta": 0, "decisionChanged": false, "measurement": "same-policy evidence comparison; not a causal improvement claim" }
```

When the pair is not comparable, `comparable` is `false`, `reason` is the first failing code (`SCOPE_ID_DIFFERS`, `SCOPE_DIGEST_DIFFERS`, `PROFILE_DIFFERS`, `EVALUATOR_DIFFERS`, `POLICY_DIFFERS`, `EVIDENCE_MODE_DIFFERS`, `CHECK_POPULATION_DIFFERS`, `CHECKS_INCOMPLETE`) and `scoreDelta`, `decisionChanged` and `measurement` are `null`; `left` and `right` are still the two report digests.

### `verify-credential`

The semantics are normative in `docs/SPECIFICATION.md` ("Credential verification"). Inputs, exactly these members:

```json
{ "jwt": "<compact vc+jwt>", "now": "<ISO>", "expectedIssuers": [ "did:key:z..." ], "policy": { } | null, "statusLists": { "<url>": "<compact vc+jwt of that list>" }, "requireStatusCheck": false, "report": { } | null }
```

`expectedIssuers` entries must begin `did:key:`, `policy` (when not null) must satisfy the policy field rules, every `statusLists` value must be a non-empty string, `report` is a `kya.assessment/v1` object or null; anything else is a **refusal**. A credential that fails verification is a **result**:

```json
{ "schema": "kya.impl-result/v1", "operation": "verify-credential", "valid": false, "errors": [ "SIGNATURE_INVALID" ], "authenticated": false,
  "issuer": "did:key:z..." | null, "issuerTrust": "unchecked | expected | anchored" | null, "issuerRole": "independent" | null,
  "reportChecked": false, "reportMismatch": [ ],
  "status": { "checked": false, "entries": [ { "purpose": "revocation" | null, "checked": true, "set": false | null, "error": null } ] } | null }
```

`errors` holds codes only (never messages), in the order the specification records them; a failure to open the credential gives exactly one code and leaves `issuer`, `issuerTrust`, `issuerRole` and `status` null. `reportMismatch` is the sorted list of top level member names that differ from the report. `valid: true` says the issuer key signed these bytes and the claims are consistent; it says nothing about truthful execution, identity or authorisation.

### `verify-score-card`

Normative text: "Score card verification". Inputs: `{ "card": <any JSON value> }`. A value that is not a valid card is a **result**, not a refusal:

```json
{ "schema": "kya.impl-result/v1", "operation": "verify-score-card", "valid": true, "problems": [ ], "score": 800, "cardDigest": "<64 hex>" }
```

`problems` are the codes of the specification in the order listed there; `score` and `cardDigest` are null when the card is not valid.

### `compare-score-cards`

Inputs: `{ "left": <any JSON value>, "right": <any JSON value> }`. Result: `{ "schema": "kya.impl-result/v1", "operation": "compare-score-cards", "comparable": true, "reasons": [ ], "delta": 40, "distinguishable": false }`. When not comparable, `delta` and `distinguishable` are null and `reasons` is `["card-invalid"]` or the reasons `suite-digest-differs` and `evaluator-digest-differs` that apply, in that order. `delta` is the left headline score minus the right.

### What the new vectors cannot show

Size limits (a 1 MiB input is too large to commit) and the 100000 value bound are not exercised by a vector, an implementation in a language whose number formatting differs from ECMAScript has to implement the shortest round-trip rule itself, and the `S` below the group order rule is exercised only through one vector whose signature has `S` replaced by `S + L`. For `verify-credential` and `verify-score-card`, no vector pins GZIP streams with trailing data or concatenated members, the card size bounds (2000 items, 32 runs) or the `unverifiable` problem, and the sfc32 arithmetic, the round-half-up rule and UTF-8 decoding agree between the two JavaScript implementations partly by construction; a non-JavaScript implementation is the real test.

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

`js-reference.mjs` implements this contract (version 2) with the JavaScript reference through `js-operations.mjs`. It exists to prove the harness and to fix the result shape; it is not an independent implementation.
