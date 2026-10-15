# Interop bridges

Implements [ADR-0027](adr/0027-interop-bridges.md). Code: `src/interop-bridges/`. CLI: `scripts/kya-bridge.mjs`. Zero dependencies, no network access, no signing, no default clock. Companion to the signed [VC bridge](VC-BRIDGE.md), which stays the only signed export.

These are **export bindings**. Each takes a `kya.assessment/v1` report and produces a plain JSON object in the shape another ecosystem uses for a similar job. None of them claims conformance with that ecosystem, none is registered anywhere, and no third-party tool has consumed any of them. Names used (in-toto, OpenTelemetry, OAuth 2.0, SPIFFE, A2A, MCP) are neutral references to public specifications; this project is not an official implementation of any of them.

## Rules shared by every export

1. **Fail closed.** The report checksum is verified first. A decision other than `qualified` is refused with `NOT_QUALIFIED` unless the caller passes `allowNonQualified`. Currency (`checkCurrency`, ADR-0013) is evaluated at an explicit `now` against the supplied manifest, policy and incidents; a fired trigger is `NOT_CURRENT`, missing inputs are `CURRENCY_NOT_CHECKED`, and a partial set is `CURRENCY_INPUTS_INCOMPLETE`, all refused unless the caller passes `allowNotCurrent`.
2. **Overrides are visible.** An override only appears in the output when it was needed (`overrides` lists `allowNonQualified` and `allowNotCurrent`). `qualified` is true only when the decision is `qualified` **and** a currency check ran and passed; an export made with an override never reads as qualified-and-current.
3. **Byte for byte reproducible.** Same report and same options give the same bytes. Serialization is KYA canonical JSON (sorted keys) plus one newline (`serialize`). This is not RFC 8785.
4. **Limits travel with the data.** Every export carries the limit list: not an authorization grant; unauthenticated report checksum; unsigned; currency evaluated once at the stated time; no third-party tool has consumed the format and no conformance claim. OpenTelemetry attributes carry `kya.authorization.granted` and `kya.assessment.authenticated` as constant `false`.
5. **No identity.** No principal, agent name or agent id is exported. The subject is the manifest digest.
6. **Evidence mode is copied, never chosen.** There is no option to set it.

## Report-style cross-check

`verifyBridgeExport(kind, output, { report, manifest, policy, now, incidents })`, CLI `kya-bridge verify KIND --export F --assessment F`. It rebuilds the export from the source report with the exporter's own construction and compares the whole object in canonical form; any difference is `REPORT_MISMATCH` naming the member. It never throws on bad input. Limits of the check:

- Without `manifest`, `policy` and `now`, the currency block is taken from the export itself (`currencyRechecked: false`), so a forged currency block is **not** detected. Pass the three to re-derive it; an override recorded in the output is honoured only if the recomputation also needed it.
- It proves consistency with the supplied report, not that the report is truthful or authentic (`authenticated` is always `false`).

## 1. in-toto Statement v1

`exportInTotoStatement`. An unsigned Statement: `_type` `https://in-toto.io/Statement/v1`, `subject` one entry whose `digest.sha256` is the **manifest digest** (`name` is `urn:kya:subject:sha256:<digest>`), `predicateType` `urn:kya:predicate:assessment:v1`. The predicate type is a URN chosen here and is not in any predicate registry. No DSSE envelope is made; wrapping and signing are the caller's job.

| Predicate member | Source |
| :--- | :--- |
| `decision`, `qualified` | `decision`; qualified per rule 2 |
| `scores` | `score.earned`, `score.possible`, `score.upperBound`, `coverage`, `independentCoverage` |
| `blockerCodes` | `blockerCodes` (`null` for legacy reports) |
| `inputDigests` | subject, profile, policy, evaluator, evidence bundle, accepted evidence, report digests |
| `evidenceMode`, `limitations` | verbatim from the report |
| `currency` | `checked`, `current`, `reliable`, `checkedAt`, `triggerCodes`, `digest` of the currency result, `overrides` |
| `assessedAt`, `validUntil`, `scopeId`, `profileId`, `selectedRunId` | same names |
| `limits`, `notAsserted` | fixed |

## 2. OpenTelemetry-style attributes

`exportOtelAttributes` returns a plain map; no OpenTelemetry package is imported. The names follow the lowercase dotted style of semantic conventions under a `kya.` namespace. **They are not registered with or reviewed by the OpenTelemetry project.** Values are strings, booleans, integers, doubles or string arrays; unavailable values are omitted because the data model has no null. A span or log record would carry `kya.assessment.digest` and `kya.decision` as the minimum.

| Attribute | Type | Source | Note |
| :--- | :--- | :--- | :--- |
| `kya.assessment.digest` | string | report.reportDigest | SHA-256 of the canonical report body |
| `kya.assessment.authenticated` | boolean | constant false | The report checksum is not a signature |
| `kya.assessment.valid_until` | string | report.validUntil | UTC timestamp |
| `kya.subject.digest` | string | report.subjectDigest | Manifest digest |
| `kya.policy.digest` | string | report.policyDigest | Policy digest |
| `kya.evaluator.digest` | string | report.evaluatorDigest | Evaluator digest |
| `kya.decision` | string | report.decision | qualified, insufficient-evidence, blocked, expired or revoked |
| `kya.qualified` | boolean | decision qualified and currency current | False whenever currency was not checked |
| `kya.evidence.mode` | string | report.evidenceMode | none, mixed, runtime, fixture or declaration |
| `kya.score.earned` | int | report.score.earned | Points earned |
| `kya.score.possible` | int | report.score.possible | Points possible |
| `kya.score.upper_bound` | int | report.score.upperBound | Score if every unknown check passed |
| `kya.coverage` | double | report.coverage | 0 to 1 |
| `kya.coverage.independent` | double | report.independentCoverage | 0 to 1 |
| `kya.blocker.codes` | string[] | report.blockerCodes | Omitted for legacy reports |
| `kya.currency.checked` | boolean | currency.checked | Whether a currency check ran at export |
| `kya.currency.current` | boolean | currency.current | Omitted when not checked |
| `kya.currency.reliable` | boolean | currency.reliable | Omitted when not checked |
| `kya.currency.checked_at` | string | currency.checkedAt | Omitted when not checked |
| `kya.currency.trigger.codes` | string[] | currency.triggerCodes | Empty when current |
| `kya.currency.digest` | string | digest of the currency result | Omitted when not checked |
| `kya.gate.overrides` | string[] | currency.overrides | allowNonQualified and allowNotCurrent actually used |
| `kya.authorization.granted` | boolean | constant false | An assessment is not an authorization grant |

A test keeps this table and `OTEL_ATTRIBUTES` in sync. Blocker codes and currency trigger codes are the closed vocabularies of ADR-0016 and ADR-0013.

## 3. OAuth 2.0 claims and SPIFFE binding

`exportOAuthClaims` returns `{ kya, kya_limits }`: a **claims map** with one private-use claim, `kya`, holding `assessment_digest`, `subject_digest`, `decision`, `qualified`, `evidence_mode`, `blocker_codes`, `valid_until`, `valid_until_epoch`, a `currency` block, `authorization_granted: false` and `not_asserted`. It sets no `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti` or `cnf`; those belong to the party that issues the token, who should keep `exp` at or below `valid_until_epoch` and re-run the currency check rather than trust the embedded block. No token is built, signed or introspected. The claim names are private, not registered with IANA.

How a relying party uses it: the token issuer (or an introspection endpoint) copies the `kya` claim into an access token or introspection response; a resource server compares `assessment_digest` and `subject_digest` against values it pins itself, and treats `decision` as an input to its own policy, never as a grant. The claim is only as trustworthy as the token that carries it.

`exportSpiffeBinding(assessment, spiffeId, options)` returns a `kya.spiffe-binding/v1` record: the SPIFFE ID (validated as `spiffe://trust-domain/path`; no query, fragment, userinfo, dot segments, empty or trailing-slash segments, uppercase trust domain), the same `kya` claims, and `bindingDigest`, the SHA-256 of the (SPIFFE ID, assessment digest, subject digest) triple. Carry it as workload-registration metadata or alongside an SVID. It is **not embedded in an SVID** and creates no trust relationship: `association` is `asserted-not-proven`. Nothing proves that the workload holding the SVID runs the manifest named by `subject_digest`; the relying party must establish that out of band (for example by attesting the artifact digest the manifest names).

## 4. A2A agent card and MCP metadata

`exportA2aExtension` returns one entry for the `extensions` list of an A2A agent card's capabilities (members `uri`, `description`, `required`, `params`). `required` is always `false`. `exportMcpMeta` returns `{ _meta: { "dev.kya-evidence/assessment": ... } }` for MCP server or tool metadata; that key is an unregistered placeholder in the reverse-DNS style the convention asks for. Both carry the same pointer in `params` / the meta value:

| Member | Meaning |
| :--- | :--- |
| `assessmentDigest`, `subjectDigest` | exact report and manifest digests; the binding |
| `decision`, `qualified`, `evidenceMode`, `validUntil` | as of the report |
| `currencyCheck.schema` | `kya.currency/v1`, the check the relying party should run itself |
| `currencyCheck.asOfExport` | what the exporter saw at `checkedAt`: `checked`, `current`, `triggerCodes`, `digest`, `overrides` |
| `currencyCheck.how` | instruction to re-run the check with the relying party's own inputs |
| `assessmentUrl` | optional https URL hint; never fetched; the digest is what binds |
| `authorizationGranted`, `limits` | `false`; the shared limit list |

A client that finds this must fetch the assessment itself, verify its checksum and digest against the pointer, and run the currency check; the pointer alone is advertising, not evidence.

## CLI

```sh
node scripts/kya-bridge.mjs export intoto --assessment a.json --manifest m.json --policy p.json --now 2026-10-13T12:10:00.000Z
node scripts/kya-bridge.mjs export spiffe --assessment a.json --manifest m.json --policy p.json --now ISO --spiffe-id spiffe://example.test/agent/one
node scripts/kya-bridge.mjs verify intoto --export out.json --assessment a.json --manifest m.json --policy p.json --now ISO
```

Kinds: `intoto`, `otel`, `oauth`, `spiffe`, `a2a`, `mcp`. Exit 0 ok, 1 cross-check found a problem, 2 refused or usage error. Refusals print `{error, code}` on stderr and nothing on stdout.

## What is not verified

No in-toto, OpenTelemetry, OAuth, SPIFFE, A2A or MCP implementation, validator or schema has been run against these outputs. The tests prove determinism, fail-closed behaviour, the documented shapes and the cross-check. Outside consumption is the XUSE gate of WS6 and is open. The predicate URN, attribute names, claim names and MCP key are proposals, not registrations.
