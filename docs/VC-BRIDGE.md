# W3C Verifiable Credentials 2.0 export bridge

Implements [ADR-0022](adr/0022-vc-export-bridge.md). Code: `src/vc-bridge/`. CLI: `scripts/kya-vc.mjs`. Zero dependencies, no network access, every time-dependent command takes an explicit `--now`.

## What the credential says

A `KyaAssessmentCredential` states that an issuer holding one Ed25519 key signed a KYA assessment result for an agent configuration identified by its **subject digest**: the decision (`qualified`, `insufficient-evidence`, `blocked`, `expired`, `revoked`), the 0..1000 score and its upper bound, evidence coverage and independent coverage, the exact profile, policy and evaluator digests, the evidence bundle and accepted-evidence digests, the blocker codes, the limitations list, and the evidence mode (`none`, `mixed`, `runtime`, `fixture`, `declaration`) exactly as the report recorded it. The validity window never exceeds the assessment's own.

## What it does NOT say

- **No human identity.** The subject is `urn:kya:subject:sha256:<digest>` of a configuration. There is no principal, name or person field, and the credential carries a `notAsserted` list: human identity, authorization grant, truthful execution.
- **No authorization.** A `qualified` decision is a local policy result, not a grant, and not a credit score for a person.
- **Signature is not truth.** A valid signature proves possession of the issuer key and integrity of the bytes. `verifyAssessmentCredential` always returns `authenticated: false`.
- **Issuer trust is policy-relative.** With no expected keys and no policy, `issuerTrust` is `unchecked`. `expected` means the issuer matched keys the caller named; `anchored` means it is a non-revoked trust anchor of a supplied KYA policy. Neither means the issuer is honest.
- **Fixture stays fixture, up to what is checked.** There is no export option to set the evidence mode, and export refuses a report whose mode and fixture limitation disagree. Without the source report the verifier checks exactly and only: the JWS signature and header, issuer trust (relative to the keys or policy you supply), the validity window, status (when lists are supplied), and that `evidenceMode` and the fixture limitation agree, plus the internal digest and id consistency of the subject and evidence block. Nothing else is bound to the original assessment: a holder of the issuer key can change `evidenceMode` to `runtime`, delete the fixture limitation, empty `notAsserted`, add subject fields, change the credential id, or append evidence or context entries, re-sign, and the result still verifies as valid (with `authenticated: false`). To bind the credential to the assessment, pass the original `kya.assessment/v1` report (`report` option, CLI `--report FILE`). The verifier then rebuilds the expected credential from the report with the exporter's own construction (issuer, `validFrom` and `validUntil` taken from the credential being checked, and bounded by the report's `assessedAt` and `validUntil`) and compares the whole credential, in canonical form, to it. Any difference is `REPORT_MISMATCH`, and the message names the top-level member that differed (for a subject difference, also the subject fields). A report that fails its own digest check is `REPORT_INVALID`. The result carries `reportChecked`. One thing the report cannot bind: `credentialStatus` entries are issuer-supplied export options, not report content. They are rebuilt through the same constructor so their shape must be exact, but their URLs and indices are not tied to the assessment.
- **Not Data Integrity, not JCS.** KYA canonical JSON is not RFC 8785. It is used only so the JWS bytes are deterministic.

## Format

JWS compact serialization, header `{"alg":"EdDSA","cty":"vc","kid":"<did:key>#<fragment>","typ":"vc+jwt"}`, payload is the credential itself (no `vc` claim). The verifier accepts only that algorithm, only those four header members (no `jwk`, `jku`, `x5u`, `x5c`, `crit`), and checks `alg` before touching a key.

## Field mapping

| Credential field | Source in `kya.assessment/v1` |
| :--- | :--- |
| `id` | `urn:kya:assessment:sha256:` + `reportDigest` |
| `issuer` | did:key of the signing key (multicodec 0xed01, base58btc) |
| `validFrom`, `validUntil` | option or `assessedAt`; capped by report `validUntil` |
| `credentialSubject.id`, `subjectDigest` | `subjectDigest` |
| `scopeDigest`, `scopeId`, `profileId` | same names |
| `profileDigest`, `policyDigest`, `evaluatorDigest` | same names |
| `decision`, `score`, `coverage`, `independentCoverage` | same names, verbatim |
| `evidenceMode` | `evidenceMode`, verbatim |
| `blockerCodes` | `blockerCodes` (`null` for legacy reports without it) |
| `limitations` | `limitations`, verbatim |
| `reportDigest`, `assessedAt`, `selectedRunId` | same names |
| `evidence[0]` (type `KyaInputDigests`) | `evidenceBundleDigest`, `acceptedEvidenceDigests`, plus subject, profile, policy, evaluator and report digests |
| `credentialStatus[]` | optional `BitstringStatusListEntry` for `revocation` and `suspension` |
| not exported | `principalId`, `agentId`, `agentName`, check-level detail, rejected evidence, dimensions |

The inline context `{"@vocab":"urn:kya:vocab:v1:"}` only gives KYA terms an IRI. It cannot be dereferenced and no JSON-LD processor was run.

## Revocation: Bitstring Status List

`buildStatusListCredential` writes a `BitstringStatusListCredential` (`credentialSubject.type: BitstringStatusList`, `statusPurpose`, `encodedList`), secured the same way. Lists have at least 131,072 entries (16 KiB), index 0 is the leftmost bit, encoding is GZIP then multibase base64url with prefix `u`. `checkStatus` verifies the list, matches the purpose, enforces the minimum length, range-checks the index and decompresses with a 2 MiB ceiling (the specification sets none). **Freshness.** A list must carry `validUntil` (the builder and CLI require it) and may carry `ttl` in milliseconds from `validFrom`. `checkStatus` refuses a list with no `validUntil` (`STATUS_LIST_NO_EXPIRY`) and an expired list or one past its `ttl` (`STATUS_LIST_EXPIRED`, reported distinctly, and the status then counts as not checked). Otherwise a stale list that predates a revocation would stay acceptable forever. The `ttl` use here (a hard staleness limit) is this project's reading of the spec's refetch hint. `revokedLedgerEntries` and the CLI validate the policy with `validatePolicy`, so an empty or junk policy is an error rather than an empty revocation set.

**Keys.** Every raw Ed25519 key admitted from a did:key or used to verify a JWS is decoded and checked with BigInt arithmetic (RFC 8032 point decoding): non-canonical `y`, points not on the curve and small-order points (8P is the identity) are refused. This closes the identity-key forgery in which an all-zero-order key accepts a signature over any payload. The same check (`src/shared/ed25519-point.mjs`) now also runs in the core verifiers through `publicKeyObject` and `validatePublicPem`, so evidence, incident, report, campaign and assessor envelopes and trust anchors refuse these keys too; the core additionally requires the PEM to equal the canonical SPKI export of the key, so one key has exactly one accepted spelling. Mixed-order points that are not small-order are not separately rejected.

`statusSize` other than 1 and purposes other than `revocation` and `suspension` are refused.

**Index assignment.** `index = HMAC-SHA256(secret, "kya.vc.status-index/v1\n" + purpose + "\n" + reportDigest + "\n" + counter) mod size`, with the counter stepped up past indices the issuer ledger already holds. Earlier entries never move. The key is the report digest of the credential, not the subject digest, and the secret (at least 32 bytes) stays with the issuer, so a reader of the list cannot link a set bit to a subject. The issuer ledger holds report digest, subject digest, selected evidence IDs and indices.

**KYA revocation to bits.** A credential's revocation bit is set when its subject digest is in the policy `revokedSubjectDigests` or any evidence ID it selected is in `revokedEvidenceIds` (`revokedLedgerEntries`). Suspension has no policy source, so the caller names subject digests. Republishing a list with the bit cleared lifts a suspension; revocation is not meant to be reversed. Freshness is whatever list the verifier supplies.

## CLI

```
kya-vc did-key --key PRIVATE_PEM | --public PUBLIC_PEM
kya-vc export --assessment FILE --key PRIVATE_PEM [--valid-from ISO] [--valid-until ISO] [--out FILE]
              [--revocation-list URL --suspension-list URL --status-secret-file FILE --ledger FILE]
kya-vc verify --jwt FILE --now ISO [--trust-did DID]... [--policy FILE] [--status-list URL=FILE]... [--require-status] [--allow-untrusted-issuer] [--report FILE]
kya-vc status-list --purpose revocation|suspension --url URL --ledger FILE --policy FILE --key PRIVATE_PEM --now ISO --valid-until ISO [--ttl-ms N] [--suspended-subject DIGEST]... [--size N] [--out FILE]
```

`verify` exits 0 when valid, 1 when not, 2 on a usage error. `verify` requires a trust source: pass `--trust-did` or `--policy`, or pass `--allow-untrusted-issuer` to accept any issuer explicitly (the result then reports `issuerTrust: "unchecked"`). Without one of them it exits 2 with a usage error, so a pipeline cannot read exit 0 as an issuer check it never ran.

## Example generated by this lane

Run on 2026-10-14 with the synthetic test fixture (random throwaway key, `evidenceMode: fixture`; evidence digests differ on every run because the fixture signer key is random). `kya-vc export ... --valid-from 2026-10-13T12:00:00.000Z` then `kya-vc verify --allow-untrusted-issuer --now 2026-10-13T12:30:00.000Z` with two empty status lists returned `valid: true`, `authenticated: false`, `issuerTrust: "unchecked"`. With a revocation list carrying the credential bit it returned `REVOKED`. At `--now 2026-10-13T14:00:00.000Z` it returned `EXPIRED`. Header and payload (accepted evidence digests abbreviated):

```json
{ "alg": "EdDSA", "cty": "vc", "typ": "vc+jwt",
  "kid": "did:key:z6MkfLfgUWY9kScssCNAHMw9XfLUYEncEWFXEJzT6USNsRRg#z6MkfLfgUWY9kScssCNAHMw9XfLUYEncEWFXEJzT6USNsRRg" }
```

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", { "@vocab": "urn:kya:vocab:v1:" }],
  "id": "urn:kya:assessment:sha256:59d35b8c65be664972839bb2d45d5cee8e83e99f6085bb4d3fa8a92c6eb5f538",
  "type": ["VerifiableCredential", "KyaAssessmentCredential"],
  "issuer": "did:key:z6MkfLfgUWY9kScssCNAHMw9XfLUYEncEWFXEJzT6USNsRRg",
  "validFrom": "2026-10-13T12:00:00.000Z",
  "validUntil": "2026-10-13T13:00:00.000Z",
  "credentialSubject": {
    "id": "urn:kya:subject:sha256:8840c18578809b058e554e7326b981c06a1b51dc24200ab7e46e91a8429b2605",
    "type": "KyaAssessment",
    "decision": "qualified", "score": { "earned": 1000, "possible": 1000, "upperBound": 1000 },
    "coverage": 1, "independentCoverage": 0, "evidenceMode": "fixture", "blockerCodes": [],
    "limitations": ["Local policy result; not an authorization grant",
      "Signatures attest bytes and key possession, not truthful execution",
      "No universal predictive validation; public suites can be gamed",
      "Includes synthetic fixture evidence; not a real product benchmark"],
    "notAsserted": ["human identity", "authorization grant", "truthful execution"],
    "...": "subjectDigest, scopeDigest, profileDigest, policyDigest, evaluatorDigest, reportDigest, assessedAt, selectedRunId"
  },
  "evidence": [{ "type": "KyaInputDigests", "evidenceBundleDigest": "c27a379bd877...", "acceptedEvidenceDigests": ["5a61219de450...", "..."], "reportDigest": "59d35b8c65be..." }],
  "credentialStatus": [
    { "type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "82187", "statusListCredential": "https://example.test/status/revocation" },
    { "type": "BitstringStatusListEntry", "statusPurpose": "suspension", "statusListIndex": "2540", "statusListCredential": "https://example.test/status/suspension" }
  ]
}
```

## Relation to Open-KYA and DIF KYA-OS

The research note records that Vouched donated its agentic identity framework to DIF, governed by a KYA-OS task force in the Trusted AI Agents Working Group (DIF blog, March 2026, from `docs/research/2026-10-14-kyc-to-kya-controls.md`). That DIF page and the Open-KYA repository were **not fetched by this lane**; no field-level alignment with either is claimed. This bridge is an export of KYA assessment results into a generic W3C format. It does not implement, and makes no claim of compatibility with, any KYA-OS data model, which centres on agent identity; this credential deliberately makes no identity claim.

## Specifications consulted

Fetched 2026-10-14 with a page-to-markdown tool (summaries, not raw text):

- Bitstring Status List v1.0, https://www.w3.org/TR/vc-bitstring-status-list/ : reported as W3C Recommendation of 15 May 2025. Entry fields, purposes, 16 KB and 131,072 minimum, bit order, GZIP and base64url, verification steps, and absence of a decompression limit were read.
- VC-JOSE-COSE, https://www.w3.org/TR/vc-jose-cose/ : `typ` vc+jwt, `cty` vc, payload is the bare credential, `vc` and `vp` claims not allowed, `nbf` not recommended. The tool reported the page date as 13 October 2026, which does not match the 15 May 2025 date the task cited; treated as unreconciled. The page was truncated: the `kid` and algorithm sections were not read, so the algorithm and `kid` rules here are this project's stricter policy, not a quoted requirement.
- VC Data Model v2.0, https://www.w3.org/TR/vc-data-model-2.0/ : reported Recommendation of 15 May 2025; context first item, `type`, evidence and `credentialStatus` terms. Truncated at 100,000 of about 552,000 characters; the issuer, validFrom, status and extension sections were not read.
- did:key, https://w3c-ccg.github.io/did-key-spec/ : two Ed25519 example strings used as vectors, base58btc `z` multibase form. The page lists multicodec 0xed and gives no raw key bytes. The 0xed01 two-byte prefix (varint of 0xed) was confirmed from a W3C Data Integrity EdDSA search result, not from a fetched page. The did-method-key repository test vectors were not found (404 on guessed URLs).

Not fetched, cited from the project's own prior notes or not at all: Open-KYA, DIF KYA-OS, RFC 7515, RFC 8032, RFC 8785, W3C Data Integrity.

## Not verified

No external VC verifier, JSON-LD processor, status list library or other implementation was run against these outputs. The did:key vectors prove decode and canonical re-encode, not agreement with raw key bytes published by the spec. No network or clock access was used.
