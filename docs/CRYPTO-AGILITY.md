# Cryptographic inventory and agility plan

Status: design and inventory, written by the project authors. Nothing here has had independent cryptographic review. The inventory sections were produced by searching the source on 2026-10-14 and are checked by `test/crypto-inventory.test.mjs`; every other statement is a plan or a recommendation. Related: [THREAT-MODEL.md](THREAT-MODEL.md), [ADR-0025](adr/0025-crypto-agility-and-algorithm-identifiers.md), [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).

## 1. Inventory

### 1.1 Signatures

Every KYA signature is Ed25519 through `node:crypto` (`sign(null, bytes, key)` and `verify(null, bytes, publicKey, signature)`). Proofs are `{algorithm, keyId, publicKey, signature}` with `algorithm` required to equal `Ed25519` and `signature` required to be canonical base64url of 64 bytes. `keyId` is SHA-256 of the SPKI DER public key and must match the embedded key. Only Ed25519 keys are admissible (`publicKeyObject` in `src/identity/domain/services/validation.mjs`).

KYA-native records sign `DOMAIN + canonical(payload)`, where `DOMAIN` is a fixed ASCII label ending in a line feed (written `\n` below):

| Domain prefix | Signs | Defined in |
| :--- | :--- | :--- |
| `kya.evidence/v1\n` | Evidence receipt payload (`kya.evidence/v1`) | `src/evidence/domain/services/signatures.mjs` |
| `kya.incident/v1\n` | Incident report, resolution, appeal payload (`kya.incident/v1`) | `src/evidence/domain/services/incidents.mjs` |
| `kya.assessor-disclosure/v1\n` | Assessor disclosure, conflict declaration, withdrawal payload (`kya.assessor-disclosure/v1`) | `src/assessor/disclosure.mjs` |
| `kya.campaign-plan/v1\n` | Campaign plan payload (`kya.campaign-plan/v1`) | `src/campaign/domain/records.mjs` (`PLAN_DOMAIN`) |
| `kya.campaign-ledger/v1\n` | Campaign ledger entry payload (`kya.campaign-ledger-entry/v1`; the domain name differs from the schema name) | `src/campaign/domain/records.mjs` (`LEDGER_DOMAIN`) |
| `kya.score.seed/v1\n` | Seed derivation for the score card bootstrap generator; not a signature and carries no secret (`kya.score-card/v1` cards are unsigned) | `src/kya-score/stats.mjs` |
| `kya.capture/v1\n` | Reference capture record payload (simulated cell, ADR-0032) | `src/capture-cell/bundle.mjs` (`CAPTURE_DOMAIN`) |
| `kya.conformance-report/v1\n` | Conformance report payload (`kya.conformance-report/v1`) | `src/conformance-report/report.mjs` (`REPORT_DOMAIN`) |

A second family uses a symmetric keyed hash, not a signature:

| Domain prefix | Use | Defined in |
| :--- | :--- | :--- |
| `kya.vc.status-index/v1\n` | Input to HMAC-SHA-256 that assigns a status-list index (`purpose`, `reportDigest`, `counter`) | `src/vc-bridge/status.mjs` |

Signing sites with no KYA domain prefix (documented exemption, checked by the test): `src/vc-bridge/jws.mjs`. It signs the JWS signing input `base64url(header) "." base64url(payload)` as required by JWS (RFC 7515) with `alg: EdDSA`. Separation from the KYA prefixes holds structurally: a JWS signing input starts with the base64url of a JSON object (`eyJ` for a header beginning `{"`), never with the characters `kya.`, so no byte string is both a valid KYA signing input and a valid JWS signing input for this header shape. The `typ: vc+jwt` and `cty: vc` header members add separation inside JOSE.

The schema name inside each payload (for example `kya.evidence/v1`) is a second, independent separator, because verifiers check it with exact-key validators before use.

### 1.2 Hashes and keyed hashes

| Use | Algorithm | Notes | Where |
| :--- | :--- | :--- | :--- |
| Object digest `digest(value)` = SHA-256 of canonical JSON, hex | SHA-256 (`sha256`) | Untagged: no domain label. Subject, profile, policy, scope, report, evaluator, bundle and dossier digests | `src/shared/canonical.mjs` |
| Raw byte digest `hashBytes` | SHA-256 | Artefact digests, source inventories, suite and evaluator identity, release inventory | `src/shared/canonical.mjs`, `scripts/pack.mjs`, `src/conformance/domain/scenarios.mjs`, `src/research/application/universe.mjs`, `src/suites/identity.mjs` |
| Key identifier `keyId` | SHA-256 of SPKI DER | Used as trust-anchor and revocation identifier | `src/identity/domain/services/validation.mjs` |
| Native adapter output commitment | SHA-256 over stdout and stderr | Streaming hash of raw output | `src/conformance/infrastructure/native-transport.mjs` |
| Holdout Merkle tree | SHA-256 with one-byte node tags (`0x00` leaf, `0x01` node, `0x02` root) and labels `kya.holdout.case/v1`, `kya.holdout.leaf/v1`, `kya.holdout.root/v1`, `kya.holdout.salt-commitment/v1` | Labels are fixed-length prefixes of each hash input | `src/holdout/index.mjs` |
| Holdout per-case salt | HMAC-SHA-256 keyed by the master salt, label `kya.holdout.case-salt/v1` | Master salt from `randomBytes(32)` | `src/holdout/index.mjs` |
| VC status index | HMAC-SHA-256 keyed by an issuer secret (see 1.1) | Secret must be at least 32 bytes or characters | `src/vc-bridge/status.mjs` |
| Python second implementation | SHA-256 (`hashlib`) and Ed25519 verification via an installed `cryptography` package | Declared subset only | `interop/python/kya_portability.py` |

Other cryptographic primitives: `node:crypto` `generateKeyPairSync('ed25519')` for key generation in `bin/kya.mjs` and the benchmark runner; `randomBytes(32)` for holdout salts; `timingSafeEqual` for digest comparison in the holdout module; did:key encoding (multicodec `0xed01`, base58btc) in `src/vc-bridge/encoding.mjs`. No other hash, cipher, KDF or RNG is used. UNVERIFIED: whether Node's Ed25519 implementation (A1 in the threat model) matches every RFC 8032 edge case; the VC bridge adds its own small-order and canonical-point checks (KYA-VCB-012) for raw keys.

### 1.3 Domain-separation audit (observations)

1. Every Ed25519 signing site except JWS prefixes its input with a distinct `/v1` label, and the five labels are pairwise different. Verified by reading each site and by the inventory test.
2. The evidence, incident, plan, entry and report verifiers each pass only their own prefix, so a signature from one cannot verify as another. Cross-type confusion would additionally need the payload to satisfy the other type's exact-key validator.
3. One key may sign several record types: nothing forbids it except the capture-issuer rule (KYA-CMP-009). Guidance in 4: use one key per role.
4. `digest(value)` is untagged. A raw artefact whose bytes equal the canonical JSON of a KYA object would share that object's digest. This is low risk because digests are compared in typed fields, but a v2 digest should carry a label (see 2.3).
5. The campaign ledger domain is `kya.campaign-ledger/v1` while entry payloads say `kya.campaign-ledger-entry/v1`. This is consistent but easy to misread; it is recorded here so a future change does not assume they match.

## 2. Algorithm-agility design

Goal: introduce a new signature algorithm or hash without invalidating old evidence and without letting an attacker downgrade a verifier. Not implemented; the current code accepts exactly Ed25519 and SHA-256 and fails closed on anything else.

### 2.1 What the code already gives

- `proof.algorithm` exists and is compared with `===`; an unknown algorithm is refused rather than negotiated.
- Every record carries a versioned schema id (`kya.*/v1`) and strict `exactKeys` validation, so an unknown field is rejected. This is good for security and means that adding a field or algorithm is a new schema version, not an optional extension. It is the reason the plan below uses `v2` schemas.
- Domain prefixes are versioned (`/v1`), so a changed signing input can take `/v2` without colliding with `/v1`.
- Policies pin which keys count and what role they have, so the relying party, not the signer, decides what is trusted.

### 2.2 Adding a signature algorithm

1. Register an identifier. A new identifier in a spec table (for example `ML-DSA-65` or `Ed448`, names illustrative) maps to key encoding, signature encoding and verification rule. An unlisted identifier is refused.
2. Bind the algorithm into the signing input. For v2 records sign `kya.<type>/v2\n<algorithm>\n` followed by canonical payload, so a signature made under one algorithm cannot be re-presented under another and a v2 signature can never verify as a v1 signature.
3. New envelope shape (`kya.<type>/v2`): `{payload, proofs: [proof, ...]}` where each proof names its algorithm. Strict validation, no unknown members.
4. `keyId` stays SHA-256 of the SPKI DER. The DER carries the algorithm OID, so keys of different algorithms cannot share an identifier.
5. Policy (`kya.policy/v2` or an additive policy field under a new schema version) lists for each trusted key its algorithm, and states `acceptedAlgorithms`, `requiredAlgorithms` and the minimum number of valid proofs per record. Verification succeeds only if every algorithm the policy requires has a valid proof from a trusted key.
6. Keep every v1 verifier in the tree, unchanged and tested against the existing golden vectors, as the reader for archived evidence.
7. Add golden vectors, update `interop/python/kya_portability.py` or declare the algorithm out of its subset, add a requirement and an ADR before the first v2 signature is issued.

### 2.3 Adding a hash

Current digest fields are bare 64-character lowercase hex and are validated with that exact shape in many places, so a different hash length cannot be dropped in. For v2 schemas, encode digests with a label (for example `sha256:<hex>`) and compute them over `LABEL\n + canonical bytes`, which also repairs the untagged-digest observation in 1.3. `keyId` and Merkle trees would need the same treatment. Old v1 digests continue to mean SHA-256 over canonical bytes forever.

### 2.4 Dual-signing transition

| Phase | Issuers | Verifiers and policy | Result |
| :--- | :--- | :--- | :--- |
| 0 (today) | Ed25519 v1 | Ed25519 v1 | Current behaviour |
| 1 | Unchanged | Ship v2 reader; policy `acceptedAlgorithms` includes the new one; nothing required | New code can read new evidence; no behaviour change |
| 2 | Dual-sign: v1 Ed25519 and v2 with both proofs | Same | Evidence readable by old and new verifiers |
| 3 | Dual-sign | Policy requires both algorithms for new evidence | A downgrade by stripping the new proof fails |
| 4 | New algorithm only | Policy requires the new algorithm; old Ed25519-only evidence is read as archival and accepted only with an anchor or countersignature made before the old algorithm was considered broken | Old algorithm retired for new evidence |

Retiring an algorithm leaves old evidence forgeable by anyone who can break it, so the transition is only safe for old evidence if it was timestamped or anchored first (ADR-0020, Proposed and not implemented) or countersigned with the new algorithm during phase 2 or 3. This is the main reason anchoring matters for agility.

### 2.5 Downgrade resistance

A verifier must never infer acceptable algorithms from the record. The required set comes from the policy. A v1 envelope is valid only if the policy still accepts v1. A v2 record whose proofs list contains only a weaker algorithm than the policy requires is refused. Algorithm identifiers are exact strings, compared exactly, with no wildcard and no fallback.

## 3. RFC 8785 decision

KYA canonical JSON (`canonical()` in `src/shared/canonical.mjs`) is not RFC 8785 (JCS) and does not claim to be. ADR-0022 and `scripts/golden-vectors.mjs` already say so.

Method: on 2026-10-14 the author ran `canonical()` and `parseJson()` on chosen values and compared with the text of RFC 8785 fetched from https://www.rfc-editor.org/rfc/rfc8785.txt on 2026-10-14 (sections 3.2.2.2, 3.2.2.3, 3.2.3 and Appendix B). No third-party JCS implementation was run, so equality is checked against the RFC text and samples only. `test/crypto-inventory.test.mjs` re-runs these checks.

| Behaviour | RFC 8785 | KYA canonical | Same? |
| :--- | :--- | :--- | :--- |
| Whitespace | None | None | Yes |
| Member sort order | UTF-16 code units, unsigned, recursive (3.2.3) | Default `Array.sort` of member names, which is UTF-16 code unit order | Yes. Tested: `{"😀":1,"￿":2,"a":3}` sorts to `a`, the astral key, then U+FFFF |
| Number formatting for numbers KYA accepts | ECMAScript Number-to-string (3.2.2.3) | `JSON.stringify` of the number | Yes. Tested on Appendix B samples that KYA accepts: `5e-324`, `-5e-324`, `9.999999999999997e-7`, `0.000001`, `333333333.3333332`, `333333333.3333333`, `-0.0000033333333333333333` and minus zero as `0` |
| String escaping | `\b \t \n \f \r`, other controls as lowercase `\u00xx`, no other escapes (3.2.2.2) | `JSON.stringify` | Yes for well-formed strings. Tested: U+0007 gives `\u0007`; U+007F and U+2028 are written raw |
| Unicode normalisation | Not applied | Not applied | Yes. Tested: `e` plus combining acute and the precomposed `é` stay distinct keys |
| Duplicate member names | Forbidden (I-JSON) | `parseJson` rejects them | Yes (parser only) |
| Integers outside plus or minus (2^53 - 1) and any integral float at or above 2^53 | Allowed, serialised by the ECMAScript rule, for example `1e+21`, `9007199254740992`, `1.7976931348623157e+308` | Rejected with `Unsafe JSON number` | **No** |
| Lone surrogates in strings | MUST fail (3.2.2.2 note) | Accepted and written as an escape, for example `"\ud800"` | **No** |
| `NaN` and `Infinity` | MUST fail | Rejected | Yes |
| Member names `__proto__`, `prototype`, `constructor` | Allowed | Rejected | **No** (KYA only) |
| Accessors, sparse arrays, non-plain objects, symbol keys, `undefined`, `bigint` | Not applicable (text input) | Rejected | KYA-only input hardening |
| Resource limits | None | 1 MiB, depth 32, 100,000 nodes, array length 100,000 | **No** (KYA only) |

Conclusion from the test: for every input both accept, the output bytes are the same, because both are defined by ECMAScript number and string serialisation and UTF-16 key order. The differences are in which inputs are accepted. KYA accepts a strict subset of what JCS accepts for numbers and members, plus lone surrogates that JCS refuses.

ADR-0022 describes the difference as "number formatting and string ordering rules". The tests above do not support that wording: formatting and ordering matched on every tested value. The accurate statement is acceptance-set differences (unsafe integers, lone surrogates, reserved member names, resource limits). ADR-0022 is outside this change and is not edited here; the correction is a follow-up (the working note that recorded it was not retained).

Decision: keep the KYA canonical form for v1 records, because existing signatures and golden vectors depend on its exact bytes, and make it explicit that it is a strict, hardened subset of JCS output.

Migration path to claimable JCS conformance (not implemented):

1. Close the two gaps that would make a v2 canonicaliser a JCS implementation with extra rules: reject lone surrogates, and either keep the safe-integer rule as an additional application-layer constraint or serialise large numbers by the ES rule. Keeping the stricter rule is permitted because JCS output is still produced for everything accepted.
2. Publish the RFC Appendix B samples (including those KYA rejects today) plus the RFC 3.2.3 sorting example as vectors; run an independent JCS implementation against them (not done here, UNVERIFIED).
3. Introduce the change under `kya.<type>/v2` with a new domain prefix (2.2). Old v1 evidence is verified with the v1 canonicaliser and is never re-canonicalised.
4. Only then consider interoperable proof suites that require JCS (for example W3C Data Integrity `eddsa-jcs-2022`, which ADR-0022 rejected for now); that decision needs its own ADR and an external consumer test.

## 4. Key management guidance

This is guidance. The repository enforces little of it (see the threat model A3). `kya keygen DIRECTORY` creates the directory with mode 0700; UNVERIFIED here: the file modes and storage of generated private keys, which the author did not inspect.

- **Roles and separation.** Use a separate key per role: evidence signer, incident reporter, independent assessor, capture issuer, VC issuer. The code forbids only capture-issuer reuse as evaluator or independent assessor (KYA-CMP-009). Never reuse a production key with the public toy keys in `evidence/golden-vectors.json`.
- **Storage.** Prefer a hardware token or a cloud KMS that supports Ed25519 for production keys; keep the private PEM out of the repository, CI logs and this package (the release tool already refuses private-key markers in packaged text). UNVERIFIED: which KMS products support Ed25519 in a given region.
- **Rotation.** Add the new key to `trustedKeys` with the same role, have the issuer sign with it, keep the old key until all evidence it signed has passed `maxEvidenceAgeSeconds` (at most 31,536,000 seconds, one year, enforced by `validatePolicy`) or is superseded, then remove it. Because policy-pinned `keyId` values identify keys, rotation is a policy change, so publish a new policy digest and update every pin (`--expect-policy-digest`).
- **Revocation.** Add the `keyId` to `revokedKeyIds`. The list has no effective date, so revocation rejects all evidence from that key, including genuine older evidence. Plan to re-issue from a new key when a key is revoked for a non-compromise reason. There is no live revocation service: a relying party that holds an old snapshot still accepts the key (A11).
- **Compromise response.** (1) Revoke the key id in a new policy snapshot and distribute it to every relying party and CI pin. (2) Treat all evidence, incidents, ledgers or credentials signed by the key in an unknown window as suspect; without an anchor the signing time cannot be established. (3) Re-run affected assessments from trusted inputs with a new key. (4) For a VC issuer key, publish revocation through status lists and stop issuing under the did:key; did:key cannot rotate (ADR-0022), so the issuer identity changes. (5) Record the event as an incident and add a regression test or ADR note per [VULNERABILITY-DISCLOSURE.md](VULNERABILITY-DISCLOSURE.md).
- **Trust-anchor distribution.** Trust anchors are carried by the policy file and distributed out of band. Take policy and evaluator digests from a protected source such as the base branch, a signed tag or a separate channel, never from the code under test (KYA-ACT-009, KYA-ACT-012). There is no PKI, transparency log or automatic update; a signed tag over the policy commit is recommended in [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).

## 5. Post-quantum migration note

Verified facts:

- Ed25519 and SHA-256 are the only primitives KYA uses for signatures and digests (section 1).
- NIST published FIPS 204, the Module-Lattice-Based Digital Signature Standard (ML-DSA), with a publication date of August 13, 2024 (https://csrc.nist.gov/pubs/fips/204/final, fetched 2026-10-14). That page also carries a planning note dated 07/31/2026 about errata; its content was not assessed.
- On the author's machine, Node v22.19.0 `generateKeyPairSync` rejected `ml-dsa-44`, `ml-dsa-65` and `slh-dsa-sha2-128s` (error `ERR_INVALID_ARG_VALUE`) and accepted `ed448`. This says nothing about other Node 22 or 24 builds, which were not tested.

Consequences for the design (reasoning, not a prediction): the project depends on `node:crypto` and has zero npm dependencies, so a post-quantum signature in the reference implementation would need either a Node release that exposes it or a vendored, reviewed implementation, which breaks the zero-dependency rule and would need its own ADR. Signature sizes for lattice schemes are larger than Ed25519's 64 bytes, and the current signature validator requires exactly 86 base64url characters (64 bytes), so a v2 envelope with a different signature length is required, which the plan in section 2 provides.

UNVERIFIED, not asserted: when, or whether, a cryptographically relevant quantum computer will exist; the recommended hybrid or dual-signature profile for any standards body; JOSE and COSE identifiers for ML-DSA; ML-DSA sizes and performance; whether FIPS 205 (SLH-DSA) suits KYA records.

What to do now: (1) keep evidence short-lived, since `maxEvidenceAgeSeconds` is capped at one year and signatures only matter until relied on; (2) implement ADR-0020 anchoring so existing evidence can later be proven to pre-date a break; (3) keep `proofs` as a list in v2 so dual-signing can ship before any algorithm is retired; (4) track the Node release notes for native support before choosing a library.
