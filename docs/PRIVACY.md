# Privacy: data flows, redaction, retention and selective disclosure

Status: Draft, written by the project authors. It is design guidance and tooling documentation. It has had no review by a qualified privacy professional, it is not legal advice and it does not establish compliance with any data protection regime. Related: [THREAT-MODEL.md](THREAT-MODEL.md), [DPIA-TEMPLATE.md](DPIA-TEMPLATE.md), [ADR-0029](adr/0029-privacy-tooling.md), [SPECIFICATION.md](SPECIFICATION.md).

## 1. Principle

KYA artifacts are meant to be about an agent configuration, not about a person. Personal data enters in four ways: a free-text label a human typed into a manifest, an agent trace that quotes a user, a pseudonymous reference that is re-identifiable by the party that issued it, and operational metadata such as addresses and file paths. The rules below keep the portable artifacts coded or digest-only and keep raw material private.

A signature or a hash is not a privacy control. Publishing a digest of a low-entropy value (a name, an email address, a phone number) lets anyone confirm a guess, so such values must be removed or committed with a secret salt before they are hashed (section 4).

## 2. Data flow: what each artifact may contain

| Artifact | Normal content | May contain personal data? | Rule |
| :--- | :--- | :--- | :--- |
| Manifest (`kya.manifest/v1`) | Agent ID, name, version, harness, model name, artifact and config digests, tool IDs, scope purpose and permissions, validity window, principal ID, optional `accountableParty` | Yes, by misuse: `agent.name` and `scope.purpose` are free text (up to 512 characters) and `principal.id` can be set to a person identifier | Use coded identifiers. `accountableParty.ref` is a pseudonymous reference; the specification admits no personal-data fields. Do not put names, emails or ticket text in labels. |
| Evidence (`kya.evidence/v1`) | IDs, digests, outcome code, timestamps, signature proof | No, when produced by the reference tools | Coded and digest-only. Case content stays in the private campaign directory. |
| Assessment report | Decision, score triple, coverage, blocker codes, per-check status, rejection reasons | Rarely: reason strings echo IDs | Contains no raw responses. IDs inherit the rule above. |
| Incident record (`kya.incident/v1`) | Record ID, subject digest, kind, severity, reference ID, time, `detailsDigest` | No by design: digest-only, no narrative | The narrative lives elsewhere under its own access control; only its digest travels. |
| Dossier | Manifest labels, system identifiers, case IDs, the full assessment | Inherits manifest and case labels | Raw responses are omitted. Inspect and authorize a sanitized public projection before publication. |
| VC export | Digest-only subject, keyed status index | No by design | See the VC bridge requirements. |
| Raw evidence bundles, traces, private campaign files | Model inputs and outputs, tool traces, logs | Yes, likely | Private directory outside the repository, owner-only permissions, never published, retention rule in section 5. |
| Capture-cell logs and environment metadata | Host names, paths, addresses, usernames | Yes | Strip before any artifact is built (section 3). |

Where each flow goes: raw material stays inside the evaluator or deployer boundary; signed artifacts cross to the relying party; dossiers are the publication surface and need a human sanitization decision.

## 3. Redaction before hashing

Order matters. Redact first, canonicalize second, hash and sign third. After a hash or signature is published, removing the personal data from the source does not remove it from the digest or from copies.

1. Decide for each free-text field whether it is needed. Prefer a coded value from a fixed vocabulary over text.
2. Remove or replace direct identifiers: email addresses, phone numbers, account numbers, national identifiers, IP addresses, home-directory paths and usernames. Replace with a stable pseudonym only when the pseudonym map stays private and is rotated per audience.
3. Run `node scripts/privacy-scan.mjs <paths>` on the artifacts before signing and again before publishing. A non-zero exit blocks the step.
4. Do not hash a low-entropy personal value to hide it. Use a salted commitment (section 4) or omit it.
5. Record which redactions were applied in the private campaign notes, not in the signed artifact.

### The scanner

`scripts/privacy-scan.mjs` is deterministic, has no dependencies and never prints a matched value. It emits a stable JSON report (`kya.privacy-scan/v1`) with the file, JSON path, rule ID, match length and a shape mask in which letters and digits are replaced by class markers. Exit code 0 means clean, 1 means at least one finding, 2 means a usage or read error (including unreadable, binary or oversized files, which are never silently skipped). Directory scans cover `.json`, `.jsonl` and `.ndjson`; an explicit file of any type is parsed as JSON or scanned line by line.

Content rules: email address, IBAN (mod-97 check), payment card number (13 to 19 digits, first digit 2 to 6, Luhn check), national identifier shapes (US SSN, UK NINO, Spanish DNI/NIE with check letter, French INSEE with key, Indian Aadhaar with Verhoeff check), IPv4, IPv6, home-directory paths (`/Users/`, `/home/`, `C:\Users\`), PEM private key blocks, and phone-shaped numbers. A span matched by an earlier rule is not reported again by a later one. Object keys are scanned too, and a key that looks like personal data is shown as `[key:N]` in the path so the path cannot leak it.

Structural rules (default `--rules all`): a field whose name ends in `Digest` must be 64 lowercase hex characters; fields named `id`, `ref`, `refId`, `scopeId`, `runId`, `checkId` or ending in `Id` must be a coded identifier; and in records whose schema is `kya.incident`, `kya.evidence` or `kya.receipt`, narrative-style fields (`note`, `comment`, `details`, `message`, `text` and similar) must not carry text. `--rules pii` runs the content rules only. The vector files under `evidence/` deliberately contain malformed records as refusal cases, so they are scanned with `--rules pii`.

### False positives and false negatives (statement)

False positives are expected and acceptable: four-part version strings parse as IPv4; digit runs that start with 2 to 6 and pass the Luhn check are reported as card numbers; numbers shaped like phone numbers; hexadecimal-looking words that parse as IPv6; email-shaped test fixtures (reserved example domains are not exempt).

False negatives are expected and are the more serious risk: personal names, postal addresses and any free text without a structured identifier; national identifiers of formats not listed; lowercase IBANs; unspaced Aadhaar numbers; personal data inside opaque encoded tokens (long base64, base64url or hex strings and PEM bodies are skipped on purpose); values split across fields or deliberately obfuscated; images and binaries. A clean scan is not evidence that an artifact contains no personal data. It is a regression tripwire for the common accidental leaks.

## 4. Selective disclosure

Goal: let a holder prove one field of a record to a verifier without revealing the other fields, and without publishing a guessable digest of the field.

### 4.1 Salted per-field commitments (design, reference helper provided)

For each sensitive field the issuer picks a fresh random salt (at least 16 bytes, 32 recommended) and publishes only the commitment:

`digest = HMAC-SHA-256(key = salt, message = domain label || len(recordId) recordId || len(field) field || len(canonical(value)) canonical(value))`

with the domain label `kya.privacy.field-commitment/v1`, 4-byte big-endian length prefixes and KYA canonical JSON for the value. The salt and value (the opening) stay with the holder. To disclose one field the holder sends `{salt, value}` for that field only; the verifier recomputes the digest and compares in constant time. Domain separation by label, record ID and field name stops a commitment from being replayed as another field or record.

`src/privacy/index.mjs` provides `commitField({recordId, field, value, salt?})`, returning `{commitment, opening}`, and `openField(commitment, opening)`, returning `{ok}` or `{ok:false, reason}` without throwing on malformed input. A signed record would carry the commitments in place of the values (for example one commitment per sensitive field under a coded field name); that record format is not defined or wired in yet.

### 4.2 Other options considered

SD-JWT style disclosure (the plan in WORLD-CLASS-PLAN WS9) is the interoperable route for the VC export and is not implemented here. Per-field commitments inside a Merkle tree would hide the number of fields; not designed. Zero-knowledge proofs of predicates (for example "the principal is a legal entity") are out of scope.

## 5. Retention and deletion

These are defaults for a deployer to adapt, not legal advice.

| Material | Default retention | Deletion |
| :--- | :--- | :--- |
| Raw evidence, traces, captured model I/O | Shortest period needed to resolve an appeal or incident, then delete; define the period before the run | Delete the private directory; keep only digests and the signed artifacts |
| Signed evidence and assessments | Until the assessment expires and the longest relying-party record-keeping duty lapses | Deleting the source does not remove published copies or digests |
| Incident narratives | As required by the incident process | Narrative deleted separately; the digest-only record remains and stays valid |
| Pseudonym map and commitment salts | As long as a disclosure may be requested | Destroying a salt makes its commitment permanently unopenable, which is the deletion mechanism for committed fields |
| Scanner reports | With the artifact they describe | Reports contain shape masks and paths, not values |

Erasure requests cannot be honored for data already inside a published signed artifact. This is the reason for redacting before hashing.

## 6. Honest limits

- The scanner is heuristic. It does not find names, addresses or free text, and a pass proves little.
- Commitments hide a value only while the salt stays secret and only when the committed value would otherwise be guessable. The same salt reused across fields or records reveals equality. The field name and the number of commitments are visible. A holder who loses the salt cannot open the field.
- The commitment helper is not zero-knowledge, not unlinkable across verifiers when the same opening is shown to several, and has had no cryptographic review. It is not wired into any signed record.
- A pseudonymous reference such as `accountableParty.ref` is personal data under many regimes if the issuer or anyone else can map it back to a person. Pseudonymous is not anonymous.
- Digests of low-entropy data are guessable. Hashing is not redaction.
- Artifact metadata (timestamps, IDs, sizes, signing keys) can itself identify a deployer or reveal activity patterns.
- This document and the tooling do not cover cross-border transfer, lawful basis, data subject rights handling, processor contracts or sector rules. Those need a qualified privacy professional and counsel; the [DPIA template](DPIA-TEMPLATE.md) is a starting structure for that review, and no such review has taken place.
