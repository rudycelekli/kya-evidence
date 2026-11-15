# ADR-0053: Principal–agent pairing for exact actions

**Status**: Implemented locally; review pending
**Date**: 2026-11-14

## Context

A manifest declares the principal and agent configuration, and evidence issuers can sign assessment receipts. A relying gateway needs a distinct proof linking a trusted principal's grant to possession of an agent key and to the exact request entering the gateway.

## Decision

The experimental profile defines two closed JSON payloads. Member names are case-sensitive.

| Schema | Required members in addition to `schema` |
| --- | --- |
| `kya.pairing-grant/v1` | `principalId`, `agentKeyId`, `manifestDigest`, `audience`, `permission`, `issuedAt`, `expiresAt` |
| `kya.paired-action/v1` | `grantDigest`, `challenge`, `requestDigest` |

Identifiers match `[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}` in full. Digests and challenges are 64 lowercase hex characters. Timestamps are actual UTC calendar instants in exactly `YYYY-MM-DDTHH:mm:ss.sssZ` form. Each envelope has exactly `payload`, `publicKey`, and `signature`. The public key is canonical Ed25519 SPKI PEM with LF endings and one trailing LF. Use a 64-byte Ed25519 signature encoded as unpadded canonical base64url. The signature input is UTF-8 schema text, then byte 0x0A, then UTF-8 KYA canonical JSON of the payload.

Use KYA's existing canonical JSON and SHA-256 conventions. A key ID hashes SPKI DER bytes. The manifest digest hashes the canonical manifest. The grant and action digests hash their entire canonical envelopes, including the key and signature. The request digest hashes the exact bytes defined by the gateway integration. The grant binds the agent key ID and manifest digest. The action binds the exact signed grant digest, gateway challenge and request digest. The schema prefix separates the two signature domains.

Verify against a trusted context containing the actual expected manifest, enrolled principal ID and key ID, expected audience and permission, outstanding challenge, recomputed request digest, clock and current lists of revoked keys and grant digests. Require both authentic signatures and distinct keys. Require the manifest and the grant to name the enrolled principal. Require the grant's allowed permission to occur in the manifest's permissions and to be absent from its approval-required list. The grant lifetime is positive and at most 3,600,000 milliseconds, fully contained in the manifest validity interval. The verification clock must fall within the inclusive start and exclusive end of the grant. Refuse either revoked key or a revoked signed-grant digest. A failed verification throws and returns no audit record.

## Alternatives

A manifest declaration cannot demonstrate key possession. A bearer grant would allow a party who copied the grant to reuse it. An external identity-token format could be profiled later. This increment reuses KYA's Ed25519, canonical JSON, SPKI fingerprint and manifest validation to keep existing KYA integrations consistent.

## Consequences

Transport is application-defined. A gateway independently owns identity enrollment, request framing, revocation freshness and atomic challenge consumption. Pairing proves possession of the keys and integrity of the bindings under the supplied trust context. The signed bytes carry no direct personal data, but identifiers can be correlated. Independent interoperability, key custody, runtime authority and deployment qualification remain open.

## Validation

The pairing suite covers forgery, key and manifest substitution, grant splicing, request substitution, scope, expiry, revocation, executable context inputs and a frozen synthetic wire replay. These tests exercise the reference verifier offline. See the local run record for regression and verifier mutation results.
