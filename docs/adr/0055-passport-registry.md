# ADR-0055: Signed passport registry and historical fingerprint lookup

**Status**: Implemented locally; review pending
**Date**: 2026-11-15

## Context

A relying party needs a persistent name for a registered agent and a way to look up a formerly active fingerprint after rotation. The pairing proof in ADR-0053 proves possession for a specific action. A registry records a separately verifiable lifecycle.

## Decision

The passport ID is the KYA digest of canonical JSON with schema `kya.passport-id/v1`, registry identifier, agent ID, principal ID, and controller key ID. Key IDs use the existing KYA Ed25519 fingerprints. A registry's scope is bound into every event. The example HTTP service uses its configured origin.

The event has exactly the fields in the PassportEvent declaration. Controller and agent signatures cover UTF-8 `kya.passport-event/v1`, followed by LF and the canonical event. Signatures are unpadded base64url Ed25519 signatures. Each event commits to the digest of the complete prior signed record, with a null predecessor for registration.

The fixed controller signs every transition. The agent signs registration and revisions, and the incoming key signs a rotation. A revision keeps the current key and changes the manifest digest. A rotation replaces the key with a fingerprint previously unused in the passport. The controller revokes the passport with no agent signature and the current manifest digest. Revocation is terminal. Of 128 available events, the last slot is reserved for revocation.

SQLite serializes append and fingerprint index changes under an immediate transaction. Exact retries return the latest history. Multiple passports may share a fingerprint, so lookup returns all matching IDs. Signed history determines the current projection.

## Alternatives

Using an agent key fingerprint as the passport ID would change the URL during rotation. Publishing the full manifest would expand the disclosure boundary. The MVP uses a separate stable ID and publishes the manifest commitment.

## Consequences

Registration binds a declared agent and principal to keys that demonstrated possession. Attribution to an operator requires independent identity evidence. An offline verifier can authenticate an event chain and pin a known head. Verifying freshness for a new client requires trust in the registry until checkpoint and mirror support exists. Loss or compromise of the fixed controller key needs a future recovery protocol. The loopback HTTP example is an integration surface for local testing.

## Validation

Tests cover tampering, signer substitution, cross-registry replay, conflicting history, retired key reuse, revision, revocation, the reserved revocation slot and SQLite readback. The verification evidence records the HTTP smoke run and weakened signature control separately.
