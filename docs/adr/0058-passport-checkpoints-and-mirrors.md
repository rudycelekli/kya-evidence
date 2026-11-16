# ADR-0058: Signed Passport checkpoints and durable mirror readback

**Status**: Implemented locally; review pending
**Date**: 2026-11-15

## Context

A Passport chain authenticates lifecycle events. A valid older prefix can hide a later rotation or revocation. ADR-0056 pins a locally observed head. A mirror also needs an authenticated and expiring observation from the registry.

## Decision

A separately pinned Ed25519 registry key signs UTF-8 `kya.passport-checkpoint/v1`, LF and the canonical checkpoint. The checkpoint names the registry, Passport ID, exact head digest, sequence, issuance and expiry. A verifier checks the pinned key, time interval of up to five minutes, and the complete signed history for that exact head. Future and expired checkpoints fail. A bundle transports the checkpoint, signature and complete history.

The mirror uses a separate SQLite store. Pin the registry identity and signing key when the store is initialized. Imports verify and update atomically. A new history must include the previous authenticated head at the same sequence. Issuance cannot go backward. Equal issuance allows only an exact bundle retry. Reads verify the stored checkpoint again and refuse expired data. Operators may use the mirror as the gateway reader under an explicit freshness policy.

## Alternatives

A mirror of unsigned projections relies on the transport for integrity and allows undetectable truncation. A single global transparency log gives stronger completeness and cross-mirror consistency, with additional indexing and witness work.

## Consequences

The checkpoint attests to one Passport view under one trusted registry key. It bounds the age of that signed view. A still-valid signed view can lag the origin, so immediate revocation requires an authoritative read. A fresh mirror cannot detect a split view without independent witnesses or comparing trusted checkpoints. Registry-wide inclusion and lookup completeness proofs, signer rotation and external operation remain additional work.

## Validation

A mirror imports two signed heads, rejects a newly signed rollback after reopening, refuses a substituted verification key, and fails closed at expiry. Tests also reject wrong signer, tampered history and excessive checkpoint lifetime.
