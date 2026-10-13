# ADR-0002: Trust comes from relying policy, not receipt self-claims

**Status**: Implemented, independent review pending
**Date**: 2026-10-13
**Related**: ADR-0001

## Context

A self-signed receipt can be cryptographically valid and entirely untrusted. An issuer can also claim independence, freshness or truth without evidence. Credential format alone does not settle relying-party trust.

## Decision

Use Ed25519 receipts with strict canonical payloads. Trust keys and signer roles are out-of-band policy configuration. Enforce subject/scope/profile/evaluator/source/time/revocation gates. Retain rejected evidence with reasons. Exclude declarations from scored observations. Distinguish fixture, runtime and mixed source modes.

## Alternatives

Trust any receipt key, accept issuer-assigned independence or centralize trust in one score service. These choices reduce setup but enable authority laundering or concentrate governance power. W3C VC adapters may later carry receipts; a bridge must preserve limits.

## Consequences

Relying parties must manage trusted keys and current revocation snapshots. Signatures prove integrity/key possession, not honest execution or organizational independence. Policy mistakes and collusion remain risks.

## Validation

Tests reject untrusted signing, revoked keys/receipts/subjects, stale/future evidence, declarations and wrong bindings. Report checksums remain unsigned and unauthenticated. External issuer review remains open.
