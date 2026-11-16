# ADR-0059: Recover active passports using a committed offline key

**Status**: Implemented locally; review pending
**Date**: 2026-11-15

## Context

ADR-0055 fixes the controller key at registration. Loss removes the ability to rotate or revoke. A compromised controller may leave an untrusted agent key active. Recovery must authorize a new controller and agent without changing the Passport URL.

## Decision

A version-two registration adds a fixed `recoveryPublicKey` to the event and a `recoverySignature` to its record. The recovery key signs registration alongside the controller and initial agent. The v2 ID digest uses schema `kya.passport-id/v2` and adds `recoveryKeyId` to the registry, agent, principal and initial controller commitment. Existing v1 IDs and signatures remain compatible.

Version-two events sign UTF-8 `kya.passport-event/v2`, LF and canonical event JSON. Every subsequent event matches the original identity, schema and recovery key. Ordinary events require the current controller and a null recovery signature. A recovery event extends the exact current head and is signed by the registered recovery key, an unused replacement controller and an unused replacement agent. Recovery retires the prior active credentials on the same Passport and preserves historical key and manifest lookup. The offline key is distinct from operational keys. Revocation remains terminal.

## Alternatives

Retrofitting recovery into a signed v1 history could let a compromised controller appoint an attacker as a recovery authority. Allowing recovery to keep the prior agent key could preserve a compromised key. A quorum and recovery delays may suit larger operators, with separate policy and liveness requirements.

## Consequences

The v2 recovery anchor is fixed at registration. Operators need to keep it offline and test recovery before use. Loss of both controller and recovery keys or a terminal revocation requires a new passport. Recovery authority can replace both operational keys, so independent custody and review matter. Gateway authorization checks the new agent fingerprint. OIDC principal enrollment remains independently managed.

## Validation

Tests cover recovery under the same ID, old controller refusal, retained historical fingerprint lookup, missing or wrong recovery signature, key reuse, and attempts after terminal revocation. The HTTP CLI fixture exercises new registration and recovery through the original URL.
