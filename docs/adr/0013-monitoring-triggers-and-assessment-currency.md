# ADR-0013: Detect change after assessment with monitoring triggers

**Status**: Implemented
**Date**: 2026-10-14
**Depends-on**: ADR-0003, ADR-0004, ADR-0011, ADR-0012

Review boundary: separate project lane; no external certification.

## Context

KYC ongoing monitoring (MAS Notice 626, UK JMLSG 5.7) keeps relationship knowledge current and cannot be outsourced to the party that vetted the customer. An assessment is point-in-time: a relying party could present a qualified report after the agent, policy or revocation state changed. FinCEN's 2026 relief shows regulators already prefer event-driven re-verification to blanket re-collection.

## Decision

Add `checkCurrency(assessment, {manifest, policy, now})` and `kya currency`. It verifies report integrity, validates the supplied manifest and policy, and fires named triggers: `subject-changed`, `policy-changed`, `subject-revoked`, `assessment-expired`, `assessment-aged` (optional policy `maxAssessmentAgeSeconds`) and `clock-regression`. Any trigger yields `action: reassess` and a non-zero CLI exit. `reliable` additionally requires a qualified decision. The result is unauthenticated and states that it observes no runtime behavior.

## Alternatives

Embedding currency in `assess` would blur a point-in-time result with a later check. A live revocation lookup service needs infrastructure and trust the protocol does not have. Treating `validUntil` alone as freshness ignores manifest and policy change. Claiming continuous behavioral monitoring would require independent capture that does not yet exist.

## Consequences

Relying parties get a deterministic, offline staleness check mapped to named triggers. It cannot see behavior drift, omitted runs or events nobody supplied. Incident records and behavioral triggers remain future work. Revocation freshness still depends on the policy snapshot the relying party supplies.

## Validation

Tests cover each trigger alone and in combination, boundary ages, unchanged currency, non-qualified decisions, forged reports, missing or invalid time, invalid inputs, an invalid age setting and the CLI exit codes. Mutation controls remove the expiry and subject-change triggers and must be detected.
