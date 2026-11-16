# ADR-0064: Portable Passport conformance corpus and candidate runner

**Status**: Implemented locally; review pending
**Date**: 2026-11-16

## Context

Passport history, witnessed lookup and downstream receipt rules need a command-level contract other teams can exercise without the KYA runtime. Assessment operations already have a separate runner and corpus.

## Decision

Freeze an independent v1 Passport vector corpus and stdin/stdout process contract. A valid candidate response explicitly accepts with an exact value, rejects, or reports unsupported. Timeouts, process errors, invalid JSON and unexpected results fail. Unsupported cases remain visible and prevent a clean outcome. A standard-library Python runner uses no KYA implementation code for comparison. The corpus uses public synthetic keys and fixed times. It includes exact expected values, wrong signatures and trust, absence and omission, stale history, expiry and incorrect delivery bindings.

## Alternatives

Extending the assessment runner would tie third-party execution to the JavaScript reference checkout. Accepting any nonzero exit as rejection could admit infrastructure failures. Explicit refusal preserves that distinction.

## Consequences

The kit runs standalone with a supplied candidate command. CI compares frozen bytes and runs both project-authored implementations. Project-authored cross-language agreement does not substitute for outside implementation or a licensed hosted pilot.

## Validation

Both project implementations pass all frozen cases. Harness controls reject malformed results and failed processes and distinguish unsupported cases. The corpus mutation exercise verifies a weakened receipt binding fails the same frozen vector.
