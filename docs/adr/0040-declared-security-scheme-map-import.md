# ADR-0040: Import security scheme names only from maps and expose truncation

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0002, ADR-0012, ADR-0039

## Context

The partial A2A declaration importer used JavaScript's `typeof value === 'object'` check before retaining the keys of `securitySchemes`. An array also passed that check, so a synthetic input containing an array of scheme definitions produced the invented scheme name `"0"`. The field was simultaneously excluded from `unsupportedFields`. The 128-name output bound also silently truncated larger maps while reporting their root field as recognized.

This is an internal mapping correction, not a claim of A2A schema validation or verified interoperability. The importer deliberately does not authenticate identities, validate security scheme definitions, resolve endpoints or inspect credentials. All examples and tests for this change are locally written synthetic declarations.

## Decision

Keep `kya.declaration-import/v1` and its bounded `declared.securitySchemeNames` array. A non-null object map supplies its existing names; arrays and primitives supply no names. The input is already copied through the canonical plain-JSON boundary, so accepted non-array objects are plain object maps. An empty object map is representable. An absent `securitySchemes` field preserves the empty-name behavior without an unsupported-field marker.

Only recognize a present `securitySchemes` field when it is a map containing at most 128 names. Present malformed shapes, including null and arrays, appear in `unsupportedFields`. Larger maps retain the existing first-128-name projection and also appear in `unsupportedFields`, making the truncation inspectable. Ordering remains the existing canonical key order; no name is normalized, generated or resolved.

The complete original input still determines `sourceDigest`. Scheme definitions and credentials are not emitted. Every existing unverified flag and limitation remains. The Open-KYA mapping, assessment schemas, evaluator identity, evidence denominator and public assessment-vector expectations are unchanged.

## Alternatives

- Continue accepting arrays as maps: rejected because indices invent declaration names.
- Drop every over-limit map entirely: rejected to preserve the existing bounded projection while exposing its loss.
- Reject the entire declaration for a malformed optional field: deferred; the API is a partial importer with explicit unsupported-field reporting.
- Treat names as verified security mechanisms: rejected; a declaration is neither a security assessment nor a permission grant.

## Consequences

Consumers of malformed declarations no longer receive invented scheme names. Consumers can distinguish a complete bounded scheme-name mapping from an unrepresentable or truncated field. Output snapshots for these cases intentionally change; valid maps of at most 128 names and absent-field behavior remain compatible. The importer still does not validate individual map values or claim complete external schema conformance.

## Validation

Four frozen tests cover valid maps at sizes zero, one and 128; absent fields; malformed present shapes; and a 129-name map. They retain source-digest, privacy and unverified-boundary assertions. The previous importer passes two and fails two; the candidate passes all four. The same four tests detect three syntactically valid weakened implementations: accepting arrays as maps, concealing malformed shapes and concealing truncation. Mutation execution requires all four tests to complete with no cancellation, skips or todo cases; a syntax error cannot count as a detected mutation. Existing declaration-import, governing-authority and claim-boundary regressions run separately. This is local same-team evidence; independent review and external acceptance remain pending.
