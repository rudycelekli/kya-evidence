# ADR-0043: Expose omitted and truncated declaration list members

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0012, ADR-0039, ADR-0040

## Context

The partial declaration importer deliberately filters and bounds external declarations. Open-KYA `permittedDomains`, `permittedRegions` and `forbiddenRegions` retain string members of at most 256 UTF-16 code units, then at most 128 retained members. A2A `skills` retains nonempty string IDs of at most 128 UTF-16 code units, then at most 128 retained IDs. Those projections previously removed malformed members or truncated larger lists without listing the root field in `unsupportedFields`.

The importer itself grants no permission or score. However, an empty or shortened projection of restrictions can be mistaken for a complete list when the loss is not inspectable. This is an internal partial-mapping correction, not evidence of an authorization bypass or external schema conformance. All validation cases are locally written synthetic declarations.

## Decision

Preserve every existing projection, bound, ordering and duplicate. Keep `kya.declaration-import/v1` and its current output fields. Report a present Open-KYA list field as unsupported whenever it is not an array entirely composed of strings at most 256 UTF-16 code units long, or when its input array contains more than 128 members. Absent optional fields retain empty arrays without unsupported markers. Empty arrays and representable string lists remain recognized; empty strings retain the existing behavior without additional semantic validation.

For A2A, keep the required array shape for `skills`. Report that root field as unsupported if mapping omits any ID because it is missing, empty, nonstring or longer than 128 UTF-16 code units, or if the input list exceeds 128 members. Retain the existing bounded ID projection. Skill descriptions and other metadata are deliberately outside that projection; their omission alone does not mark the field unsupported. Do not normalize or deduplicate IDs.

The complete source still determines `sourceDigest`. Emit no dropped values, skill metadata or credentials. Preserve all unverified flags and limitations. Imported lists remain declarations; they do not establish effective restrictions, identity, authority, runtime enforcement, or external interoperability acceptance. Assessment schemas, evaluator identity and public assessment-vector expectations are unchanged.

## Alternatives

- Continue silently filtering and truncating: rejected because consumers cannot inspect the missing projection members.
- Reject the whole declaration on a malformed optional list: deferred; this API provides partial mappings and unsupported-field reporting.
- Remove all valid members when one is malformed: rejected to preserve the existing projection and compatibility.
- Emit rejected values or new diagnostic copies: rejected; the source digest binds the complete input without expanding disclosure.
- Treat all omitted skill metadata as unsupported: rejected; the stated mapping is of IDs, not full skill objects.

## Consequences

Valid bounded lists, absent optional fields and all existing retained values remain compatible. `unsupportedFields` intentionally gains affected root names for malformed or truncated input. Consumers must read those markers with the unverified boundary; a retained subset is not a complete external schema validation. Duplicate and empty-string behavior remains unchanged where already representable.

## Validation

Six frozen tests cover representable lists and metadata compatibility, absent optional lists, malformed Open-KYA list members, Open-KYA truncation, malformed A2A IDs and A2A truncation. The previous source passes two and fails four; the candidate passes all six. The same tests detect four syntactically valid weakened implementations that separately conceal each format's malformed-member loss and truncation. Mutation execution requires all six tests to complete with no cancellations, skips or todo cases, and syntax errors cannot count as detected mutants. Existing authority and scheme-map mutation controls also run to protect those admission boundaries. Evidence is local and same-team; independent review and external acceptance remain pending.
