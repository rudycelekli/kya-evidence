# ADR-0038: Refuse malformed UTF-8 before comparing implementation output

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0034, ADR-0036, ADR-0037

## Context

The vector runner decoded stdout with Buffer.toString('utf8'), which replaces malformed byte sequences with replacement characters. For a vector whose rejection reason is intentionally any nonempty string, corrupted bytes could become an acceptable reason and earn pass. The selected public case is `assess.proof-key-spelling-crlf-line-endings-rejected`, whose digest is intentionally not compared because the error text is implementation specific. Strict JSON parsing after lossy decoding does not detect the byte corruption.

## Decision

Decode successful result output using a fatal UTF-8 TextDecoder before strict JSON parsing. Share that function between ordinary results and the version 2 unsupported-refusal reply path. Set ignoreBOM true so a leading BOM remains in the decoded text for the existing strict parser to refuse; do not silently strip it. Preserve valid UTF-8 replacement characters and existing JSON escape semantics. Normal nonzero refusal handling still ignores stdout under the existing contract.

Add three frozen adversarial tests and a one-control isolated mutation runner that restores lossy decoding. Clarify KYA-VEC-005 and add its encoding tests as traces. The registry digest changes; no public assessment vector input, expected value, signing input or core evaluator identity changes.

## Alternatives

- Continue lossy decoding and rely on JSON validation: rejected because a replacement character can be valid JSON and an allowed free-form reason.
- Ban the replacement character: rejected because well-formed UTF-8 may legitimately encode it; validity depends on bytes, not the resulting character.
- Strip BOM while decoding: rejected because it would expand the accepted output grammar relative to the strict parser.
- Change vector expectations to reject all free-form reasons: rejected; unspecified error text must remain implementation specific and the fixed expectations are preserved.

## Consequences

Adapters that emit malformed result bytes now fail instead of having their output repaired implicitly. Valid output stays compatible. This verifies an encoding boundary, not truthful execution, useful error content, independence or adoption. Nonzero expected refusals remain unable to distinguish an intentional refusal from an uncaught exception. A producer may still fabricate well-formed output.

## Validation

The same three frozen encoding tests 2 passes and 1 failure on the previous runner and 3 passes and zero failures on the candidate. Valid U+FFFD stays accepted; invalid leading bytes, overlong encodings, truncated sequences and encoded surrogate bytes fail without requirement pass credit. BOM refusal and exact unsupported replies remain intact. Restoring lossy decoding is a syntactically valid mutant that fails the same malformed-output test. The isolated lane also ran the five existing runner gate tests, eight targeted tests total, without skips. Integration runs `scripts/vector-output-mutations.mjs`, the other admission controls and full regression separately. The 799 public vector expectations remain unchanged. This is same-team local evidence; hosted results and independent review are separate gates.
