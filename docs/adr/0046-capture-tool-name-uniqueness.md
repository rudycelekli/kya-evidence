# ADR-0046: Refuse duplicate tool names before capture surface comparison

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0021, ADR-0032

## Context

The simulated capture cell already rejected duplicate names among executable tools, but accepted duplicate IDs in its declared tool configuration. The capture payload validator also accepted duplicate exposed or declared names. Surface comparison, attempt checks and probe checks then created name-keyed maps, which selected the last definition. A synthetic capture could contain two `read_file` declarations with conflicting permissions, show an empty surface diff and no findings, verify under its trusted synthetic issuer, and produce a passing fixture tool-surface candidate. A correctly signed exposed surface with an additional conflicting definition had the same ambiguity.

This is a record-consistency defect demonstrated entirely with synthetic tools and keys. It does not establish a real-agent compromise, truthful host execution or sandbox isolation. Signature validity alone remains insufficient to establish record consistency.

## Decision

Require unique tool names separately within each exposed and declared capture surface. Refuse both identical and conflicting duplicates rather than deduplicating or selecting a first or last definition. Keep the existing exact tool shapes and 64-entry limits. Use the existing tool validator before map-based surface comparison and when validating signed payloads, so direct finding derivation and capture construction cannot silently collapse ambiguous surfaces either.

Reject duplicate declared tool IDs during `createCell`, before canary planting, clock advancement or simulated agent invocation. The existing executable-tool uniqueness guard remains unchanged. This early guard avoids doing agent work under an ambiguous declaration; signed-payload validation remains necessary for captures received from other issuers or manually assembled records.

No capture or evidence schema, evaluator identity, core scoring semantics, public assessment-vector expectation or claim class changes. Unique surfaces retain their deterministic bytes and fixture candidate behavior. Captures still declare `kind: simulated`, `isolation: none`, and unobserved environment surfaces. Candidate evidence remains `fixture`, unsigned until separately reviewed and signed by an evaluator.

## Alternatives

- Keep the last duplicate: rejected because it hides a conflicting recorded definition.
- Deduplicate byte-identical entries but reject conflicts: rejected; a unique-name contract gives one unambiguous representation and does not normalize malformed captures.
- Add only the early configuration guard: rejected; received signed payloads require their own validation.
- Add only the payload guard: insufficient for early failure before simulated agent work and direct surface finding derivation.

## Consequences

Previously accepted ambiguous captures and duplicate declared configurations now fail. Valid unique captures retain their behavior and serialization. A duplicate-name payload yields a schema problem during verification, so it cannot become a verified result accepted by the candidate adapter. The change does not prove that the issuer recorded all actual tools or that its declarations are truthful.

## Validation

Four frozen tests cover deterministic unique-surface compatibility; correctly signed exposed duplicates; correctly signed declared duplicates; and early configuration refusal before agent invocation. Both signed-payload cases include identical and conflicting definitions, before and after the original entry. The previous sources pass one and fail three; the candidate passes all four. The payload tests sign their synthetic bytes directly with a generated key so the verifier must detect the malformed surface rather than depend on `signCapture` refusing it. They separately require validation, signing and finding derivation to reject it, and ensure no candidate is admitted.

Three syntactically valid weakened implementations separately bypass exposed-name uniqueness, declared-name uniqueness and early configuration refusal. The same four tests must detect each control. Mutation execution requires all four tests to complete with no skips, cancellation or todo cases; syntax failures do not count as detections. Existing capture-cell, hardening and issuer-role regressions run separately. Evidence is local and same-team; independent review, real-agent validation and external acceptance remain unestablished.
