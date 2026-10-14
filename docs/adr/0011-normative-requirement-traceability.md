# ADR-0011: Number normative requirements and gate their test traceability

**Status**: Implemented
**Date**: 2026-10-14
**Depends-on**: ADR-0003, ADR-0008, ADR-0010

Review boundary: separate project lane; no external certification.

## Context

The specification is accurate prose, but a second implementer cannot cite, count or test its obligations. Prose and tests drift: a test can be renamed or deleted while the document still claims the behavior is enforced. Multi-implementation conformance (roadmap stage 5) needs stable requirement identifiers and an auditable mapping from each obligation to executable evidence.

## Decision

Keep `evidence/requirements.json` as the single registry of requirement IDs (`KYA-<AREA>-<NNN>`), RFC 2119 level, specification section and verifying tests. Generate `docs/REQUIREMENTS.md` from it. `npm run check` fails when an ID is duplicated, a level is invalid or not stated in the sentence, a section is absent from the specification, a requirement has no test, or a cited test title is missing or ambiguous. IDs are never reused; a removed obligation is retired in a new ADR, not renumbered.

## Alternatives

Annotating tests with comments cannot detect an obligation that has no test. Embedding IDs in the specification prose duplicates the registry and drifts. Counting passing tests as coverage says nothing about which obligations are enforced. Claiming RFC-level normativity without independent implementations would overstate maturity.

## Consequences

Implementers can claim conformance per requirement ID. Reviewers see untraced obligations immediately. A trace proves the reference implementation has a test for the obligation, not that the test is sufficient or that any outside party reviewed it. Mutation controls remain the evidence that tests detect weakened gates.

## Validation

`test/requirements.test.mjs` mutates a copy of the registry to remove a test, rename a title, duplicate an ID, set an invalid level, cite a missing section, drop the level from the statement and cite an ambiguous title; each must be rejected. The generated document must equal the registry rendering.
