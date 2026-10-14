# ADR-0015: Machine-readable conformance report with honest evidence classes

**Status**: Implemented
**Date**: 2026-10-14
**Depends-on**: ADR-0003, ADR-0008, ADR-0011, ADR-0014

Review boundary: separate project lane; no external certification.

## Context

ADR-0011 gave every normative obligation a `KYA-*` ID and a traced test, and ADR-0008 added a secondary Python byte checker. Nothing yet lets an implementation state, in a form a machine can compare, which IDs it passes, how it knows, and what it did not run. Free-text claims invite counting skipped tests as passes, counting self-declarations as evidence, and silently dropping requirements an implementation never tried.

## Decision

Define `kya.conformance-report/v1`: implementation identity (name, version, language, optional source digest, optional declared subset), the digest of the requirement registry it ran against, an explicit run time, and one entry per registry requirement with `result` in pass, fail, not-applicable, not-run and `evidence` in executed-test, portable-vector, declaration. Each executed entry lists the exact test or vector IDs. A pass requires executed-test or portable-vector evidence and at least one executed ID; a declaration can never be pass. Every registry ID appears exactly once; unknown, missing and duplicate IDs and a registry digest mismatch are rejected. not-applicable is valid only when the implementation's own declared subset excludes the ID; without a declared subset the answer for an unrun requirement is not-run. Summary counts are recomputed on validation and keep not-run in the denominator; only not-applicable leaves it. The report is unauthenticated unless wrapped in an Ed25519 envelope signed under the new domain `kya.conformance-report/v1\n`, following the incident pattern. The JavaScript reference builds its report by running each cited test file under the TAP reporter: a requirement passes only if all traced tests pass and none was skipped; a skipped or absent trace is not-run.

## Alternatives

A bare percentage hides unknowns and denominators. Counting declarations as pass lets a self-description score. Allowing an implementation to omit requirements makes the denominator negotiable. Reusing the incident signing domain would let a signature on one record type be replayed as another. Reading the clock inside the builder would make reports non-reproducible.

## Consequences

Any implementation can publish a comparable, digest-bound claim. The registry digest ties a report to one registry version; a registry change makes old reports stale rather than wrong. A report proves what the producer says it executed, not that it ran truthfully, that the tests are sufficient, or that the producer is independent. A signature proves integrity and key possession only.

## Validation

`test/conformance-report.test.mjs` covers deterministic builds, summary counts with not-run retained, rejection of unknown, missing and duplicate IDs, declaration-backed pass, digest mismatch, misuse of not-applicable, strict shape, tampered summaries, signature tampering and cross-domain signatures, TAP parsing with escapes and skips, mapping rules for fail, skip and absent traces, and the CLI end to end on a fixture repository.
