# ADR-0005: Content-addressed research universes and immutable package inputs

**Status**: Implemented
**Date**: 2026-10-13
**Depends-on**: ADR-0001, ADR-0002, ADR-0003, ADR-0004
**Review**: Local adversarial tests and separate implementation lanes; external whole-artifact review remains open.

## Context

Research changes through competing hypotheses, new evidence and corrections. Mutable notebooks and unbound implementation versions can hide which inputs produced a conclusion. A branch should preserve its parent and allow exact replay without implying truthful observations or causal improvement.

## Decision

Create strict content-addressed universes containing all assessment inputs, explicit assessment time, source references, question, computed assessment and source-engine digest. Hash every executable src module and package routing, covering transitive import barrels. Require named hypotheses for forks. Recompute on replay and reject incompatible or incomplete comparisons. Preserve correction references and expose affected descendants. Build package archives from immutable Git blobs, fixed tar metadata and per-file SHA-256 inventories. Publish canonical and Ed25519 golden vectors.

## Alternatives

Mutable latest-only reports, version strings without source hashes, best-case case mixing or editable research branches are simpler but lose reproducible lineage. A blockchain or vector database does not establish truth and is unnecessary for this local reference record. Signed external timestamps and independent capture can be added without substituting for reproducible inputs.

## Consequences

Any executable or package-routing change requires the archived engine for historical replay. Hashes are integrity references, not signer authentication, original-byte possession, rights verification or proof of loaded runtime code. Correction metadata does not grant revocation authority. The default snapshot can contain private signed evidence and must remain private until separately authorized sanitization. Protected holdouts and external outcomes remain necessary for causal improvement and calibration.

## Validation

Twenty-eight targeted universe cases cover deterministic bytes, every binding, stale rehash attempts, actual engine/barrel/package mutations, symlink refusal, immutable parent forks, graph corrections and missing references, rights limits and comparison refusal. Package tests reject unsafe tar types, links, paths, metadata, duplicate records, bad checksums and gzip resource abuse. Gate mutation checks require the same complete passing baseline population before accepting assertion failures as a killed mutant.
