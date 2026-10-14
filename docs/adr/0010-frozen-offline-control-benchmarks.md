# ADR-0010: Ship fixed offline evaluation-control benchmarks

**Status**: Proposed
**Date**: 2026-10-14
**Depends-on**: ADR-0003, ADR-0004, ADR-0009

## Context

A benchmark needs a fixed population and an evaluator that can detect an intentionally broken control. Existing public behavioral examples test a response contract and remain susceptible to memorization. Scaffolding a suite, checking its shape or receiving an imported score is not execution evidence. Provider, startup and timeout failures cannot be counted as successfully detected assertions.

## Decision

Ship a versioned frozen catalog with public behavioral reference controls and receipt-integrity adversaries. Run the actual reference/assessment APIs offline with no provider calls. Pin expected decisions, coverage and case populations before candidate evaluation. Include every planned case in the denominator, preserve errors, and separate measured duration from unknown cost. Preserve catalog, evaluator, source, input and artifact digests. Verification checks fixed identities/order/expectations and recomputes summary consistency.

These controls assess the reference evaluator and known synthetic harnesses. They do not score commercial agents or validate generalization. Benchmark snapshot checksums are unauthenticated references, not proof that a run occurred. External benchmarks require separate reviewed execution adapters and exact dataset/model/configuration bindings.

## Alternatives

A test-pass headline without negative controls cannot show evaluator sensitivity. Removing errors or missing cases inflates the denominator. Treating a timeout as a killed mutant confuses infrastructure failure with an assertion. Reusing public tests as a purported protected holdout would conceal contamination. A weighted composite of unrelated datasets lacks a stable decision contract.

## Consequences

Developers can exercise reproducible built-in checks without keys, model accounts or a network. Comparable future campaigns require matched cases, definitions and protected evaluator ownership. Quality, latency, cost and evidence reach remain separate dimensions. The standard can extend through versioned benchmark adapters without rewriting the core policy score.

## Validation

Test the complete catalog, positive controls, fixed negative controls and actual weak-source mutations. Reject omitted/reordered/duplicate cases, fabricated pass outcomes, modified expectations and inconsistent summaries even after outer checksums are recomputed. Record baseline failure to candidate pass using identical cases. No commercial product qualification is inferred.
