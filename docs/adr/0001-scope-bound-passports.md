# ADR-0001: Exact configuration and scope are the assessed subject

**Status**: Implemented, independent review pending
**Date**: 2026-10-13

## Context

An agent name alone hides model, harness, tools, configuration and permission differences. A portable reputation attached to a person or brand can falsely transfer assurance across configurations and uses.

## Decision

Hash the full strict manifest as the subject. Bind every receipt to that subject, explicit scope, frozen profile and evaluator. Keep the principal pseudonymous and prohibit human creditworthiness claims. Separate identity, evidence, assessment and conformance bounded contexts; public context exports omit infrastructure.

## Alternatives

A stable name-only passport makes lookup simple but permits configuration substitution. A person-level score conflates agent behavior with human worth. A digest of executable bytes alone excludes model/tool/scope context.

## Consequences

Every configuration change requires new evidence. Portability carries exact inputs and scope, not transferable universal trust. Manifest claims still need independent runtime observation.

## Validation

Reference validation rejects incompatible permissions and unexpected fields. Assessment tests reject wrong subject, scope, profile and evaluator. Independent runtime capture and external review remain open.
