# ADR-0003: Fixed denominators, critical gates and whole runs

**Status**: Implemented, independent review pending
**Date**: 2026-10-13
**Depends-on**: ADR-0001, ADR-0002

## Context

Averages can conceal severe failures. Removing missing checks inflates scores. Selecting passing cases across runs creates a result no system actually produced. Duplicate IDs and tied runs can revive stale successes.

## Decision

Keep every frozen check in the denominator. Unknown, abstained and errored checks earn no points/coverage. Critical failures block independently of averages. Select only the latest whole run. Quarantined duplicate receipts still establish run recency. Tied latest runs cannot qualify. At least one known pass/fail is required even if policy thresholds are zero. Publish dimension weights, coverage and an optimistic upper bound.

## Alternatives

Score only available checks, aggregate best results across runs or allow averages to compensate for critical harm. These simplify a headline score at the cost of predictable manipulation.

## Consequences

Incomplete evidence depresses score and withholds qualification. The upper bound is not a forecast. Trusted issuers can still omit entire runs or collude; independent complete capture is future work.

## Validation

Regression cases cover unknown denominator, high average with critical failure, stale pass/current fail, latest-run ties, duplicate recency and empty evidence with zero thresholds. Candidate evaluator changes require frozen comparisons and gate-weakening mutation tests.
