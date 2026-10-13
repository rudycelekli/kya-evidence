# ADR-0003: Fixed denominators, critical gates and whole runs

**Status**: Implemented
**Review**: Core reviewed independently at 0b63f5e; whole-artifact external review remains open.
**Date**: 2026-10-13
**Depends-on**: ADR-0001, ADR-0002

## Context

Averages can conceal severe failures. Removing missing checks inflates scores. Selecting passing cases across runs creates a result no system actually produced. Duplicate IDs and tied runs can revive stale successes.

## Decision

Keep every frozen check in the denominator. Unknown, abstained and errored checks earn no points/coverage. Critical failures block independently of averages. Select only the latest whole run. Authentic bound receipts establish recency before expiry, revocation and duplicate quarantine; invalidating a newer failure cannot resurrect an older passing run. Tied latest runs, mixed evaluator issuers and repeated frozen checks cannot qualify. Failure remains visible across timestamps; retry with a fresh complete run. At least one known pass/fail is required even if policy thresholds are zero. Publish dimension weights, coverage and an optimistic upper bound.

## Alternatives

Score only available checks, aggregate best results across runs or allow averages to compensate for critical harm. These simplify a headline score at the cost of predictable manipulation.

## Consequences

Incomplete evidence depresses score and withholds qualification. The upper bound is not a forecast. Trusted issuers can still omit entire runs or collude; independent complete capture is future work.

## Validation

Regression cases cover unknown denominator, high average with critical failure, stale pass/current fail, latest-run ties, duplicate recency and empty evidence with zero thresholds. Candidate evaluator changes require frozen comparisons and gate-weakening mutation tests.
