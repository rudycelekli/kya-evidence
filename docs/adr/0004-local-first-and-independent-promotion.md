# ADR-0004: Local-first evidence, bounded adapters and independent promotion

**Status**: Implemented
**Review**: Core reviewed independently at 0b63f5e; whole-artifact external review remains open.
**Date**: 2026-10-13
**Depends-on**: ADR-0002, ADR-0003

## Context

Evaluation can leak secrets, incur unexpected costs or execute untrusted code. Public fixtures can be mistaken for real product assessments. Candidate generation can bias its own evaluator and claims.

## Decision

Keep runtime dependency-free and offline by default. Command adapters use executable plus argument array, never shell; bound time/output and suppress stderr exposure. Execution isolation belongs to caller. Fixtures retain synthetic provenance. Dashboard imports remain unverified claimed reports and use text-only rendering. Promotion compares frozen baseline/candidate cases and requires independent review; human authority controls publication and deployment.

## Alternatives

Automatically launch installed agents, download benchmark scripts or publish a leaderboard from fixture scores. These create apparent activity without authorized, trustworthy observation. A managed sandbox may later strengthen isolation but needs tested integration.

## Consequences

Setup is explicit. Executable probes establish availability only. Costs remain null if unmeasured. No roadmap implies a running scheduler. Multiple implementation, capture and calibration milestones precede standardization claims.

## Validation

Transport tests cover timeout, excessive output, malformed responses, nonzero exits and stderr suppression. Viewer tests cover malformed reports and malicious text. Real commercial-agent measurements, external audit and multi-implementation acceptance remain open.
