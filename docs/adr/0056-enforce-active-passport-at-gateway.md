# ADR-0056: Enforce current Passport state at MCP acceptance

**Status**: Implemented locally; review pending
**Date**: 2026-11-15

## Context

ADR-0054 verifies exact MCP calls against principal-signed grants and agent signatures. Under ADR-0055, a previously valid agent key may be rotated or revoked while a grant is still within its validity interval.

## Decision

A gateway configured with a Passport registry and current-history reader requires a pinned passport ID on every route. The challenge binds that ID. On invocation the gateway first verifies the pairing proof, then reads and authenticates the current signed Passport history. The Passport must be active and its ID, agent, principal, current key fingerprint and exact manifest digest must match the pinned route and verified proof. Missing history, a reader error, or a failed match aborts acceptance. The accepted audit records the passport ID and observed signed head. Gateway instances without Passport configuration retain their existing API and challenge digests.

The reader is a trusted synchronous dependency. An authoritative SQLite read at acceptance is the reference deployment. The Passport database and gateway database may be separate. Acceptance uses the committed snapshot observed by the reader. A revocation committed after that read does not cancel an in-flight acceptance or tool call.

## Alternatives

Checking only at challenge issuance permits rotation between challenge creation and invocation. Trusting a supplied current projection allows its unsigned fields to diverge from the signed event history. Trusting an arbitrary valid signed prefix cannot establish freshness.

## Consequences

An unexpired pairing proof cannot independently authorize an agent on a Passport-required gateway. A local authoritative reader supplies currentness. A remote reader needs a separate freshness and consistency policy. The audit records the exact Passport head checked. The gateway's acceptance remains distinct from an observed downstream response or successful delivery.

## Validation

Equivalent signed proof bytes are submitted to the pairing verifier and the Passport-enabled gateway. Tests exercise active and replacement keys, stale manifest, rotation and revocation between issuance and invocation, missing policy and history, and a substituted passport ID. A weakened enforcement gate is exercised in an isolated source copy. The OIDC and MCP loopback fixture repeats enrollment, principal rotation, live-shaped MCP tool dispatch, Passport rotation and revocation.
