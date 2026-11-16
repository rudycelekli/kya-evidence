# ADR-0057: Recover unknown MCP outcomes from durable delivery records

**Status**: Implemented locally; review pending
**Date**: 2026-11-15

## Context

ADR-0054 records local acceptance before forwarding. A process may die after a downstream operation takes effect and before a response is recorded. Automatically dispatching that action again can duplicate the effect.

## Decision

Write a delivery row atomically with acceptance and challenge consumption. Derive its operation ID from canonical `{schema:"kya.mcp-delivery/v1", actionDigest, routeRevision}`. Pass that ID separately to the trusted forwarding adapter, which can propagate it using the downstream's own idempotency or receipt interface. The signed MCP arguments remain exact.

Advance the row from accepted to dispatching before calling the adapter. Adapter errors mark the row unknown. A process interrupted during forwarding leaves dispatching, which also requires reconciliation. Record a returned response as response-observed atomically with the audit marker. Keep prior audits readable when they predate delivery tracking.

Expose a bounded operator scan and reconciliation API. The host observer uses the original route and operation ID to establish an authenticated terminal outcome and returns an exact operation ID and receipt digest. Unknown observations preserve state. A reconciliation cannot overwrite a terminal result. No delivery path automatically redispatches. An accepted row that never entered dispatching requires operator handling and fresh authorization before any new call.

## Alternatives

Retrying every accepted request risks doubling effects. Recording only returned responses loses the ability to identify work interrupted during the call. Requiring all MCP implementations to support the same receipt mechanism would exclude hosts with different interfaces.

## Consequences

The journal preserves ambiguity instead of claiming successful execution. A response can carry a tool error. The observer must authenticate receipts and require a definitive outcome. A temporary absence or a lookup failure is unknown. Use a pinned downstream route and verify association with the original operation before confirming anything.

## Validation

A child process records the operation ID in a synthetic downstream fixture and exits before it returns. A second gateway connection recovers the row, refuses a receipt for another operation, records confirmation by digest, and refuses replay. Separate tests cover transport errors and ordinary response observation.
