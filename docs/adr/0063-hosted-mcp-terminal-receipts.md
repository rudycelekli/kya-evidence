# ADR-0063: Verify terminal downstream MCP receipts by operation ID

**Status**: Implemented locally; review pending
**Date**: 2026-11-16

## Context

ADR-0057 persists gateway delivery state but relies on an authenticated downstream observer to classify an interrupted operation. A hosted pilot needs a receipt format and a way to exercise recovery across process boundaries.

## Decision

An opted-in pilot route commits to the receipt endpoint and signer fingerprint in its route revision. The gateway passes the operation ID, request digest and route revision in MCP `_meta["kya-evidence/delivery"]`. The tool name and arguments retain their exact verified values. The downstream authenticates the caller, checks the binding against the request it received, and associates the operation ID with its own authoritative outcome.

Query the pinned HTTPS receipt endpoint using a read-only GET to the operation ID. Refuse redirects, bound the response, and use a separate scoped bearer if configured. A terminal receipt signs UTF-8 `kya.mcp-receipt/v1`, LF and canonical JSON with Ed25519. The receipt message has exactly `schema`, `operationId`, `requestDigest`, `routeRevision` and `outcome`. The transport envelope has exactly `receipt` and `signature` with unpadded base64url. Accept only confirmed-applied or confirmed-not-applied with correct signature and exact delivery binding. HTTP 202 and 404 leave the delivery unresolved. A bad receipt or transport error never changes the outcome.

The drill stops the process after the MCP response returns and before the gateway records response observation. A second command opens persisted delivery state and queries the receipt endpoint. Reconciliation has no tool dispatch dependency and never resends the call.

## Alternatives

MCP tool responses alone cannot resolve uncertain delivery after a crash. A receipt from an arbitrary origin or a signed receipt for a different request scope is insufficient. Generic retries could duplicate external effects.

## Consequences

Receipt profiles are explicit opt-ins. They require a cooperating downstream application and an authoritative terminal receipt signer with independent custody. A valid signature proves the signer made the receipt assertion. Operational evidence must establish that the downstream signs from its committed outcome and that the terminal declaration is trustworthy.

## Validation

An SDK Streamable HTTP fixture receives one call. The gateway process exits before recording the response. Fresh reconciliation processes reject a missing receipt, a receipt signed by the wrong key and a genuine signature over the wrong request digest. The correct receipt persists the terminal outcome. The tool's call count stays at one.
