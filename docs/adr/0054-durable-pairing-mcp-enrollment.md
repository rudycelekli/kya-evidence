# ADR-0054: Durable pairing, MCP call framing and OIDC enrollment

**Status**: Implemented locally; review pending
**Date**: 2026-11-14

## Context

ADR-0053 authenticates paired actions and leaves challenge consumption, trusted principal identity and request framing to the host. An MCP gateway needs to enforce the same binding when multiple workers race, after restart and after a principal rotates keys.

## Decision

Use SQLite in WAL mode with full synchronous commits. Store each random 32-byte challenge with its issue and expiry times and the SHA-256 digest of its expected call digest, exact manifest digest, audience, permission, route revision and principal key ID. In a single immediate write transaction, read the current key and expected challenge, validate every binding and both signatures, consume the challenge, and persist the audit record. Forward once after commit. When forwarding returns, persist a response-observed marker in the accepted audit row. The marker requires no result payload and does not attest to downstream execution or success. Historical rows and interrupted forwarding stay unmarked. Retain accepted rows for audit. The operator owns retention and reconciles unknown downstream outcomes.

The MCP request digest is KYA canonical SHA-256 over `{schema: "kya.mcp-tool-call/v1", method: "tools/call", server, tool, arguments}`. The server is a trusted registry identifier and tool is the exact case-sensitive MCP name. Arguments must be a JSON object. The gateway resolves an immutable registered route revision and forwards the verified argument snapshot as MCP `tools/call` params. The downstream client resolves the pinned endpoint and owns MCP protocol negotiation and transport.

Store an opaque principal ID bound uniquely to an authenticated issuer and subject. Rotation compares the expected current key and authenticated identity under the write lock and preserves retired fingerprints. New grants and challenges use the new key.

The OIDC adapter's nonce is the digest of canonical JSON containing `schema: "kya.oidc-enrollment/v1"`, `issuer`, `audience`, `challenge`, `keyId` and `previousKeyId`. The new key signs the same canonical bytes prefixed with UTF-8 schema and LF. The provider authenticates the session and returns that nonce in its signed ID token. The host verifies the token against pinned issuer trust. The adapter checks the exact issuer, single audience, nonce, subject, expiry and a login within five minutes, proves possession of the intended key, and consumes the issued enrollment challenge before persisting the identity change. A consumed enrollment with an uncompleted identity write requires a new ceremony.

## Alternatives

An in-memory challenge store loses replay state on restart and cannot coordinate independent processes. A shared network database may be suitable for a multi-host gateway. Local SQLite gives a testable single-host boundary with no additional runtime dependency.

## Consequences

A crash after durable acceptance can prevent delivery. Downstream server execution remains separate from admission. Trust comes from hosted enrollment, a registered route, and provider-verified tokens. Local SQLite tests establish restart and independent-process behavior on one host. A hosted identity tenant and an externally operated MCP pilot still require separate evidence.

## Validation

Tests exercise cross-process replay, stored audit readback after restart, exact server/tool/argument binding, route changes, expiry, authenticated key rotation, signed OIDC intent, nonce reuse, and downstream errors after acceptance.
