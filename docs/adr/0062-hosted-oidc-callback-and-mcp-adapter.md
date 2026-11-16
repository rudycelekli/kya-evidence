# ADR-0062: Hosted browser callback and scoped MCP pilot adapter

**Status**: Implemented locally; review pending
**Date**: 2026-11-16

## Context

The hosted pilot preflight checks configuration and provider discovery. A pilot operator needs a real browser callback and an external MCP transport that preserve the approved endpoint, tool and arguments.

## Decision

Use openid-client for discovery and an Authorization Code exchange with S256 PKCE, single-use state, KYA enrollment nonce, recent login and ID-token signature verification. Bind an ephemeral listener to IPv4 loopback. The approved HTTPS reverse proxy delivers only the registered callback path. The token exchange constructs the callback from configured values, regardless of Host and forwarding headers. Unmatched state does not consume the login. A consumed callback cannot redeem another code. The expected issuer subject is mapped to the manifest principal before enrollment.

Use the MCP SDK for Streamable HTTP and keep the endpoint and credential scoped to one configured URL. Forbid redirects. Pin server, route revision, tool name and the canonical SHA-256 digest of its input schema. Fetch tool metadata before opening the pilot and before forwarding. The already verified MCP argument snapshot passes unchanged. Persist the normal gateway acceptance and delivery records. The runner emits operation, Passport head, request and result digests with an expected-result comparison. Credentials, claims and results stay in the pilot process.

## Alternatives

A mock token verifier and stdio exercise can validate local trust logic but cannot qualify a real hosted tenant or tool. Building a general-purpose hosted gateway would add exposure and make the first pilot harder to scope.

## Consequences

Operators provide the registered callback, proxy, persistent gateway and registry databases, active Passport and permitted test tool. The reference runner handles one approved call per execution. The downstream deployment must keep the tool revision stable during the exercise. Additional receipt integration is needed for an external crash recovery drill. Keep callback query strings out of proxy logs.

## Validation

The loopback provider tests the actual callback and signed code exchange, refuses a forged state, and verifies exact callback handling despite untrusted forwarding headers. A separate SDK server covers authenticated Streamable HTTP, endpoint and route pins, and schema changes. A runner fixture checks wrong-subject refusal and digest-only results. Hosted provider and tool evidence require the approved pilot environment.
