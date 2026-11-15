# SQLite pairing gateway for MCP

The experimental `kya-evidence/pairing/mcp-gateway` export runs on maintained Node 22 and 24 releases with `node:sqlite`. It binds an MCP tool call to a verified principal–agent pairing and commits acceptance before it forwards. Give each gateway deployment a private persistent volume and a single shared SQLite database on a local filesystem.

## Connect an MCP client

1. Configure a trusted registry keyed by server ID and case-sensitive tool name. Resolve a manifest, audience, permission, revocation lists and SHA-256 route revision. The named tool and permission must occur in the manifest. Derive the route revision from your immutable route descriptor, including the endpoint identity, tool schema and permission mapping. Resolve the same pinned route revision at forwarding time.
2. Enroll a principal with the adapter below. The gateway host authorizes access to challenge issuance using its own session policy. Maintain a trusted mapping from issuer and subject to an opaque principal ID and authorize each configured MCP route.
3. The gateway issues a 60-second challenge for `{server, tool, arguments}`. Agents hash the exact call using `mcpToolCallDigest` and sign it with `signPairedAction`. Use an explicit empty object for tools without arguments. Parse incoming JSON strictly.
4. Call `gateway.invoke(call, proof)`. The receipt includes the request hash, route revision, server ID, tool and both signer identities. The downstream callback receives the verified snapshot. A conventional connected MCP SDK client can forward via `client.callTool(request.params)`.

```js
import { openPairingGateway } from 'kya-evidence/pairing/mcp-gateway';

const gateway = openPairingGateway(databasePath, {
  authenticateIdentity,
  resolveRoute(server, tool) {
    return trustedRoutes.lookup(server, tool);
  },
  forward(server, revision, { params }) {
    return trustedRoutes.connectedClient(server, revision).callTool(params);
  },
});
```

Keep credentials, connection setup, endpoint identity checks, MCP negotiation, tool input schema enforcement, quotas and output controls in the gateway application and MCP client. The downstream operation can remain unknown if the process stops after durable acceptance or the server fails to respond. Audit reports local acceptance and the gateway refuses replay. An application that retries externally visible work needs downstream idempotency and outcome reconciliation. Keep accepted audit rows according to the operator's retention policy.

## Enroll and rotate through OIDC

Use `kya-evidence/pairing/oidc-enrollment` with an OIDC client for the configured issuer. The client handles discovery, Authorization Code with PKCE, ID-token signature verification and trusted JWKS. Configure step-up or recent login and request `max_age=300` so the token contains `auth_time`.

1. Call `gateway.issueEnrollmentChallenge()`. The ceremony uses an opaque, random, five-minute value.
2. Build an intent with `issuer`, `audience` (the OIDC client ID), `challenge`, the new `publicKey`, and `previousKeyId` (null for initial enrollment). Send `oidcEnrollmentNonce(intent)` as the OIDC authentication request's nonce. The holder of the new key signs `oidcEnrollmentMessage(intent)` with Ed25519.
3. The gateway's `authenticateIdentity` accepts `{idToken, challenge, publicKey, signature}`. The adapter requires the configured issuer and a single audience string, verifies possession of the new key, matches the provider nonce to the intent, checks recent login and consumes the durable challenge. Pass `challenge => gateway.consumeEnrollmentChallenge(challenge)` as `consumeNonce`.
4. Route initial enrollment to `enrollIdentity` and rotation to `rotateIdentity(session, previousKeyId)`. The same registered issuer and subject may move from the current fingerprint to a new key. Existing grants under the former key fail at verification, old pending challenges no longer match, and rotation refuses retired keys.

The OIDC token verifier and principal mapping are host dependencies. The local tests run a cryptographically signed fixture identity ceremony. Deployment with a real provider requires that provider's app registration, approved callbacks and a test identity. [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) · [MCP tool calls](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)

See [ADR-0054](adr/0054-durable-pairing-mcp-enrollment.md) for the transaction and wire boundaries.
