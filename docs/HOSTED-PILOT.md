# Hosted OIDC and MCP pilot preflight

Use the existing approved test tenant and a scoped external tool. Prepare a local JSON file using the structure below. The values are examples. Keep the actual file in the pilot workspace. References name records in your deployment or secret store.

```json
{
  "oidc": {
    "issuer": "https://login.example.test/test-tenant",
    "clientId": "kya-pilot-client",
    "callback": "https://gateway.example.test/oidc/callback",
    "authentication": "none",
    "credentialRef": null,
    "testIdentityRef": "pilot:test-user"
  },
  "gateway": {
    "url": "https://gateway.example.test",
    "registry": "https://registry.example.test",
    "deploymentRef": "pilot:gateway",
    "storageRef": "pilot:gateway-sqlite"
  },
  "mcp": {
    "url": "https://tools.example.test/mcp",
    "transport": "streamable-http",
    "tool": "read_fixture",
    "schemaDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "credentialRef": "vault://pilot/mcp",
    "testCaseRef": "pilot:read-fixture",
    "receiptRef": null
  }
}
```

Use the registered client authentication mode and a credential reference if it requires a secret or private key. Supply a test sign-in contact, scoped gateway deployment access, a writable persistent volume, the versioned MCP input schema, and one sanitized request with its expected result. Confirm permission to invoke that tool. The optional receipt reference identifies the downstream operation-ID and receipt interface for the second-stage recovery exercise.

```sh
node interop/pairing-gateway/hosted-preflight.mjs /private/path/pilot.json
node interop/pairing-gateway/hosted-preflight.mjs /private/path/pilot.json --discover
```

The first command validates configuration shape and performs no network requests. Discovery fetches only the pinned issuer's public metadata, validates issuer and HTTPS endpoints, and checks Authorization Code and the configured client authentication mode. When PKCE capability is omitted from metadata, the result records it as unadvertised. A real browser sign-in and authorization-code exchange remain required. [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) · [PKCE](https://datatracker.ietf.org/doc/html/rfc7636)

For the hosted run, connect the approved browser callback and MCP client to the gateway application. Complete enrollment and a signed read-only request, record the proof and receipt digests, then exercise principal and agent rotation, replay refusal, tampered arguments, revocation and registry unavailability. Use the downstream receipt interface for the controlled interruption test. Sign-off requires a live, authenticated tool response and refusal evidence from the actual gateway. See the [readiness plan](PASSPORT-ROADMAP.md).

## Run one approved hosted call

Use Node 24 and install the pinned adapters with `npm --prefix interop/pairing-gateway ci --ignore-scripts`. On the HTTPS gateway, route only the exact registered callback path to `127.0.0.1:<callbackPort>`. Preserve the path and query for the exchange, disable query and header logging for that route, and restrict shell and database access to the pilot operators. The browser callback never supplies a tool name or arguments.

Create a separate private inputs JSON file:

```json
{
  "expectedSubject": "approved-test-user-subject",
  "callbackPort": 7338,
  "gatewayDatabase": "/private/pilot/gateway.sqlite",
  "registryDatabase": "/private/pilot/passports.sqlite",
  "passportId": "<registered-passport-id>",
  "manifestFile": "/private/pilot/manifest.json",
  "principalKeyFile": "/private/pilot/principal.pem",
  "agentKeyFile": "/private/pilot/agent.pem",
  "previousPrincipalKeyId": null,
  "server": "pilot:external-tools",
  "permission": "read",
  "arguments": { "path": "synthetic-fixture.txt" },
  "expectedResultDigest": "<canonical-kya-sha256-of-the-expected-MCP-result>"
}
```

Use a current manifest that explicitly authorizes the tool and permission. Register the test agent in the authoritative Passport database for the configured registry. Keep the signing files restricted. Pin the issuer's exact subject and the complete expected MCP result digest. Resolve secrets through the deployment's credential store. Supply `KYA_PILOT_OIDC_SECRET` for client secret authentication, `KYA_PILOT_OIDC_PRIVATE_JWK` for an RS256 client assertion, and `KYA_PILOT_MCP_BEARER` for a scoped MCP bearer token. Public clients and unauthenticated test tools can omit their corresponding credential.

```sh
node interop/pairing-gateway/hosted-pilot.mjs /private/pilot/settings.json /private/pilot/inputs.json
```

Open the authorization URL from the private operator console and sign in as the pinned subject. On success the runner enrolls the principal, verifies the active Passport, and sends the one signed call. The outcome contains its operation ID, Passport head, request and result digests, and whether the result matched. For a principal rotation run, supply the previous enrolled fingerprint and point the principal key file to the replacement. Review persisted delivery state before any rerun following an ambiguous outcome. Supply a trusted downstream receipt adapter for the separate interruption qualification.

## Exercise downstream recovery after a controlled interruption

Use a read-only or idempotent test tool with a cooperating receipt service. Provide the scoped receipt endpoint and signer public key in a private profile file.

```json
{
  "url": "https://receipts.example.test/status",
  "publicKey": "<canonical Ed25519 SPKI PEM>",
  "credentialRef": "vault://pilot/receipts"
}
```

Set `KYA_PILOT_RECEIPT_BEARER` from the approved receipt credential reference. Use null for a test receipt endpoint that does not require a bearer. The configured MCP server must accept the operation binding in `_meta["kya-evidence/delivery"]`, check the route and actual request, and serve the terminal signed envelope at `GET <url>/<operationId>`. Agree on how it records the authoritative effect and terminal outcome before starting.

First run a normal hosted call. For the recovery drill use a separate authorized test run with fresh enrollment or an explicit principal rotation, and enough scope to exercise the approved operation once.

```sh
node interop/pairing-gateway/hosted-pilot.mjs /private/pilot/settings.json /private/pilot/inputs.json \
  --interrupt-after-response /private/pilot/receipt-profile.json
```

The controlled run prints the operation ID and exits with status 75 after the tool responds. Then use the same gateway database, route configuration and receipt profile. This second command does not need OIDC or the tool credential.

```sh
node interop/pairing-gateway/hosted-pilot.mjs /private/pilot/settings.json /private/pilot/inputs.json \
  --reconcile /private/pilot/receipt-profile.json <operation-id>
```

Capture the terminal delivery state and receipt digest, and ask the downstream operator to confirm the invocation count remained one. A pending receipt leaves the outcome unresolved. Repeat the receipt lookup when authorized. See [ADR-0063](adr/0063-hosted-mcp-terminal-receipts.md).
