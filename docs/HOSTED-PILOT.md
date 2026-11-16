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
