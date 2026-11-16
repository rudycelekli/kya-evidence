# Loopback OIDC and MCP pairing smoke test

From the repository root with Node 24, install the pinned test dependencies and run the fixture.

```sh
npm --prefix interop/pairing-gateway ci --ignore-scripts
npm --prefix interop/pairing-gateway test
```

The fixture starts an OIDC provider on a random loopback port and an MCP server child process speaking stdio through the official TypeScript SDK. It uses a synthetic account and automatic login and consent interactions. The OIDC client performs discovery, Authorization Code with PKCE, ID-token signature verification and nonce validation. The gateway enrolls one key, rotates it through a second login, refuses old credentials and forwards one exact MCP request. The fixtures use temporary SQLite databases that are removed when each test finishes. The browser callback receives an actual signed token through the local provider. The Streamable HTTP test negotiates with the official SDK server, checks bearer authentication and refuses a changed tool schema. The runner test uses a substituted identity to check rejection and verifies hash-only output. Package installation uses npm. The test itself keeps identity and tool activity on the local host.

A hosted enrollment deployment needs an approved tenant, real login UI, TLS and a pinned route registry. The test dependencies are isolated from the main package's runtime.
