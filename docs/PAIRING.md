# Experimental principal–agent pairing

A principal is the user or organization that delegates a permission. A pairing grant identifies the principal, an agent signing key and one exact manifest. A paired action demonstrates possession of that agent key and binds the grant to one relying-party challenge and the SHA-256 digest of the action request.

Run the packaged example with Node.js 22 or later.

```sh
node examples/verify-pairing.mjs
```

The example replays a synthetic [wire vector](../examples/pairing-vector.json) with public keys and an explicit fixture clock. The verifier returns principal, agent and key IDs plus the manifest, grant and action digests. Treat those values as potentially linkable audit identifiers. Use a principal reference scoped to the relying party and keep raw requests, private keys, identity assertions, and the principal-reference mapping outside shared evidence.

## Gateway integration

1. Resolve the expected principal ID and its trusted, active Ed25519 key fingerprint through the gateway's identity enrollment. Use the local registry's current manifest for this agent and audience.
2. Have the principal sign a grant with `signPairingGrant`. The grant permits one operation for up to one hour and fits inside the manifest's validity interval.
3. Generate a fresh 32-byte random challenge at the gateway. Store it with a short expiry, the expected audience, permission, manifest and principal. Define which request bytes are protected. An HTTP gateway's request representation should bind the method, target and body. An MCP tool proxy should bind the selected server and tool and the arguments. The request format is an integration contract.
4. Have the agent sign the canonical signed-grant digest, the challenge and the exact request digest with `signPairedAction`. Deliver the two envelopes as a `{grant, action}` JSON object.
5. Parse input with the package's `parseJson` to reject duplicate members. Call `verifyPairedAction` with the proof and the gateway-owned context, including its clock, current revocation lists and the digest recomputed from the received request. Atomically consume the challenge before any side effect. Repeated verification of the same proof produces the same result. For distributed gateways use a shared consume-once store and ensure retries are idempotent at the action boundary.
6. Apply the relying party's authorization policy and retain the IDs and digests needed for audit. For permissions requiring separate action approval, this verifier refuses the grant. Replace compromised or retired key bindings, revoke affected grants and issue a new grant after rotation.

The gateway supplies the trust binding between the principal ID and the key. This profile verifies both signatures and the exact request commitment. Human identity, authority to act, runtime execution and third-party assessment require their own evidence. A gateway also owns challenge expiry, one-time use and freshness of revocation data. The included profile is an offline experiment with no live OAuth, SPIFFE, MCP or A2A adapter.

See [ADR-0053](adr/0053-principal-agent-pairing.md) for the interoperable wire rules.

## Interoperability milestones

1. Define a single request framing profile at an HTTP or MCP gateway and demonstrate acceptance of an enrolled pair, rejection of a modified request and consume-once behavior under concurrent delivery.
2. Profile identity enrollment and key rotation against a real identity provider. Consider OAuth token exchange for delegated credentials, DPoP for OAuth token sender constraint, and SPIFFE for workload identity. Specify which trust claims each integration brings into KYA and how those claims expire or are revoked. [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693), [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/).
3. Have an independent implementer validate the wire format from the specification and run both acceptance and rejection vectors. Record disagreements before stabilizing the protocol version.
4. Run a relying-party pilot with a measurable enrollment, action verification, key rotation and incident response path. Advance the standards proposal after external security review and governance participation.
