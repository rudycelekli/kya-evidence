# KYA Passport MVP

A passport is a signed registry record for a declared agent. The controller and agent sign the registration locally. A stable ID names the passport, a manifest digest identifies a declared configuration, and an Ed25519 key fingerprint identifies the active signing key. Verification checks the public history against the configured registry and the expected passport ID. A relying party separately establishes who controls the controller key and checks a live agent proof before granting access.

## Try the registry

Use Node.js 22.13 or later. Run the sample on one machine with a private database path.

```sh
mkdir -m 700 passport-demo
node --input-type=module <<'JS'
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
for (const name of ['controller', 'agent', 'replacement']) {
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync('passport-demo/' + name + '.pem',
    privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
}
JS
node examples/passport-server.mjs passport-demo/registry.sqlite
```

In a separate terminal, register a manifest. The command returns a passport ID, the active key fingerprint, and a link to the passport page.

```sh
node examples/passport-client.mjs register http://127.0.0.1:7337 examples/manifest.json passport-demo/controller.pem passport-demo/agent.pem
```

Use the returned ID and original key fingerprint in the following commands. An optional expected head argument to `verify` checks that the registry returns the exact revision observed by the verifier.

```sh
node examples/passport-client.mjs verify http://127.0.0.1:7337 <passport-id>
node examples/passport-client.mjs rotate http://127.0.0.1:7337 <passport-id> passport-demo/controller.pem passport-demo/replacement.pem
node examples/passport-client.mjs lookup http://127.0.0.1:7337 <old-key-fingerprint>
node examples/passport-client.mjs revoke http://127.0.0.1:7337 <passport-id> passport-demo/controller.pem
```

Use `revise <origin> <passport-id> <controller-key> <active-agent-key> <new-manifest>` to update the declared configuration while keeping the active key. Revocation ends the passport. The passport link and old fingerprint lookups continue working as long as the registry retains its data and address.

The HTTP sample binds to loopback. Its links are usable on the host running it. The registry and verifier are reusable modules for an application that exposes an HTTPS registry under its own origin.

## API

- `POST /v1/events` appends one signed event or returns the current history for an exact retry.
- `GET /passports/<id>` displays the passport, current status and a link to its signed history.
- `GET /v1/passports/<id>` returns the signed history and current projection. A verifier should derive the projection from the history and compare the passport ID with its expected ID.
- `GET /v1/fingerprints/<digest>` returns every indexed passport URL for the key or manifest digest. Verify each candidate history and check that it contains the requested fingerprint.

Use opaque identifiers in shared passports. The service publishes those identifiers, public keys, signatures and manifest digests. It keeps the private keys and manifest document off the HTTP wire. Place shared registries behind admission controls and rate limits.

## What remains for distribution

The MVP supports terminal revocation and one logical SQLite registry. Optional offline recovery applies to version-two registrations. Per-passport checkpoints support authenticated mirror readback. Registry-wide consistency proofs and independent witnesses remain future work. A verifier that trusts a single registry for freshness relies on it to show the latest signed head. A hosted rollout also needs operator identity enrollment, retention rules, backups, and incident response. Connect live pairing by requiring that the verified action's agent key and exact manifest match the active passport state.

See [ADR-0055](adr/0055-passport-registry.md) for event and signature rules.

## Register a recoverable Passport

To opt into version-two recovery, append an offline recovery private key path to the registration command. Use a separate Ed25519 key and sign registration on a machine where the recovery key can be used safely. Keep it offline after the ceremony. The service receives public keys and signatures.

If an active Passport loses its controller key, generate a replacement controller and agent key. The offline recovery key and both replacement keys sign the same event against the current head.

```sh
node examples/passport-client.mjs recover http://127.0.0.1:7337 <passport-id> <new-controller-key> <new-agent-key> <offline-recovery-key>
```

The existing URL and former fingerprint lookup continue working. The new agent key and controller replace the old ones. A previously registered v1 Passport has no recovery authority. Terminal revocation remains final.

For authenticated distribution to another operator's store, see [Passport checkpoints and mirrors](PASSPORT-CHECKPOINTS.md).

For authenticated registry-wide discovery, see [registry witnesses and verifiable lookup](PASSPORT-WITNESSES.md).
