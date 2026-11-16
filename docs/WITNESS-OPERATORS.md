# Two-operator witness setup and recovery

Assign two operators who can independently hold signing keys and durable state. Use separate hosts, administration and backup access. A third role holds the offline enrollment authority key. The registry origin keeps its own checkpoint signing key. Pin the origin and authority public keys through a channel the operators and relying parties trust.

## Enroll the operators

Create the roster JSON with `schema: "kya.witness-roster/v1"`, the registry identifier, the origin Ed25519 fingerprint as `originKeyId`, `generation: 1`, `previous: null`, and `handoff: null`. Add exactly two `operators` sorted by ID, each with `id` and `publicKey` containing its SPKI PEM. An operator checks the roster and signs on its own host.

```sh
node examples/witness-operator.mjs enroll roster.json operator:a operator-a.pem > operator-a.json
node examples/witness-operator.mjs enroll roster.json operator:b operator-b.pem > operator-b.json
node examples/witness-operator.mjs approve roster.json offline-authority.pem > authority-signature.json
```

Assemble `{roster, signature, enrollments}` using the roster object, authority signature string, and both enrollment objects in roster order. Give each operator a locally pinned configuration object with `registry`, `originPublicKey`, `authorityPublicKey`, `rosters` (the list of signed rosters from genesis), and `pinnedRosterDigest` (the independently approved KYA digest of the latest roster payload). Include `checkpointPin` when the operator has an independently recorded latest joint checkpoint. This is exactly `{epoch, checkpointDigest}`.

Each operator keeps its own database on persistent storage. Compare the origin snapshot with independently retained registration receipts and endorse it.

```sh
node examples/witness-operator.mjs endorse local-trust.json epoch.json operator:a operator-a.sqlite operator-a.pem
node examples/witness-operator.mjs verify local-trust.json lookup.json fingerprint <fingerprint>
```

Archive each full jointly endorsed bundle `{signed, histories, endorsements}`. Independently retain the latest checkpoint pin and signed roster chain. Take consistent SQLite backups with the SQLite backup API or with the service shut down.

## Recover a database or replace a lost key

1. Freeze checkpoint publication at an independently confirmed joint checkpoint. Obtain the pinned epoch and digest from a surviving operator or independently stored receipt. A backup supplied by the origin alone is insufficient.
2. If the old key remains under your control, retain the roster and restore a fresh database from the exact jointly endorsed anchor. If a key is lost or compromised, generate a new witness key, keep the operator ID, set `generation` to the next number and `previous` to the trusted roster digest. Set `handoff` to the exact anchor. The offline authority, surviving operator and replacement key holder sign the new roster. Update the independently pinned roster on the operators and verifiers.
3. Restore the affected operator from an archived bundle under the roster effective at the anchor. Use an empty database. Keep the survivor's durable state. Recover one operator at a time.

```sh
node examples/witness-operator.mjs restore local-trust.json anchor.json operator:a restored-a.sqlite replacement-a.pem
```

4. Issue the next epoch with the handoff digest as predecessor. Both current keys endorse it independently. Verify inclusion and absence with the current roster. Exercise refusal of an old signer, an older database snapshot and a conflicting history.

If no jointly endorsed checkpoint and independent pin can be recovered, or if both keys are lost, stop this trust domain and establish a new trust decision. Archived snapshots enable state reconstruction. Live checkpoint verification uses the current clock. See [ADR-0061](adr/0061-witness-operator-roster-and-recovery.md).
