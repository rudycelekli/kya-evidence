# Passport checkpoints and mirrors

Use `kya-evidence/passport/checkpoint` and `kya-evidence/passport/mirror` to serve an authenticated, time-bounded copy of a Passport history. The operator pins the registry identifier and an independently distributed checkpoint public key. Keep the checkpoint signing key separate from agent and controller keys.

1. Read the committed Passport from the origin registry. Build a checkpoint with `schema: 'kya.passport-checkpoint/v1'`, `registry`, `passportId`, `head`, `sequence` (history length), `issuedAt` and `expiresAt`. Use canonical UTC millisecond timestamps with a lifetime of at most five minutes. Issue different bundles for the same passport at distinct times.
2. Sign `passportCheckpointBytes(checkpoint)` with Ed25519. Transport `{checkpoint, signature, history}` through your distribution channel. Encode the signature as unpadded base64url. Verify against the pinned public key before accepting any projections.
3. Open `openPassportMirror(databasePath, { registry, publicKey })` and call `importCheckpoint(bundle)`. Import includes the complete signed history. Copy only public records.
4. Read with `mirror.read(passportId)`. A stale or malformed stored checkpoint fails closed. Use an authoritative origin read for immediate revocation. A paused distribution feed must resume with a current checkpoint that extends the mirror's last stored head.

Deploy the same import and read API on independently operated mirrors when operators are available. These per-passport bundles do not prove completeness of a registry-wide lookup or cross-mirror agreement. See [ADR-0058](adr/0058-passport-checkpoints-and-mirrors.md).
