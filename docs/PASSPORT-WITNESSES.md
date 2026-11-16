# Registry witnesses and verifiable lookup

The registry-wide checkpoint commits Passport heads and the set of matching Passport IDs for every known agent key or manifest fingerprint. It works with the existing per-passport checkpoint, which carries one authenticated history. The verifier accepts proofs against a pinned origin and at least two configured witness keys.

## Run the reference workflow

Generate separate Ed25519 keys for the origin and each witness. Keep each witness key and SQLite database under that operator's control. Distribute the registry identifier and public trust keys independently to verifiers. The reference CLI operates on JSON files that fit the existing one-megabyte transport envelope.

```sh
node examples/passport-witness.mjs snapshot <registry> <origin-db> <origin-private-key> > epoch-1.json
node examples/passport-witness.mjs endorse <registry> epoch-1.json <witness-a-db> <origin-public-key> <witness-a-private-key> > witness-a.json
node examples/passport-witness.mjs endorse <registry> epoch-1.json <witness-b-db> <origin-public-key> <witness-b-private-key> > witness-b.json
node examples/passport-witness.mjs prove <registry> epoch-1.json fingerprint <digest> witness-a.json witness-b.json > lookup.json
node examples/passport-witness.mjs verify <registry> lookup.json fingerprint <digest> <origin-public-key> <witness-a-public-key> <witness-b-public-key>
```

Pass the prior bundle as the final `snapshot` argument when issuing the next epoch. Preserve the witness databases and deliver every epoch in order while its lifetime is valid. Independently collect the origin histories and pass the complete set to each witness. The command workflow can transport a single origin export for a local exercise. Real operators should compare independent records or signed registration receipts so a withheld registration can be discovered.

A valid proof returns a sorted array of matching Passport IDs, a Passport head and sequence, or null for verified absence. Keep the returned checkpoint epoch and digest. SDK clients can supply them as `checkpointPin` for subsequent lookups. Open a result using the expected Passport ID and verify its history against the proved head. Recent jointly signed data can lag a newer revocation until the next epoch. Use the authoritative reader for immediate gateway decisions.

## Scope

The reference implementation verifies signatures, reconstruction, persistence, freshness and exact lookup results. It is a full snapshot protocol with a derived Merkle lookup index. Succinct global consistency proofs, independent hosted operators, recovery from lost witness state, and witness-key rotations need further work. See [ADR-0060](adr/0060-witnessed-registry-lookup.md) and the [RFC 9162 transparency log design](https://www.rfc-editor.org/rfc/rfc9162).
