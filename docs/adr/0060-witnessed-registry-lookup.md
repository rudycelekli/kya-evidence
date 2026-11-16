# ADR-0060: Independent registry witnesses and authenticated lookup

**Status**: Implemented locally; review pending
**Date**: 2026-11-16

## Context

ADR-0058 authenticates one Passport view. A registry lookup can omit a matching registration or falsely claim that a fingerprint was never registered. Separate witnesses need to verify and preserve their view of the complete registry.

## Decision

Build the registry index from a coherent committed snapshot of every Passport history. Verify each complete signed history. Add one leaf for each `passport:<id>` with its head and sequence and one leaf for each `fingerprint:<digest>` with the sorted, deduplicated set of matching Passport IDs across all events. Include historical agent fingerprints and manifest digests after rotation or revocation.

Sort ASCII leaf keys in lexicographic order. Hash canonical KYA JSON arrays `["kya.registry-leaf/v1", leaf]` and `["kya.registry-node/v1", left, right]` with the existing SHA-256 digest. Duplicate the final node of an odd level. An empty tree hashes `["kya.registry-empty/v1"]`. Authenticated membership specifies a zero-based leaf position and ordered siblings. Nonmembership proves both adjacent boundaries or the relevant tree edge. The verifier checks positions, ordering, padding and signed leaf count.

The pinned origin signs canonical checkpoint bytes with prefix `kya.registry-checkpoint/v1` and LF. A checkpoint commits the registry, epoch, previous checkpoint digest, root, leaf count and time interval of at most five minutes. Genesis is epoch 1. Each witness rebuilds the index from the complete histories. It independently validates the origin signature, enforces sequential epochs and advancing timestamp, and persists the authenticated checkpoint and each Passport head before releasing its endorsement. A previously seen Passport must still exist and extend its exact history. Endorsements sign the checkpoint with the distinct prefix `kya.registry-witness/v1` and LF.

Verifiers pin the origin key and between two and sixteen distinct witness keys, require all pinned endorsements, and validate that every signature refers to the same checkpoint. A client can pin its last known epoch and digest and refuse older or same-epoch conflicting checkpoints. Witnesses maintain separate keys and state. Public registry exports carry public histories and proofs only.

## Alternatives

Returning a signed list for each query gives no independently reconstructed global commitment. An RFC 9162-style global event log would provide succinct append-only consistency proofs. This first version reconstructs complete snapshots at every witness and uses a separate sorted map for lookup.

## Consequences

This design proves complete results relative to the jointly authenticated snapshot. A witness can detect disappearance of previously observed records. At genesis it depends on the histories it independently obtains. Completeness at the origin and independence of witness operators require operational evidence. A still-valid older checkpoint can be replayed against a new client. A missing witness prevents verification, and key replacement and onboarding after genesis require a future trust policy. Full snapshot distribution and bounded proof payloads target pilot scale.

## Validation

Tests cover shared fingerprints, truncation, false absence, padding, missing and repeated witness endorsement, expiry, local checkpoint pins, historical rotation, and durable refusal to re-sign a conflicting or truncated history. The CLI fixture uses two independently keyed processes and separately persisted witness databases. A weakened adjacency guard is tested against the same adversarial proof.
