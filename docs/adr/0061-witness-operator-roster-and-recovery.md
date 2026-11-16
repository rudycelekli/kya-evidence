# ADR-0061: Onboard independent witness operators and restore witness state

**Status**: Implemented locally; review pending
**Date**: 2026-11-16

## Context

ADR-0060 requires separately pinned witness keys and durable consistency state. An operator needs to enroll a key, recover a lost database, and replace a lost key without treating an unverified snapshot as current.

## Decision

A pinned offline authority signs an exact two-operator roster with the domain prefix `kya.witness-roster/v1` and LF. Each operator signs its ID and roster digest with prefix `kya.witness-enrollment/v1` and LF. The origin, authority and two witness keys must be distinct. Operators sign locally and distribute only public keys and signatures. Verify sequential roster generations against the previously authenticated roster. Pin the current roster digest in local configuration obtained independently of the origin.

To replace a key, keep the same two operator IDs and replace one key at a time. Bind the new roster to the prior roster digest and a handoff epoch and checkpoint digest. The authority, survivor and replacement sign the transition. Previously retired witness keys cannot rejoin this roster lineage. Verification using the new roster requires a checkpoint after its handoff epoch.

For state loss or replacement, select the latest checkpoint anchor through an independent operator channel. An empty witness validates the origin signature, both endorsements under the roster effective at that epoch, exact pinned digest and epoch, and complete histories. The restore transaction writes the checkpoint and Passport heads before the witness can endorse a later epoch. An archival checkpoint can be used for restore after its expiry. Live reads still enforce expiry. A nonempty database refuses restore.

## Alternatives

Trusting the newest file supplied by the origin permits rollback. Requiring both previous private keys to sign a rotation prevents recovery after a key is lost. Authority plus survivor approval and an independently pinned, previously jointly endorsed checkpoint preserves continuity for a single lost key.

## Consequences

Two independent operators still need separate deployment and custody. If there is no independently recoverable joint checkpoint, or both witness keys are lost, the current trust domain requires operator intervention and a new trust decision. Verifiers must update their pinned roster through a trusted channel. A verifier using an obsolete roster can accept that roster until its local trust is updated. Existing raw witness APIs remain suitable for prototype callers that independently manage trust.

## Validation

Tests cover wrong-key enrollment, missing survivor approval, generation rollback, archive recovery with both old endorsements, wrong checkpoint pins, state replacement refusal and old-key rejection after handoff. The CLI rehearsal coordinates the same transitions with separate keys and databases. The weakening check removes the pinned anchor comparison against the same fixture.
