# ADR-0012: Declare an accountable party and let policy require it

**Status**: Implemented
**Date**: 2026-10-14
**Depends-on**: ADR-0001, ADR-0003, ADR-0011

Review boundary: separate project lane; no external certification.

## Context

KYC ties a relationship to a verified customer and, for entities, to natural persons who own or control them. The v1 manifest names only a pseudonymous `principal.id`, so a relying party cannot require that an agent answers to a human or legal entity. The 2026-10-14 research note found no verified standard that binds an external agent to an accountable principal, and UK MLR reg 39 shows reliance does not transfer accountability.

## Decision

Add an optional `principal.accountableParty` `{kind, ref}` to the manifest, where `kind` is `natural-person` or `legal-entity` and `ref` is a pseudonymous identifier. No other fields are accepted, and `ref` cannot equal the agent ID. Add an optional policy flag `requirePrincipalBinding`; when true, a manifest without the declaration returns `insufficient-evidence` with an explicit blocker. Both fields are optional so existing manifests, policies and digests are unchanged. The declaration is inside the manifest and therefore inside the subject digest: changing the accountable party invalidates prior evidence.

## Alternatives

A mandatory field would break every v1 manifest and force a version bump before the semantics are proven. A free-form name or contact field would pull personal data into public records. Verifying the party in the evaluator would claim identity proofing the protocol cannot perform. Putting the requirement only in prose would not be testable.

## Consequences

Relying parties can demand an inspectable accountability reference. The declaration remains an unverified claim: it does not prove identity, authority or liability, and a self-declared reference can be false. Verified principal binding needs signed credentials from an accountable issuer and is future work. The core profile does not score this field.

## Validation

Tests reject an agent as its own party, unknown kinds, extra fields, non-object values and a non-boolean policy flag. They show a policy requiring the party withholds qualification when absent, qualifies when present, changes the subject digest, and leaves prior behavior unchanged without the flag.
