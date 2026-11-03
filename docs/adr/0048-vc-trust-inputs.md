# ADR-0048: Capture and validate VC issuer trust inputs

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0022, ADR-0045

## Context

The VC verifier used `expectedIssuerKeys.length` and the caller array's `map` method directly. A Set or object with no length silently skipped pinning, and a native Proxy GET view could replace the declared array member and produce `issuerTrust: expected`. Policy anchoring compared only a key ID and revocation membership. A JSON anchor whose ID named the signing key but whose public key belonged to another issuer could produce `issuerTrust: anchored` and an independent role, despite violating the core KYA policy fingerprint invariant. Live policy reads could also conceal revocations.

The existing API and tests accept a partial `{ trustedKeys, revokedKeyIds }` policy projection. Requiring the entire KYA policy schema would break that interface and validate unrelated settings that the issuer check does not consume.

## Decision

Require `expectedIssuerKeys` to be a dense array of at most 256 members. Capture descriptor-backed membership through `captureArrayItems` before matching; use the resulting plain array rather than caller-supplied methods or element GET views. Preserve DID strings, Ed25519 public KeyObjects, PEM strings and raw public-key bytes as supported member forms. Omitted input and an empty array keep the documented unchecked mode. Invalid collection shape returns `ISSUER_KEYS_INVALID` through the existing verification error result. Status-list verification shares the same opener and retains its existing status-error wrapping.

For policy anchoring, capture the two own enumerable data fields `trustedKeys` and `revokedKeyIds`, then canonicalize and parse that projection before reading anchors or revocations. Validate the consumed core invariants: at most 256 trust anchors, exact anchor members, SHA-256 key IDs matching valid Ed25519 public PEM keys, recognized roles, unique anchor IDs, and at most 4,096 unique well-formed revoked key IDs. Preserve both full policies and partial trust projections; unrelated full-policy fields are not validated by this check.

Treat any supplied policy, including falsy malformed values, as a requested trust restriction. A malformed projection returns `POLICY_INVALID` within the verification result. A valid projection with no matching non-revoked anchor keeps `ISSUER_NOT_TRUSTED`. Return `anchored` only after the consumed projection is validated and the issuer matches it.

## Alternatives

- Accept arbitrary iterable expected-key collections: rejected; the interface already models a key array, and implicit empty detection silently drops restrictions.
- Validate a full KYA policy: rejected for this interface because the supported trust projection intentionally omits unrelated policy fields.
- Compare only caller-supplied key IDs: rejected; that can assert a role for an anchor whose public key disagrees with its fingerprint.
- Read live policy data after validation: rejected; native GET views can alter trust or hide revocations.

## Consequences

Honest supported key arrays and existing partial/full policy inputs keep their results. Malformed restrictions fail closed instead of becoming unchecked or anchored. Previously accepted malformed trust anchors, omitted revocation arrays and unsupported role labels are intentionally refused. An empty valid expected-key array still permits unchecked issuer verification, and a valid empty anchor list yields no trust match.

This validates only issuer matching against the supplied trust inputs. It does not make the policy authoritative, prove an issuer's honesty, establish independence, or authenticate report claims. Signatures still establish integrity and key possession; `authenticated` remains false. Reflection traps can execute during capture, so this is not a JavaScript sandbox. Public credential schemas and core assessment evaluator semantics are unchanged.

## Validation

Six fixed tests cover supported key forms and compatibility, malformed and non-dense expected-key collections, native GET substitution, malformed policy fingerprints/roles/duplicates/bounds, captured policy and revocation views, and status-list issuer checks. On the corrected population, the previous implementation passes one test and fails five; the candidate must pass all six. One initial test asserted the opener's issuer error code instead of the status wrapper's existing public error contract. That assertion was corrected against the unchanged parent `status.mjs`, with the original test and failure retained privately; the refusal expectation was unchanged and both implementations were rerun against the corrected population.

Three syntax-valid mutants omit expected-key membership capture, omit anchor fingerprint validation, or retain live nested policy data after root-field capture. Each must fail the same six-test population with complete execution and no skips, cancellations or TODOs. Existing VC, report-snapshot and status-related regressions run separately. Tests and review remain same-team evidence; outside independent assessment is open.
