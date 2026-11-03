# ADR-0049: Capture issuer trust and expected bindings before verification decisions

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0006, ADR-0032, ADR-0046

## Context

`verifyCapture` captured its signed envelope and policy, but consumed an explicit `trustedIssuerKeyIds` array and the `expected` object directly. A synthetic issuer absent from the supplied trust members could be accepted by overriding the array's `includes` method. A Proxy over an expected-binding object containing the wrong scope could vary its GET results: expose the wrong value during the undefined-only check, return undefined during mismatch checking, then return the payload's scope during the `bound` calculation. The verifier returned a valid, bound result usable by the fixture candidate adapter.

These are JavaScript API data-boundary inconsistencies, not demonstrated network/JSON attacks or real-agent compromises. ADR-0006 already requires a captured plain-JSON view for public verification inputs. Signature integrity does not resolve disagreement between an input's captured data and its executable property views.

## Decision

When an explicit issuer list is the active trust source, copy it through the existing canonical JSON boundary before testing array membership. That boundary refuses sparse, extended and accessor-bearing arrays. Membership is then evaluated on the captured plain array; caller-supplied `includes` implementations are never invoked. The existing policy path still validates and derives issuer IDs from the captured policy, and retains its precedence over an explicit list.

Capture expected bindings from their own enumerable data descriptors into a plain object before envelope validation and every comparison. Refuse accessor properties, hidden members, symbol keys and non-plain prototypes. Apply canonical capture to the descriptor values and use the resulting copy throughout unknown-key checks, mismatch checks, complete-binding checks and optional probe-set pinning. A Proxy's property GET view never supplies binding values to those decisions.

Explicit undefined values are retained as a narrow diagnostic exception to plain JSON. Capture them separately while snapshotting the remaining data, then restore them on the private plain copy so `binding-undefined` remains distinct from omission. Unknown keys still yield `binding-unknown`. Omitted bindings preserve valid-but-unbound verification; a full matching set remains required before the adapter accepts the result. Do not infer or fill missing values from the payload.

No capture/evidence schema, evaluator identity, scoring behavior, public assessment vector or claim class changes. Signatures continue to prove integrity and key possession; the fixture cell still provides no real-agent safety, independence or sandbox-isolation claim.

## Alternatives

- Invoke `Array.prototype.includes.call` directly on the supplied list: rejected as incomplete because element GET views could still vary; capture the members first.
- Cache only the last expected value read: rejected because preceding checks and the resulting bound decision would still depend on inconsistent views.
- Reject all undefined values as a generic schema problem: rejected to preserve the explicit established binding diagnostic.
- Infer omitted bindings from the payload: rejected because this would invent relying-party expectations and make incomplete input appear bound.

## Consequences

Normal plain lists, complete matching bindings and partial expectations retain their behavior. Previously accepted extended issuer lists and accessor-bearing expected objects are refused. Plain data represented through a Proxy is consumed from its descriptor snapshot rather than its GET behavior. A wrong captured binding remains a mismatch; a caller-controlled method cannot grant issuer trust. This change does not authenticate a caller's intentions or prove the issuer's measurements truthful.

## Validation

Five frozen tests cover full/partial compatibility and probe pinning; overridden and proxied trust methods; changing expected scope views; benign data GET views and rejected accessors; and existing unknown/undefined/pin-mismatch diagnostics. The previous verifier passes two and fails three; the candidate passes all five. The same tests detect two syntactically valid weakened implementations that independently bypass issuer-list capture and expected-binding capture. Mutation execution requires all five cases to complete with no skips, cancellations or todo cases; syntax errors do not count as detections. Capture, hardening, tool-uniqueness and issuer-role regressions run separately. Evidence is local and same-team; independent review and external acceptance remain unestablished.
