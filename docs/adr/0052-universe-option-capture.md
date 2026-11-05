# ADR-0052: Capture universe options before destructuring

**Status**: Implemented locally; same-team review pending
**Date**: 2026-11-05
**Related**: ADR-0006

## Context

The research universe constructor captured nested inputs but destructured its outer SDK options first. An enumerable getter could run before validation, and a Proxy GET view could substitute a valid question for an invalid own data value. The resulting universe replayed consistently, but its recorded question did not reflect the descriptor view accepted by canonical JSON. Inherited option values were also accepted. This violates the existing SDK capture boundary.

## Decision

Canonicalize and parse the complete options wrapper before destructuring or applying optional defaults. Use the existing strict JSON snapshot mechanism. Nested validation, assessment and universe digest generation remain in place. A regular JSON options object with omitted optional members retains defaults. Explicit undefined members and executable or non-JSON wrappers are refused, consistent with the JSON boundary contract.

## Alternatives

Capturing nested values after destructuring leaves the initial GET substitutions intact. Reading options twice permits inconsistent views. A new custom serializer would duplicate the existing canonical validation contract.

## Consequences

Descriptor-backed data is validated before assessment. This does not sandbox Proxy traps on reflection operations, authenticate the question, prove execution truth, or establish outside independent review. Assessor source binding changes with the implementation bytes; replay of earlier snapshots requires their archived implementation as before. Callers using executable wrappers must supply plain JSON data.

## Validation

Four cases were frozen before implementation: normal options/defaults/replay, a question getter, a Proxy GET laundering an invalid own question, and inherited options. The baseline passed one and failed three. The candidate passed all four and the existing thirty universe tests. An actual weakened implementation removing the wrapper snapshot passed one and failed three on those same frozen cases. These are synthetic SDK boundary controls, not live agent qualification. Full regression and separate same-team review are recorded separately before promotion.
