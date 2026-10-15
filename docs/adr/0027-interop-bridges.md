# ADR-0027: Interop bridges for in-toto, OpenTelemetry, OAuth and SPIFFE, A2A and MCP

**Status**: Proposed
**Date**: 2026-10-14
**Depends-on**: ADR-0002, ADR-0003, ADR-0013, ADR-0016, ADR-0022

Review boundary: separate project lane; no external review, no third-party tool consumed any output, no conformance claim with any outside specification.

## Context

WS6 of the world-class plan asks for bindings into the ecosystems that incumbents already use: supply-chain attestations, telemetry, workload and token identity, and agent discovery. ADR-0022 covers W3C Verifiable Credentials with a signed export. The remaining targets differ from it: they mostly carry a result as data inside someone else's envelope, so a signature of our own would add little and a wrong claim of compatibility would add risk. What must survive the trip is the same: an assessment is not an authorization grant, its checksum is unauthenticated, fixture evidence must stay visible, and a result must not read as good after the manifest, policy or clock has moved on.

## Decision

1. New package `src/interop-bridges/` (zero dependencies, no network, no clock default). It is not under `src/conformance/`; the evaluator identity digest is unaffected.
2. Six unsigned exports: an in-toto Statement v1 with subject equal to the manifest digest and a project-chosen predicate type URN; a plain OpenTelemetry-style attribute map with a documented table; an OAuth 2.0 claims map under one private claim; a SPIFFE binding record; an A2A agent-card extension entry; MCP `_meta` members. None is signed, none builds a token, none fetches anything.
3. A shared gate runs before every export: it verifies the report checksum, requires a `qualified` decision and a passing currency check at an explicit `now`, and fails closed (`NOT_QUALIFIED`, `NOT_CURRENT`, `CURRENCY_NOT_CHECKED`, `CURRENCY_INPUTS_INCOMPLETE`) unless the caller passes `allowNonQualified` or `allowNotCurrent`. Used overrides are recorded in the output; `qualified` is true only if a currency check ran and passed.
4. Output is KYA canonical JSON plus a newline, byte for byte reproducible. Every export lists its limits and a fixed not-asserted list, carries no principal or agent name, and cannot have its evidence mode set by the caller.
5. A report-style cross-check (`verifyBridgeExport`) rebuilds each export from the source report with the exporter's own construction and compares the whole object. Without currency inputs it cannot see a forged currency block; that is stated in the result and in the docs, and the check can re-run currency when given them.
6. The SPIFFE record and the OAuth claim are associations asserted by the builder; they do not prove that a workload runs the assessed manifest. A2A and MCP pointers bind by digest; the URL is an unfetched hint and `required` is false.
7. Names this project invents (predicate URN, `kya.` attribute names, `kya` claim, `dev.kya-evidence/assessment` meta key, `urn:kya:extension:assessment:v1`) are proposals, not registrations.
8. The CLI lives only in `scripts/kya-bridge.mjs`. Shared files (package scripts, requirements, specification, CI) are not edited by this change; proposals are in `docs/lane-q-integration.md`.

## Alternatives

Wrapping the in-toto Statement in a signed DSSE envelope or emitting JWTs would make the output look more finished, but this project has no key policy for those formats and a signature adds no truthfulness. The caller can wrap the statement with their own tooling. Depending on an OpenTelemetry package was rejected to stay dependency free; a plain map is enough to attach to a span, log or metric. Putting the assessment into a SPIFFE SVID, or minting SVID-bound tokens, would blur the line between identity and assessment and imply a binding that nothing here verifies. A single generic format for all targets was rejected because each ecosystem has its own shape. Defaulting to the system clock or silently allowing non-current exports would make the same inputs give different bytes and let a stale result circulate, so there is no default clock and the overrides are explicit and recorded.

## Consequences

KYA results can be attached to attestations, telemetry, tokens, workload registrations and agent metadata with the honesty limits intact and with a way for a recipient holding the report to check consistency. Cost: the exporting party must supply manifest, policy and a clock, and an export is a snapshot; the embedded currency block ages. Claim ceiling: an export shows what one run of this code derived from one report at one time. It does not show that any other tool understands it, that the report is authentic or truthful, that a workload is the assessed agent, or that anything is authorized. Because outside consumption is unverified, the ADR stays Proposed until at least one third-party tool or specification maintainer has consumed or reviewed each format.

## Validation

`test/interop-bridges.test.mjs` covers: in-toto shape and manifest-digest subject; predicate content; attribute names and value types against the documented table, kept in sync with `docs/INTEROP-BRIDGES.md`; OAuth claim shape with no reserved token members; SPIFFE binding digest and rejection of fifteen malformed IDs; A2A and MCP pointers; https-only URLs; byte reproducibility across input key order; limits present and no identity leakage or signature; fail-closed refusal for non-qualified, expired, aged, changed-manifest, changed-policy, revoked and not-yet-assessed cases, missing and partial currency inputs; recorded overrides and `qualified` false under override; unknown options, non-boolean flags and tampered reports; cross-check acceptance, per-kind forged-member detection, injected and dropped members, the documented blind spot for a forged currency block and its detection on recheck, junk input never throwing; a source scan for network, signing and clock use; and the CLI end to end including exit code 2 refusals. Not validated: any consumption by an outside tool.
