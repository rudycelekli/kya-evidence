# ADR-0039: Preserve representable governing-authority declarations and expose loss

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0002, ADR-0012

## Context

A read-only review of Open-KYA commit `ba7702398b0368843742d63a4b3b0781cc77f762` found that its schema models `governingAuthority` as an array. Its published full example has two entries. Our partial declaration importer treated that field as a scalar string, so the array became null while the field still disappeared from `unsupportedFields`. That concealed an unmapped declaration. The importer does not validate the whole upstream schema or its cryptographic proofs.

Sources: [pinned schema](https://github.com/open-kya/kya-standard/blob/ba7702398b0368843742d63a4b3b0781cc77f762/schema/kya-manifest.schema.json), [full example](https://github.com/open-kya/kya-standard/blob/ba7702398b0368843742d63a4b3b0781cc77f762/examples/01-full.json), [upstream README](https://github.com/open-kya/kya-standard/blob/ba7702398b0368843742d63a4b3b0781cc77f762/README.md). The README describes an incubation alpha while the example carries `kyaVersion: 1.1.0`; this review does not reconcile those version labels or claim official compatibility. No upstream code or example data is copied into the tests.

## Decision

Keep `kya.declaration-import/v1` and its singular nullable `identity.controllerRef`. Map a one-element array containing a bounded string to that exact string. Preserve the previous bounded scalar-string behavior for compatibility. Do not normalize, resolve or authenticate the identifier.

Only mark `governingAuthority` recognized when its declaration is retained. Present plural arrays, empty arrays and other unrepresentable shapes leave `controllerRef` null and appear in `unsupportedFields`. Do not choose the first element, concatenate identities or assert a sole authority. The complete original declaration still determines `sourceDigest`.

Retain all existing unverified flags and limitations. No score, permission, controller consent, legal authority or cryptographic validation is created. The A2A branch and assessment/evaluator semantics are unchanged.

## Alternatives

- Pick the first member of a plural array: rejected; that hides other declared authorities.
- Join the members into a string: rejected; that invents an identifier.
- Add a plural identity field to the existing record: deferred; that changes the record shape and needs a separate versioned decision.
- Keep every authority array silently unmapped: rejected because even loss should be inspectable.

## Consequences

Consumers see more accurate partial declarations. A singleton array can now populate the existing field; unsupported present shapes become explicit. The source digest is unchanged for identical inputs. Consumers that snapshot the entire imported output may see this deliberate correction and should read unsupported fields. Multiple authorities remain unrepresented in v1, and neither the source nor its mapping is an authorization grant. Full schema conformance, external interoperability acceptance and independent review remain unestablished.

## Validation

Three frozen tests cover singleton retention, plural/malformed loss reporting and legacy/absent compatibility. The previous importer passes one and fails two; the candidate passes all three. Three syntactically valid weakened variants remove singleton support, choose the first plural member or conceal unsupported shapes; the same test population must detect all of them. Existing import and claim-boundary tests run separately. A private probe of the pinned public full example confirms the unsupported-field flag changes from absent to present for its two-authority array; no external proof or credential is validated. Upstream files remain read-only inputs and are not republished.
