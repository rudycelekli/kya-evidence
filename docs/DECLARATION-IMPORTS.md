# Partial declaration imports

`importDeclarations` reads supported fields into `kya.declaration-import/v1`. It is non-executing and intentionally lossy. Its output is a declaration, with a digest of the complete supplied input and a list of unsupported root fields. It produces no agent score or permission grant and does not validate external identity, legal authority, signatures, credentials, hardware attestation or runtime enforcement.

## Open-KYA authority mapping

A limited read-only comparison used Open-KYA commit [`ba7702398b0368843742d63a4b3b0781cc77f762`](https://github.com/open-kya/kya-standard/commit/ba7702398b0368843742d63a4b3b0781cc77f762). Its [schema](https://github.com/open-kya/kya-standard/blob/ba7702398b0368843742d63a4b3b0781cc77f762/schema/kya-manifest.schema.json) defines `governingAuthority` as an array; its [full example](https://github.com/open-kya/kya-standard/blob/ba7702398b0368843742d63a4b3b0781cc77f762/examples/01-full.json) contains two entries. This field comparison is not a full schema or proof review, independent acceptance or affiliation.

The legacy format label remains `open-kya-alpha`. The importer preserves field spelling and the supplied version string; it does not infer compatibility from that version.

| Supplied `governingAuthority` | `identity.controllerRef` | Unsupported field |
| :--- | :--- | :--- |
| Absent | null | No |
| One bounded string, in an array | That exact string | No |
| A bounded scalar string, for legacy compatibility | That exact string | No |
| Present plural/empty array or another unrepresentable shape | null | `governingAuthority` |

The string bound is 512 UTF-16 code units, matching the existing partial-import bound. Recognized means representable in this partial mapping, not structurally or cryptographically verified. Read `unsupportedFields` and `unverified` alongside the imported values. A plural authority model needs a separate versioned record; this v1 record does not retain the list or silently pick a member. The original `sourceDigest` still binds all source data.

## Reproduce the boundary checks

```sh
node --test test/declaration-authority.test.mjs test/imports.test.mjs
node scripts/declaration-authority-mutations.mjs
```

The cases use locally written synthetic declarations. The mutation control restores three incorrect behaviors and requires the same three frozen tests to detect them. [ADR-0039](adr/0039-declared-governing-authority-import.md) records the compatibility decision. Existing A2A declaration mapping is unchanged. External schema validation, key resolution and proof verification need separate tools and evidence; they are not performed by this API.

## A2A security scheme names

The A2A partial mapping retains names from a non-null object map in `securitySchemes`. It does not emit the map's definitions or credentials or validate those definitions. An empty map yields an empty name array and is representable. An absent field preserves that empty array without an unsupported-field marker.

Arrays, null and other present non-map shapes yield no names and leave `securitySchemes` in `unsupportedFields`; array indices never become scheme names. Maps containing more than 128 names retain the first 128 in the existing canonical key order and also leave `securitySchemes` in `unsupportedFields` to expose truncation. The complete supplied input still determines `sourceDigest`. All unverified flags and limitations remain; imported scheme names establish no security enforcement or authorization.

```sh
node --test test/declaration-schemes.test.mjs test/imports.test.mjs
node scripts/declaration-schemes-mutations.mjs
```

Four frozen synthetic tests and three weakened implementations exercise this mapping boundary. [ADR-0040](adr/0040-declared-security-scheme-map-import.md) records the decision. This correction does not establish full A2A schema conformance or external interoperability acceptance.

## List projections and visible loss

The Open-KYA `permittedDomains`, `permittedRegions` and `forbiddenRegions` projections retain string members at most 256 UTF-16 code units long, in their existing order including duplicates, then retain at most 128 members. Empty strings preserve the existing behavior. A present field remains in `unsupportedFields` if it has a non-array shape, contains an unrepresentable member or has more than 128 input members. Absent optional fields preserve empty arrays without an unsupported marker; empty arrays remain representable.

The A2A `skills` projection retains nonempty string IDs at most 128 UTF-16 code units long, including duplicates, then retains at most 128 IDs. Missing, empty, nonstring or overlong IDs, and lists with more than 128 input members, leave `skills` in `unsupportedFields`. Skill descriptions and other metadata are deliberately outside the ID projection; ignoring that metadata alone does not make the field unsupported. The importer still requires `skills` to be an array.

These markers expose loss while preserving all existing projected values and bounds. No rejected values or skill metadata are emitted. The complete original input still determines `sourceDigest`; every unverified flag and limitation remains. A retained list is not proof of effective permission, restrictions or runtime enforcement, and a partial declaration import is not full external schema validation.

```sh
node --test test/declaration-lists.test.mjs test/imports.test.mjs
node scripts/declaration-list-mutations.mjs
```

Six frozen synthetic tests and four weakened implementations exercise the list-loss boundary. [ADR-0043](adr/0043-declaration-list-loss-reporting.md) records the compatibility decision. The projection bounds and the unsupported-field markers describe this implementation, not independent or external acceptance.
