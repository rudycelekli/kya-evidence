# ADR-0029: Privacy tooling

**Status**: Proposed
**Date**: 2026-10-15
**Depends-on**: ADR-0014, ADR-0022, ADR-0025

Review boundary: implemented and tested in this repository by the authoring lane only; no independent privacy or cryptographic review, no legal review, no external certification. The scanner patterns are heuristics.

## Context

WS9 asks for privacy to be a testable property. The specification keeps incident records digest-only and the manifest free of personal-data fields, but nothing checks an actual artifact, and nothing says what to do when a field must be proven without being published. A hash of a guessable value is not redaction.

## Decision

1. `scripts/privacy-scan.mjs` is a standalone, deterministic, dependency-free scanner for KYA artifacts. It reports email addresses, phone-shaped numbers, IBANs (mod-97), card numbers (Luhn, first digit 2 to 6), five national-identifier shapes with check digits, IPv4 and IPv6 addresses, home-directory paths and PEM private key blocks, plus structural violations: malformed digest fields, coded identifier fields holding free text, and narrative fields in digest-only record types. It exits 1 on any finding, 2 on usage or read errors (nothing is skipped silently), emits a stable `kya.privacy-scan/v1` report, and never prints a matched value: only file, JSON path, rule, length and a shape mask. Object keys that look like personal data are replaced by `[key:N]` in paths.
2. `--rules pii` runs content rules only. It exists because vector files deliberately contain malformed records as refusal cases; the structural rules would flag those on purpose.
3. `src/privacy/index.mjs` provides `commitField` and `openField`: HMAC-SHA-256 keyed with a secret salt over a domain label, record ID, field name and canonical value, with length prefixes. It is a design reference; no signed record embeds commitments yet and it is not exported from `src/index.mjs`.
4. `docs/PRIVACY.md` records the data flow per artifact, redaction before hashing, retention, selective-disclosure options and limits; `docs/DPIA-TEMPLATE.md` gives deployers a template marked as draft input for a qualified professional.
5. Wiring into package scripts, CI, the requirements registry and the specification is proposed in `docs/lane-t-integration.md`, not done here.

## Alternatives

Regular-expression redaction that rewrites artifacts: rejected, rewriting after signing invalidates the signature and rewriting before signing is a deployer decision the tool cannot make safely. A scanner built on a named-entity model or an external service: rejected, it is not deterministic, needs a dependency or a network call and would itself process the data. Printing matched values to ease triage: rejected, the report would become a copy of the leak. SD-JWT now: deferred, it is the interoperable route for the VC export but needs a format decision and review. Merkle-tree commitments hiding the field count: deferred. Plain unsalted hashes of fields: rejected, guessable. Per-field salts derived from one master secret: deferred, convenient but couples fields.

## Consequences

Accidental leaks of structured identifiers into artifacts become a failing check instead of a review habit. The scanner cannot find names, addresses or free text, skips opaque encoded tokens on purpose, and will flag some benign strings (version-like quads, Luhn-valid digit runs); a clean result is not evidence of absence and the report says so. The commitment helper hides a value only while its salt stays secret, reveals equality when a salt is reused, is not zero-knowledge and is unreviewed. Pseudonymous references remain personal data when re-identifiable. None of this addresses lawful basis, data subject rights or transfers; the DPIA template is a structure for a qualified reviewer, and no such review has happened.

## Validation

`test/privacy.test.mjs` covers every scanner rule with positive and negative cases, structural rules, JSON paths, exit codes, byte-stable output, loud handling of binary files and symbolic links, a check that no raw matched value (including object keys) appears in JSON or text output, a scan of the repository example artifacts and fixtures that must be clean, a scan of the vector files that must raise only the known structural findings, and the commitment helper: round trip, wrong value, wrong salt, other field, other record, framing ambiguity, weak salts and malformed input. Not verified: recall on real data, any privacy review, any cryptographic review of the commitment construction.
