# Lane T integration proposals (WS9-02 privacy tooling)

For the integration owner. Lane T changed no shared file. Everything below is a proposal; nothing here is applied.

## Files added by this lane

`scripts/privacy-scan.mjs`, `src/privacy/index.mjs`, `docs/PRIVACY.md`, `docs/DPIA-TEMPLATE.md`, `docs/adr/0029-privacy-tooling.md`, `test/privacy.test.mjs`, this file. Nothing under `src/conformance/`.

## package.json scripts

```
"privacy:scan": "node scripts/privacy-scan.mjs examples test/fixtures profiles policies suites",
"privacy:scan:vectors": "node scripts/privacy-scan.mjs --rules pii evidence interop schemas"
```

## CI step (add after `node scripts/check.mjs` in `.github/workflows/ci.yml`)

```
      - run: npm run privacy:scan
      - run: npm run privacy:scan:vectors
```

Exit code 1 (findings) or 2 (error) fails the job. Deployers should point the same command at their own artifact directory before signing and before publishing.

## Requirements registry (`evidence/requirements.json`, then `npm run requirements` to regenerate docs/REQUIREMENTS.md)

All sections below exist as `## <section>` headings in `docs/SPECIFICATION.md`. Proposed area: `privacy`. The existing registry test lists a fixed set of required areas, so adding an area needs no change there (it only asserts the listed areas are non-empty).

| ID | Level | Section | Statement | Tests (file `test/privacy.test.mjs`, exact titles) |
| :--- | :--- | :--- | :--- | :--- |
| KYA-PRV-001 | SHOULD | Records and bindings | A deployer SHOULD scan artifacts for personal-data shapes before signing and before publishing; the scanner MUST NOT print a matched value. | `privacy scan never echoes a raw matched value in any output form`; `privacy scan exit code is 1 on findings, 0 when clean and 2 on usage errors` |
| KYA-PRV-002 | SHOULD | Records and bindings | Identifier and digest fields SHOULD be coded or 64-hex digests; incident, evidence and receipt records SHOULD carry no narrative text. | `privacy scan reports structural violations in coded and digest-only fields` |
| KYA-PRV-003 | SHOULD | Records and bindings | The scanner report SHOULD be deterministic and SHOULD state its false-positive and false-negative limits. | `privacy scan report is byte-stable across runs and input ordering`; `privacy scan documentation states false positives and false negatives and the report carries them` |
| KYA-PRV-004 | MUST | Records and bindings | The repository example artifacts and fixtures MUST scan clean. | `repository example artifacts and golden fixtures scan clean` |
| KYA-PRV-005 | MAY | Records and bindings | A per-field salted commitment helper MAY be used; the commitment MUST be domain separated by record ID and field name and MUST open only with the matching salt and value. | `field commitment opens with the right salt and value and is deterministic for a fixed salt`; `field commitment rejects a wrong value, wrong salt, other field or other record`; `field commitment is domain separated by record ID and field name with unambiguous framing`; `field commitment refuses weak salts, bad names and unsupported values and openField never throws` |

A MUST statement must contain the word MUST (registry rule). Optionally add a sentence under `## Records and bindings` in SPECIFICATION.md referring to docs/PRIVACY.md; the registry only needs the heading to exist.

## docs/CRYPTO-AGILITY.md

`src/privacy/index.mjs` uses HMAC-SHA-256 with a domain label `kya.privacy.field-commitment/v1`. The inventory test in `test/crypto-inventory.test.mjs` passes without change (the label is composed through length prefixes, so it does not match the `\n`-suffixed prefix pattern, and it uses only `sha256`). For completeness add a row to section 1.2 or 1.3 of CRYPTO-AGILITY.md naming the label, the construction and that it is signature-free and unreviewed.

## src/index.mjs and src/index.d.ts

Optional: re-export `commitField` and `openField` from `src/index.mjs` and add declarations. Not done, because the record format that embeds commitments is undefined and exporting would make the helper look supported.

## Other shared files

`docs/WORLD-CLASS-STATUS.md` and `evidence/world-class-status.json`: WS9 can move from Partial toward a recorded "tooling present, review pending" state; the deliverables still open are SD-JWT, retention enforcement, and the external privacy and legal review (EXT). `npm run adr:index` must be re-run so `evidence/adr-index.json` includes ADR-0029. Optionally list the scanner and PRIVACY.md in the README and in `docs/THREAT-MODEL.md` (the "Raw evidence bundles" asset row and the VC bridge row).

## Not verified

No external privacy or legal review, no measurement of recall or precision on real artifacts, scanner patterns are heuristics, the commitment construction has had no cryptographic review, and vector files under `evidence/` are scanned with `--rules pii` only because they intentionally contain malformed records.
