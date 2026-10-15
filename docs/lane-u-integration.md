# Lane U integration proposals (WS2-03 profile specification and registry)

Shared files were not edited. The integration owner decides what to apply.

## 1. Requirements

Proposed entries for `evidence/requirements.json` (and rows in `docs/REQUIREMENTS.md`). Each section below exists as a `## <section>` heading in `docs/SPECIFICATION.md`. Titles are copied exactly from `test/profiles.test.mjs`.

| ID | Level | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- |
| KYA-PRF-001 | MUST | Records and bindings | A profile's identity MUST be the digest of its canonical form, and a registry entry whose digest differs from the profile bytes MUST be refused. | `a digest mismatch between metadata and the profile is refused`; `a profile edited after registration no longer matches its recorded digest`; `the registry digest for the core profile is recomputed from the frozen file` |
| KYA-PRF-002 | MUST | Interoperability and versioning | A registry MUST NOT list the same profile id and version twice, MUST NOT list one digest under two ids, and MUST refuse ids that break the naming and reserved-prefix rules. | `a duplicate profile id and version in the registry is refused`; `the same digest under another id is refused`; `an id differing only by case collides with an existing id`; `profile id naming and namespace rules` |
| KYA-PRF-003 | MUST | Governance documents | Profile metadata MUST state known gaps, a change log, an owner and a purpose; an entry missing any of them, with an unknown status, or with unknown members MUST be refused. | `a missing known gaps field is refused`; `an empty known gaps list is refused`; `a missing change log or owner or purpose is refused`; `an unknown status is refused`; `unknown extra fields and a wrong schema are refused` |
| KYA-PRF-004 | MUST NOT | Governance documents | A profile entry MUST NOT claim review or sign-off without a sign-off record carrying reviewer, role, date and evidence digest, and a draft MUST NOT carry one. | `a sign-off object without evidence fields is refused`; `a sign-off with a malformed evidence digest is refused`; `a draft profile cannot carry a sign-off`; `prose claiming expert sign-off without evidence is refused`; `every registry entry is draft or reference with no sign-off set` |
| KYA-PRF-005 | SHOULD | Governance documents | The committed profile registry SHOULD match the generator output, and every policy template SHOULD target a registered profile. | `the committed profile registry matches the generator byte for byte`; `every policy template targets a registered profile id` |

The `KYA-PRF` area prefix is new; the registry generator (`scripts/requirements.mjs`) may need the area added.

## 2. package.json scripts

```json
"profiles:registry": "node scripts/profile-registry.mjs",
"profiles:registry:check": "node scripts/profile-registry.mjs --check"
```

`docs/PROFILES.md`, `src/profiles/` and `evidence/` are already covered by the package `files` list.

## 3. CI step

In `.github/workflows/ci.yml`, next to the other drift checks (for example after `node scripts/adr-index.mjs`):

```yaml
      - run: node scripts/profile-registry.mjs --check
```

## 4. Other shared files

- `docs/governance/EXTENSION-REGISTRY.md` section 4.1: the core row reads `core-v1`; the document id is `kya-core` (file `profiles/core-v1.json`). Align the table and add a pointer to `docs/PROFILES.md`.
- `evidence/adr-index.json`: regenerate with `node scripts/adr-index.mjs` to include ADR-0030.
- `evidence/world-class-status.json` (WS2): the profile specification and registry rules exist; flagship profiles and domain-expert sign-off do not. Do not mark WS2 done.
- `scripts/check.mjs` required artifacts: optionally add `docs/PROFILES.md`.

## 5. Not verified

No domain expert has reviewed any profile, check, weight or flag. `kya-core` is labelled `reference` for repository maturity only. The three flagship profiles do not exist; policy templates over `kya-core` are not profiles. The validator checks the form of a sign-off record, not whether a review happened.
