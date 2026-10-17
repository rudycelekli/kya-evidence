> **Draft for review by qualified legal counsel. Not legal advice. Not yet adopted by any body.**

# Versioning, stability and deprecation (draft)

Status: draft, version 0.1 (drafted 2026-10-15). Not adopted. Numbers marked "proposed" are maintainer proposals for review, not commitments.

## 1. What is versioned

| Artifact | Identifier today | Version rule |
| :--- | :--- | :--- |
| Software package | `package.json`, currently `0.1.0-alpha.4` | Semantic versioning (MAJOR.MINOR.PATCH, with pre-release tags) |
| Specification | `docs/SPECIFICATION.md` (no separate number today) | Follows the package version it ships with; a normative change needs an ADR |
| JSON schemas and wire formats | Identifiers such as `kya.evidence/v1`, `kya.assessment/v1`, `kya.campaign-ledger/v1` | The `vN` suffix changes only for a breaking wire change |
| Requirement registry | `evidence/requirements.json`, schema `kya.requirements/v1`, digest shown in `docs/REQUIREMENTS.md` | Digest changes on any change; ID rules in section 5 |
| Evaluator identity | `evidence/evaluator-identity.json`, field `evaluatorDigest` | Digest, not a version number; a change is breaking (section 6) |
| Profiles | `profiles/core-v1.json` | Identifier includes the version; a new profile version is a new identifier |
| Extension identifiers | See `EXTENSION-REGISTRY.md` | Registered once; never silently changed |

Software semantic versions and wire-format versions are separate. A package release may keep a wire format unchanged. A wire-format break must bump its `vN` and must not be hidden inside a package patch.

## 2. Stability levels

Every specification item, schema, profile and interface carries one of five levels. The level is written next to the item and in the relevant ADR.

| Level | Meaning | Change rule |
| :--- | :--- | :--- |
| Experimental | May change or be removed in any release. Not a basis for conformance claims. | No deprecation window |
| Candidate | Proposed for stable. Has tests, at least one ADR and a named editor. | Changes need an ADR; claims must name the version |
| Stable | Relied on by implementers. | Compatible changes only in minor or patch releases; breaking changes follow section 4 |
| Deprecated | Still works. A replacement is named and a retirement date or version is set. | No new uses; behaviour frozen except for security fixes |
| Retired | Removed. The identifier stays allocated and is never reused. | Listed in a tombstone list with the replacement, if any |

Promotion from candidate to stable needs an ADR that cites the evidence in `DECISION-PROCESS.md` (section 4) and a same-case comparison where scoring is involved.

## 3. Compatibility rules

1. **Strictness.** The parsers in this project reject unknown members in the signed records described in ADR-0021 and related ADRs. Treat any added field as a breaking change unless the specification defines an explicit extension point for it.
2. **Additive changes.** A new optional field, a new enumeration value or a new requirement is compatible only if every verifier that claims the current version rejects it safely, and the change does not weaken a MUST. Otherwise it needs a new `vN`.
3. **Narrowing.** Removing an accepted value, tightening a MUST or changing the meaning of an existing field is breaking.
4. **Security fixes.** A fix that closes a bypass may change behaviour in a patch release, provided the release notes name the affected version range and the fix comes with a regression test.
5. **Digest changes.** A change to any byte that feeds a published digest is breaking for every record that binds that digest. Such records are not silently revalidated.

## 4. Breaking-change announcements and deprecation windows

1. A breaking change to a stable item is announced in an ADR and in the release notes before release. The notice names the affected items, the reason, the migration path and the first version that breaks.
2. Proposed deprecation window for stable items: at least two minor releases or six months, whichever is longer. Counsel and the maintainers should confirm this number.
3. Experimental items have no window. Candidate items have a window only when they have been relied on by a published conformance report.
4. During the pre-1.0 period, the package may break between minor versions. Every such break must still be announced under section 4.1.
5. Security-driven removals may skip the window. The ADR must state why.

## 5. Requirement identifiers

1. IDs take the form `KYA-<AREA>-<NNN>`. A new obligation takes the next free number in its area.
2. IDs are never reused, renumbered or moved to another area.
3. A requirement is retired only by a new ADR. The ADR names the removed obligation and the reason. The retired ID stays allocated.
4. The generator in `scripts/requirements.mjs` has no retired status today. A retirement therefore also changes the traceability gate in the same ADR, as `docs/GOVERNANCE.md` requires.
5. A changed statement with the same obligation keeps the ID. A changed obligation that is no longer the same as the old one is a new ID, plus a retirement of the old one.
6. The registry digest changes with the registry. A conformance claim names the digest it was made under (see `TRADEMARK-AND-CLAIMS.md`).

## 6. Evaluator identity changes are breaking

`evidence/evaluator-identity.json` pins the digest of the evaluator, which is the source under `src/conformance/` together with its descriptor. Evidence issued under an old evaluator digest is bound to that digest and does not inherit the new one. A change to that digest is therefore a breaking change, and it follows these steps in the same change:

1. A substantive ADR that states the purpose of the change, its effect on scores and verdicts and the claims that become stale.
2. An adversarial regression test and a mutation control that fails when the weakened gate is restored (as `AGENTS.md` requires).
3. A same-case comparison of baseline and candidate on identical frozen cases. Expected outputs are not edited to match the candidate.
4. The update to `evidence/evaluator-identity.json`, in the same change and only with the ADR.
5. A migration note that lists which evidence and assessments are now stale, how relying parties re-run them, and which conformance reports must be reproduced.
6. Release labelling: a stable item's evaluator change is a major version change, and a pre-1.0 change is at least a minor version with the migration note.

Code that is not evaluator logic must move out of `src/conformance/` rather than change the digest.

## 7. Hand-over of versions

If the project moves to a neutral home, the identifiers, the retired-ID list and the evaluator digest history move with it. The new home does not renumber any identifier.

See also: `EXTENSION-REGISTRY.md`, `DECISION-PROCESS.md`, `CHARTER.md`, `../CONFORMANCE.md`, `../REQUIREMENTS.md`.
