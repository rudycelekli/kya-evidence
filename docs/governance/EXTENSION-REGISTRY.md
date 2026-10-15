> **Draft for review by qualified legal counsel. Not legal advice. Not yet adopted by any body.**

# Extension registry (draft)

Status: draft, version 0.1 (drafted 2026-10-15). Not adopted. The registry is empty for third parties. Registering an entry is not an endorsement by the project or by any body.

## 1. Purpose

Extensions let implementers and use cases add profiles, check identifiers, incident kinds, anchor roles and verifiable-credential fields without changing the core. The registry gives each extension a stable, namespaced identifier, a documented meaning and a clear limit on what it may do.

## 2. Identifier form

1. An extension identifier has the form `<namespace>:<name>`.
2. `<namespace>` is a lowercase DNS name that the registrant controls, for example `registrant.example`. The registry checks the claim but does not verify ownership of the name.
3. `<name>` is lowercase kebab-case, with optional `.` separators, at most 64 characters, and no spaces.
4. A version, where needed, is a separate field in the registry entry, not part of the identifier.

Identifiers are case-sensitive in storage and compared in lowercase for collision checks.

## 3. Reserved prefixes

| Prefix or pattern | Owner | Use |
| :--- | :--- | :--- |
| `kya.` | Project | Core wire-format identifiers, such as `kya.evidence/v1`. Never used by extensions. |
| `KYA-` | Project | Requirement IDs in the registry. Never used by extensions. |
| `core-` | Project | Profiles shipped with the repository, such as `core-v1`. |
| `reference-`, `fixture-` | Project | Reference and fixture material. Never a basis for a score. |
| `local.` | Anyone | Unregistered local use. Must not appear in published evidence as an interoperable identifier. |

A registry entry may not use a reserved prefix. A request to do so is refused.

## 4. Registry tables

The tables list what is registered. The core items are shown for reference and cannot be changed by an extension.

### 4.1 Profiles

| Identifier | Status | Notes |
| :--- | :--- | :--- |
| `kya-core` | Core, reserved | Document id of the profile shipped in `profiles/core-v1.json`; see [PROFILES.md](../PROFILES.md) |
| (none registered) | | |

### 4.2 Check identifiers

No third-party check identifiers are registered. Core check identifiers are defined by the suites and the specification. An extension check may add evidence for a scored question only through a profile that is registered and reviewed under section 5.

### 4.3 Incident kinds

| Identifier | Status | Notes |
| :--- | :--- | :--- |
| `report`, `resolution`, `appeal` | Core, reserved | Defined in `schemas/incident.schema.json`. Extensions cannot add a kind that changes how a resolution or appeal is read. |
| (none registered) | | |

### 4.4 Anchor roles

| Identifier | Status | Notes |
| :--- | :--- | :--- |
| `self` | Core, reserved | Receipts and proofs cannot assign it |
| `independent` | Core, reserved | Assigned only by a relying party's policy |
| `capture-issuer` | Core, reserved | Signs campaign plans and ledgers, never counts as an evidence issuer (ADR-0021) |
| `calibrator`, `anchor-operator` | Approved, not yet added | Not in code until ADR-0019 and ADR-0020 are implemented |

No extension may add an anchor role. A role changes who may sign for scoring, so it is a core change under `DECISION-PROCESS.md`.

### 4.5 Verifiable-credential fields

| Identifier | Status | Notes |
| :--- | :--- | :--- |
| (none registered) | | The export bridge is described in ADR-0022 and `docs/VC-BRIDGE.md`. |

Fields in the bridge output are mapped by the bridge. An extension may add a field only under a namespace and must not change the meaning of a mapped core field.

## 5. Registration procedure

1. **Draft.** The registrant fills in the template in section 6 and opens a proposal following `DECISION-PROCESS.md`.
2. **Screen.** A maintainer checks the namespace form, the reserved prefixes, collisions (section 7) and the prohibitions (section 8).
3. **Review.** At least one maintainer who did not author the entry reviews its semantics. Counsel reviews any entry that involves a naming, trademark or third-party claim.
4. **Record.** An accepted entry is added to the table with a date and status. A refused entry is recorded with its reason.
5. **Maintain.** The registrant may deprecate or withdraw an entry. A withdrawn identifier is retired, not reused.

Acceptance means the entry is well-formed and does not conflict with the core. It does not mean the extension is correct, safe or useful.

## 6. Registration template

Copy this template into the proposal.

| Field | Content |
| :--- | :--- |
| Identifier | `<namespace>:<name>` |
| Kind | profile, check, incident kind, anchor role (not accepted), or VC field |
| Registrant | Name of the person or body, and the namespace it controls |
| Contact | A URL or a maintainer-approved channel. Do not put personal email addresses in the registry. |
| Version | Version of the extension |
| Description | What the extension means, in no more than five sentences |
| Normative effect | `none` (informational) or the core requirement IDs it relies on. It may not add a MUST to the core. |
| Evidence required | Which signed records, classes and tests the extension needs |
| Conformance impact | Whether a conformance claim may mention it, and under which requirement IDs |
| Vectors or tests | Locations of tests or vectors that show the extension is well-formed and refused when malformed |
| Limits | What the extension does not establish |
| Status and date | Proposed, accepted, deprecated or withdrawn, with the date |
| Supersedes | Identifier replaced, if any |

## 7. Collision handling

1. Two registrations with the same lowercase identifier: the first accepted registration keeps the identifier. The later proposal is refused and must rename.
2. Two extensions with different identifiers and the same meaning are not merged automatically. A maintainer may record an equivalence note. Neither is removed.
3. A registrant may not claim an identifier from another namespace in a later proposal to take it over.
4. A dispute over a registration follows the appeal and dispute steps in `DECISION-PROCESS.md`. The registry does not decide ownership of names.
5. A collision with a reserved prefix, or with a core identifier, is refused without a hearing.

## 8. What an extension may never do

An extension, however registered, may not:

1. override or redefine core semantics, including the meaning of `kya.*` records, digests and signatures;
2. weaken a MUST, or turn a MUST NOT into a permission;
3. alter fixed-denominator rules: every frozen check stays in the denominator, and unknown checks stay unknown (`docs/SCORING.md`);
4. count a declaration, a fixture or an unexecuted check as a pass;
5. grant or assign a role, including `self`, `independent` or `capture-issuer`;
6. change the evaluator digest, or move evaluator logic outside `src/conformance/`;
7. raise, lower or waive a critical gate or a mandatory minimum in the core profile;
8. present an extension result as a core conformance result;
9. collect personal data as a required field, or change the data-minimisation rules.

Any entry that appears to do one of these is refused, and a maintainer may withdraw an accepted entry that does so.

See also: `VERSIONING.md`, `DECISION-PROCESS.md`, `TRADEMARK-AND-CLAIMS.md`, `CHARTER.md`, `../SCORING.md`, `../CONFORMANCE.md`.
