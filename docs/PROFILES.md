# Profiles

Status: draft specification of the profile mechanism and registry rules (ADR-0030, Proposed). No profile in this repository has been reviewed by a domain expert.

## 1. What a profile is

A profile is the frozen definition of what is measured. It is a JSON document with schema `kya.profile/v1` and these members, all required: `schema`, `id`, `version`, `title`, `checks`. Each check has `id`, `dimension`, `title`, `weight` and `critical`. The profile fixes the denominator: every check in it counts in the score whether or not evidence exists for it, and an unknown check stays unknown (`docs/SCORING.md`).

A profile has four properties the rest of the system relies on:

1. a **check set**: the list of check identifiers, each in one of the six dimensions;
2. **weights**: a positive integer per check;
3. **critical flags**: a check marked critical blocks the decision when it fails, however high the score;
4. a **scope of use**, stated in the registry metadata (section 5). The profile file itself carries no scope; the scope of a result comes from the manifest and the relying policy.

A profile is not a policy. The relying party chooses thresholds, accepted sources, trusted keys and mandatory minimums in a `kya.policy/v1` document that binds one profile by digest. A policy template (`policies/templates/`) is a starting point over one profile, not a profile.

## 2. Validity rules

These rules are enforced today by `validateProfile` in `src/identity/domain/services/validation.mjs` and are used by `assess` in `src/assessment/application/assess.mjs`. An implementation MUST refuse a profile that breaks any of them.

| Rule | Where enforced |
| :--- | :--- |
| The document is canonicalised first, so duplicate members, accessors, cycles and resource-exhausting input are refused before validation | `canonical` in `src/shared/canonical.mjs` |
| Exactly the members `schema`, `id`, `version`, `title`, `checks`; unknown members are refused | `exactKeys` in `validateProfile` |
| `schema` equals `kya.profile/v1` | `validateProfile` |
| `id` matches `^[A-Za-z0-9][A-Za-z0-9:._/-]*$`, at most 128 characters, no control characters | `identifier` |
| `version` and `title` are non-empty text without control characters (version at most 64, title at most 512) | `text` |
| `checks` is an array with 1 to 256 entries | `validateProfile` |
| Each check has exactly `id`, `dimension`, `title`, `weight`, `critical` | `validateProfile` |
| `dimension` is one of `identity`, `authority`, `security`, `reliability`, `accountability`, `operations` | `DIMENSIONS` |
| `weight` is a safe integer from 1 to 100000 | `validateProfile` |
| `critical` is a boolean | `validateProfile` |
| Check identifiers are unique within the profile | `validateProfile` |
| A policy names the profile by `profileDigest`; assessment is refused if it differs | `assess` ("Policy does not bind this profile") |
| Evidence carries the profile digest; evidence for a different profile, or for a check outside the profile, is rejected | `assess` ("Frozen profile differs", "Evidence check is outside frozen profile") |
| A mandatory minimum may name only a check that exists in the profile | `assess` |

The code does not require that a profile cover every dimension, contain a critical check, or have any particular total weight. A profile that omits a dimension is valid but its scoring then says nothing about that dimension; the registry metadata MUST list the omission under known gaps.

## 3. Digest identity, versioning and freezing

1. A profile's identity is its digest: SHA-256 of the canonical form of the parsed document (`digest` in `src/shared/canonical.mjs`). Two documents with the same digest are the same profile. The `id` and `version` are labels for people.
2. A profile is frozen when it is registered. A frozen profile MUST NOT be edited. Any change to a check, weight, critical flag, title or version produces a new digest and is a new profile version.
3. A new version of an existing `id` gets a new `version` string and a new registry entry. The old entry stays; it may be marked deprecated (section 7). Digests of released profiles are never reused for different content.
4. The evaluator digest for the reference profile binds the profile file bytes as well (`src/conformance/domain/scenarios.mjs`). The registry digest is the canonical-form digest used by policies and evidence, which is a different value from the byte hash in the evaluator descriptor. Neither proves a profile is correct.
5. The repository records each profile digest in `evidence/profile-registry.json`. `node scripts/profile-registry.mjs --check` fails when a profile file changes without the registry changing, and when a file in `profiles/` has no registry metadata.

## 4. Naming and namespacing

Identifiers follow `docs/governance/EXTENSION-REGISTRY.md`, section 2 and 3, as narrowed by the validator in `src/profiles/validate-metadata.mjs`.

1. **Project profiles** (owner kind `project`): the id is `kya-core`, or `core-<name>` in lowercase with `.` and `-` only. These are the only ids that may use a reserved prefix. The reference profile is `kya-core` at version `1.0.0`, shipped as `profiles/core-v1.json`. The extension registry table lists it as `core-v1` after the file name; the id in the document is `kya-core`, and the registry file uses the document id.
2. **Third-party profiles** (owner kind `third-party`): `<namespace>:<name>`. The namespace is a lowercase DNS name the registrant controls (at least two labels). The name is lowercase kebab-case with optional `.`, at most 64 characters. Neither part may start with `kya.`, `kya-`, `core-`, `reference-`, `fixture-` or `local.`.
3. An id is lowercase. Collisions are compared in lowercase. The same lowercase id and version cannot be registered twice. The same digest cannot be registered under two ids.
4. A withdrawn id is retired, not reused.
5. Namespace ownership is claimed, not verified, as in the extension registry.

## 5. Required metadata

Each registry entry is a `kya.profile-metadata/v1` document. All of these are required and unknown members are refused.

| Field | Meaning |
| :--- | :--- |
| `profileId`, `profileVersion`, `profileDigest`, `file` | Binding to the frozen file `profiles/<name>.json` |
| `checkCount`, `criticalCount`, `totalWeight` | Derived from the profile and checked against it |
| `status` | `draft`, `reference`, `deprecated` or `retired` (section 6) |
| `purpose` | What the profile is meant to measure |
| `intendedScope` | The kind of agent, tools and setting it is meant for |
| `knownGaps` | At least one stated limit or omission. A registry entry with no known gaps is refused. |
| `changeLog` | At least one entry (`version`, `date`, `summary`), including one for the registered version |
| `owner` | `kind` (`project` or `third-party`) and `contact`. The contact is the placeholder `<owner-contact-placeholder>` or an https URL; an email address is refused. |
| `signOff` | `null`, or a record with `reviewer`, `role`, `date` and `evidenceDigest` |
| `deprecation` | Present only for deprecated or retired entries: `date`, `reason`, `supersededBy` (an id or `null`) |

The owner contact is a placeholder until a maintainer assigns one. Nothing in this repository names a reviewer.

## 6. Status and what a profile may not claim

| Status | Meaning |
| :--- | :--- |
| `draft` | Proposed. Not reviewed. This is the starting status of every new profile. |
| `reference` | Maintained by the project as the reference used by the evaluator, templates and fixtures. Project profiles only. It is a statement about the repository, not about fitness for any use. |
| `deprecated` | Still valid and verifiable. New use is discouraged. Needs a deprecation record. |
| `retired` | Must not be used for new assessments. Kept so old evidence can be checked. Needs a deprecation record. |

There is deliberately no `approved`, `accepted`, `certified` or `reviewed` status. A status outside the four is refused.

A profile and its metadata MAY NOT claim:

1. that a domain expert has reviewed, signed off or accepted the checks, weights, critical flags or thresholds. Domain-expert sign-off is an outside item (`docs/WORLD-CLASS-PLAN.md`, WS2). Until it exists, every profile is a draft proposal even when its status is `reference`;
2. a sign-off without evidence. `signOff` is `null` unless it names a reviewer, a role, a date and the SHA-256 of the review record. A draft cannot carry one. Prose in `purpose`, `intendedScope` or a change-log summary that says "signed off", "expert reviewed", "certified" or "accepted by" is refused when `signOff` is `null`. The validator checks form, not truth: a well-formed sign-off record shows only that someone wrote it;
3. that a score is a prediction of safety, a credit score or an authorization grant;
4. that fixture or declared evidence scores a commercial product;
5. any change to the core profile, the evaluator identity or `src/conformance/`; an extension may not move evaluator logic or change a critical gate or mandatory minimum of the core profile (`EXTENSION-REGISTRY.md`, section 8).

A profile that overlaps another does not inherit its claims. Results under different profile digests are not comparable (`assess` refuses to compare them).

## 7. Deprecation and retirement

1. The owner sets `status` to `deprecated` and adds a `deprecation` record with a date, a reason and the superseding id, or `null` when none exists.
2. A deprecated profile stays verifiable and its digest stays registered. A policy that binds it keeps working.
3. After a period the registry maintainers choose, the status may become `retired`. A retired profile is not removed and its id is not reused.
4. Deprecation of `kya-core` needs an ADR and the change process in `docs/governance/DECISION-PROCESS.md`, because the evaluator, templates and golden fixtures depend on it.

## 8. Checking

- `node scripts/profile-registry.mjs --check` recomputes every digest and compares the committed registry.
- `validateProfileMetadata(doc, { profile })` and `validateProfileRegistry(registry, { profiles })` in `src/profiles/validate-metadata.mjs` apply sections 3 to 7 and throw on any breach. They fail closed: an unexpected member, a missing field, an unknown status, a digest mismatch, a duplicate id or an unevidenced sign-off all refuse.
- `test/profiles.test.mjs` holds the negative cases.

## 9. Not established

The registry and validator show that a profile is well formed, that its recorded digest matches its bytes and that no sign-off is claimed without a record. They do not show that any check is the right check, that any weight or flag is reasonable, or that any domain expert agrees. The flagship profiles for code agents, agentic payments and read-only assistants do not exist as profiles yet; the three policy templates over `kya-core` are not profiles.
