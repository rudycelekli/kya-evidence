# ADR-0024: Governance charter, IPR, claims, versioning, extension registry and decision process

**Status**: Proposed
**Date**: 2026-10-15
**Depends-on**: ADR-0003, ADR-0011, ADR-0021

Review boundary: separate project lane; drafted for counsel review. No counsel has reviewed it, no body has adopted it, and no external review exists. Nothing here is legal advice.

## Context

The project aims at an open protocol that other implementations and assessors could adopt, but it has no written governance. `docs/STANDARDIZATION-STRATEGY.md` lists neutral governance, IPR policy, versioning and an extension registry as missing. `docs/WORLD-CLASS-PLAN.md` (WS4) requires a charter, a contributor policy with DCO, an IPR and trademark policy with a royalty-free patent commitment, a versioning and deprecation policy, a namespaced extension registry and an RFC-style change process. Its verification requires legal review and adoption by at least three independent organisations, which does not exist.

Without written rules, contributors cannot tell which changes need an ADR, how a conformance claim may be worded, how an evaluator change is treated, or how an extension may be named. A future neutral home would have to write these rules from nothing.

## Decision

Add a governance layer under `docs/governance/`, each document marked as a draft for qualified legal counsel:

1. `CHARTER.md` sets purpose and scope from the repository's own statements, the roles, decision rules, conflict-of-interest declarations, the neutral-home selection method (listing the WS4 candidates without choosing any), the amendment procedure and hand-over.
2. `IPR-POLICY.md` keeps Apache-2.0 as the licence, requires a Developer Certificate of Origin sign-off, relies on the Apache-2.0 patent grant, provides a labelled draft royalty-free commitment for essential claims, sets a disclosure duty, covers employer contributions and third-party material, and prohibits customer data, credentials, private code and operational logs, mirroring `AGENTS.md`.
3. `TRADEMARK-AND-CLAIMS.md` permits claims that name requirement IDs and a conformance report, prohibits "certified", "endorsed", "approved by" and "compliant with" wording, and claims no registered mark.
4. `VERSIONING.md` defines semantic versioning per artifact, five stability levels, compatibility rules, announcement and deprecation windows, requirement-ID retirement without reuse, and treats an evaluator digest change as breaking, requiring an ADR, adversarial regression, mutation control, same-case comparison and a migration note.
5. `EXTENSION-REGISTRY.md` defines namespaced identifiers, reserved prefixes, the registry tables, a registration procedure and template, collision handling, and the things an extension may never do.
6. `DECISION-PROCESS.md` defines the RFC and ADR lifecycle (Proposed, Accepted, Implemented, Superseded), discussion windows, review, required acceptance evidence and errata.

`CONTRIBUTING.md` gains the DCO, the test-first expectation, the rule that code under `src/conformance/` changes only with an ADR, and links to these documents. `docs/GOVERNANCE.md` gains cross-links only. `CODE_OF_CONDUCT.md` adapts a widely used covenant, with its enforcement contact left as a placeholder that the owner must set. `test/governance-docs.test.mjs` checks the structure of these files.

No registry entry, requirement, schema, evaluator file or evidence file changes. Requirement proposals are recorded separately in `docs/lane-n-requirements-proposal.json` and are not added to `evidence/requirements.json`.

## Alternatives

Fold the rules into `CONTRIBUTING.md` only. This keeps one file, but mixes contributor instructions with legal and versioning rules that a neutral home would adopt separately.

Adopt an existing charter template without adaptation. This risks wording that claims affiliations or processes the project does not have, and it would not match the protocol's evaluator and evidence rules.

Wait for a neutral home before writing governance. This leaves the project without rules for the period in which outside contributors are most likely to arrive, and it leaves the home with nothing to review.

Write the IPR terms as adopted policy. Counsel has not reviewed them, so they are presented as drafts with the open questions listed.

## Consequences

Contributors have written rules for DCO, claims, extensions and evaluator changes. Reviewers can cite a section when they reject a claim or an extension. A future neutral home has a starting text to amend.

The documents are drafts. They do not create a legal entity, bind any contributor to the royalty-free commitment, or make any claim of adoption. Counsel must decide the open questions listed in each document. The enforcement contact and the quorum are placeholders. The extension registry starts empty. Governance text can drift from practice; the tests here check structure, not that the owner follows the rules.

## Validation

`test/governance-docs.test.mjs` reads the markdown files and asserts:

- every governance document and the code of conduct opens with the draft-counsel notice;
- the notice text is exact on the legal documents;
- `CONTRIBUTING.md` mentions the DCO sign-off and links each governance document;
- `CONTRIBUTING.md` states that code under `src/conformance` needs an ADR;
- every ADR in `docs/adr/` has the five required sections and a Status line;
- this ADR has the Proposed status and the 2026-10-15 date;
- `docs/GOVERNANCE.md` keeps its existing section headings and links the governance documents;
- the governance documents contain no registered-mark symbols;
- the code of conduct has an enforcement placeholder and no email address.

`npm test`, `npm run check` and `npm run adr:index` must pass. The index file is restored after regeneration so that it is not staged.
