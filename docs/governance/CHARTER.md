> **Draft for review by qualified legal counsel. Not legal advice. Not yet adopted by any body.**

# KYA Evidence governance charter

Status: draft charter, version 0.1 (drafted 2026-10-15). No body has adopted this charter. No organisation has agreed to host the project, and no ratification, endorsement or affiliation exists.

## 1. Purpose

KYA Evidence is a reference implementation of an open protocol for signed evidence about an exact agent configuration, and for policy-relative assessment of that evidence. The repository states the aim: an open protocol that many implementations and independent assessors can use. A single score provider should not silently control the meaning of agent assessments.

This charter sets out who may propose, decide, implement and assess changes, how those decisions are made and recorded, and how stewardship could pass to a neutral home. It describes the project as it is today. It does not create a legal entity.

## 2. Scope

In scope:

- the normative specification (`docs/SPECIFICATION.md`) and the JSON schemas under `schemas/`;
- the requirement registry (`evidence/requirements.json`) and its generated document (`docs/REQUIREMENTS.md`);
- the conformance suite, golden vectors and conformance report format (`docs/CONFORMANCE.md`);
- the evaluator under `src/conformance/`, pinned by `evidence/evaluator-identity.json`;
- profiles, the extension registry and these governance documents.

Out of scope:

- deciding what any relying party accepts as trustworthy (relying parties hold their own policies and trust anchors);
- authorising any agent to act, or granting any person authority;
- scoring people, or ranking commercial products without authorised runs.

## 3. Roles

A role is a function, not a title. One person may hold several roles, but must declare them (section 6).

| Role | Responsibility | Limits |
| :--- | :--- | :--- |
| Editor | Drafts and maintains specification and governance text; keeps wording consistent with the registry | Cannot accept a normative change alone |
| Maintainer | Reviews protocol meaning, evaluator changes and corrections; approves ADRs for acceptance | Cannot approve own proposal as the only reviewer |
| Implementer | Builds an independent implementation and reports conformance against published vectors | Claims are limited to the requirement IDs passed (see TRADEMARK-AND-CLAIMS) |
| Assessor | Runs assessments and independent reviews, and challenges evaluator quality | Must declare conflicts; an assessment never grants authority |
| Relying party | Sets its own policy, trust anchors and acceptance rules | Its policy binds only itself |
| Observer | Reads, comments and may file issues | No decision weight |

The repository owner retains merge, publication and deployment authority, as stated in `docs/GOVERNANCE.md`. This authority is administrative. It does not override a recorded objection on protocol meaning, and it does not waive a failed test or a digest mismatch.

## 4. Decision rules

1. **Consensus first.** Proposals are discussed in the open under the window in `DECISION-PROCESS.md`. The aim is that no maintainer holds a reasoned, unresolved objection.
2. **Objections.** An objection states the requirement, interface or claim it affects and a concrete reason. The proposer must answer it in writing. An answered objection stays on the record. An objection to a MUST-level requirement, a critical gate or an evaluator change blocks acceptance until it is resolved or the proposal is changed.
3. **Tie-break.** If consensus is not reached when the window closes, maintainers decide by a majority of the active maintainers, with reasons recorded. If the vote is tied, the proposal is not accepted. The existing text remains in force.
4. **No override of evidence.** No decision may change a frozen case, an expected output or a digest to make a candidate pass.
5. **Recording.** Every decision is recorded in an ADR with its status, date, reasons, dissent and the evidence relied on.

## 5. Quorum and active maintainers

Quorum and the list of active maintainers are not yet defined, because the project has a single maintainer-led team. Counsel and the owner should set them before any multi-organisation governance begins. Until then, the tie-break in section 4.3 applies to whoever is listed as an active maintainer in the repository.

## 6. Conflicts of interest

- Each editor, maintainer and assessor declares, in writing and before voting or reviewing, any employment, funding, ownership, contract or other interest in a product, agent, competitor or assessed subject that could reasonably affect the decision.
- A person with a declared conflict on a decision does not vote on it. The conflict and the recusal are recorded in the ADR.
- Assessors may not assess a subject they own, operate, fund or have advised, and may not review their own evaluator change.
- No signed conflict-of-interest register exists yet. Building one is a named deliverable (WS8 in `docs/WORLD-CLASS-PLAN.md`).

## 7. Choosing a neutral home

The project has not chosen a neutral home, has not approached any home for adoption, and has no agreement with one. The options listed in the world-class plan (WS4) are candidates for evaluation only:

- a W3C Community Group;
- a Decentralized Identity Foundation working group;
- a foundation-hosted project.

Selection needs a written decision matrix with criteria for IPR terms, neutrality of control, cost, fit with the protocol's scope and exit rights. The matrix is drafted in a later ADR. The selection itself is a decision of the maintainers recorded under sections 4 and 6, and it needs counsel's review of any hosting agreement.

## 8. Amendment procedure

1. A charter amendment is proposed as an ADR that quotes the changed clause and states the reason.
2. The amendment follows the discussion window and the decision rules in section 4.
3. Counsel reviews any change to roles, decision authority, IPR terms or the neutral-home process before acceptance.
4. The charter records its version and date. Earlier versions stay in the repository history.

## 9. Hand-over to a successor body

If stewardship moves to a neutral home:

1. The successor body receives the repository, the requirement registry, the identifier allocations (including retired IDs), the extension registry and the decision records.
2. The Apache-2.0 licence and the DCO sign-off requirement continue to apply to contributions made after hand-over. Earlier contributions keep the terms under which they were made.
3. Existing evidence and assessments are not rewritten. Their digests and the evaluator digest they bind to remain valid as recorded. Any change is a new, linked record (see `VERSIONING.md`).
4. Open proposals are transferred with their discussion record or closed with a stated status.
5. The outgoing team publishes a transition note listing what moved, what did not and the open questions.
6. Trademark rights, if any are ever registered, are transferred only under a written instrument reviewed by counsel (see `TRADEMARK-AND-CLAIMS.md`).

## 10. Open questions for counsel

- Whether a corporate contribution agreement is needed beyond the DCO sign-off.
- Which body, if any, holds the name, and whether any registration should be sought.
- Quorum, maintainer appointment and removal, and the term of office.
- The governing law and dispute venue for any hosting agreement.

See also: `IPR-POLICY.md`, `TRADEMARK-AND-CLAIMS.md`, `VERSIONING.md`, `EXTENSION-REGISTRY.md`, `DECISION-PROCESS.md`, `../GOVERNANCE.md`, `../../CONTRIBUTING.md`.
