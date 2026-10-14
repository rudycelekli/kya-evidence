> **Draft for review by qualified legal counsel. Not legal advice. Not yet adopted by any body.**

# Decision process: proposals, ADRs and errata (draft)

Status: draft, version 0.1 (drafted 2026-10-15). Not adopted. The numeric windows and reviewer counts are maintainer proposals for review.

## 1. Records

Each decision that changes the specification, schemas, registry, evaluator, profiles, extension registry or governance is recorded as an Architecture Decision Record in `docs/adr/`. An ADR is a Markdown file named `NNNN-short-title.md`, numbered from the next free number. The next free number after this draft is 0025.

Every ADR has:

- a title line `# ADR-NNNN: <title>`;
- a `**Status**:` line;
- a `**Date**:` line;
- optional `**Depends-on**:` and a review-boundary line stating what review occurred;
- the five required sections: `## Context`, `## Decision`, `## Alternatives`, `## Consequences` and `## Validation`.

`npm run adr:index` checks these sections and writes an index. The index is generated, so a change to an ADR is reflected by regenerating it in the same change.

## 2. Lifecycle

| Status | Meaning | Who sets it |
| :--- | :--- | :--- |
| Proposed | Written and open for discussion or review. No decision yet. | Author |
| Accepted | Maintainers decided to make the change, and the acceptance evidence in section 4 is attached. The code may not exist yet. | Maintainers, recorded with reasons |
| Implemented | The change exists in the repository, with tests, and the implementation commit and test output are recorded. | Maintainers, after verification |
| Superseded | A later ADR replaces this one. The old record is kept, with a link to its successor. | Maintainers, in the successor ADR |

Transitions:

- Proposed to Accepted, when the discussion window and review in section 3 have closed and the decision rules in `CHARTER.md` have been applied.
- Accepted to Implemented, when the code, tests and controls in section 4 exist.
- Any status to Superseded, by a later ADR that names the record it replaces.
- A proposal that is not pursued stays Proposed with a closing note, or is superseded by a record that rejects it. A separate Rejected status is an open question for counsel and the maintainers.

`Implemented` means that code exists. It does not mean that anyone independent has accepted the change (`docs/GOVERNANCE.md`).

## 3. Proposal, discussion and review

1. **Proposal.** The author opens a Proposed ADR. It states the problem, the decision sought, the alternatives and the expected effect on conformance claims and evaluator digests.
2. **Discussion window.** Proposed windows, to be confirmed: at least 14 calendar days for a change to normative text, the registry, a schema or the evaluator, and at least 5 calendar days for an editorial change. The window is open to all contributors and observers.
3. **Review.** At least one maintainer who did not write the change reviews it. An evaluator or scoring change needs a second review by a maintainer or assessor with no declared conflict. A governance, IPR, trademark or privacy change needs counsel's review before acceptance.
4. **Objections.** Objections follow the rules in `CHARTER.md` section 4. An unanswered objection to a MUST, a critical gate or an evaluator change blocks acceptance.
5. **Decision.** The maintainers record the decision, the reasons, any dissent and any recusals in the ADR.

## 4. Evidence required for acceptance and implementation

A change to protocol meaning, scoring, eligibility, schemas or the evaluator needs all of the following before it is Accepted or Implemented:

| Evidence | Required for | How it is shown |
| :--- | :--- | :--- |
| Tests written first that fail without the behaviour | Any behaviour change | Test titles and the failing output before the fix, and passing output after |
| Adversarial regression | Protocol and evaluator changes | Named test that tries the attack or the weakening |
| Mutation control | Any gate, critical check or eligibility rule | `npm run test:mutations` output showing the weakened gate is caught |
| Same-case comparison | Scoring and evaluator changes | Baseline and candidate on identical frozen cases, with expected outputs unchanged |
| Evaluator digest statement | Any change under `src/conformance/` | Old and new digest, and the stale-evidence note from `VERSIONING.md` |
| Independent review notes | Protocol, evaluator and governance changes | Name and role of each reviewer, their declared conflicts, and their findings. If there is none, write "no independent review" |
| Registry and traceability | Any requirement change | `npm run requirements` and `npm run check` output |

Acceptance evidence is not a claim of external acceptance. An ADR that cites independent review must name the reviewer and what they reviewed.

## 5. Verification commands

Before an ADR is moved to Implemented, the change must pass:

```sh
npm test
npm run check
npm run adr:index
```

`npm run adr:index` rewrites the local index file. A governance change that does not touch that file should restore it after running the command, so that unrelated changes are not staged.

## 6. Errata

1. **Typographical or formatting fixes** are made in place. The git history records them.
2. **Clarifications that do not change meaning** are added as a dated note under a `## Errata` heading at the end of the ADR. The note names what was clarified.
3. **Corrections that change meaning** need a new ADR that supersedes the old one. The old ADR keeps its text, with an errata note that points to the successor.
4. **Errata for published vectors, schemas or released versions** follow `VERSIONING.md`. A wrong vector is withdrawn and replaced with a dated note. Conformance claims that relied on it are listed as affected.
5. **Errata for a finding in a security review** follow `SECURITY.md`, and are published only after an authorised fix is ready.

## 7. Appeals against a decision

A person affected by a decision may open a dispute by written reply to the ADR. The maintainers acknowledge it and decide it under section 3, with the decider recused if they had a conflict. No response time is promised. A future appeal process with timelines and an independent panel is a proposed milestone in `docs/WORLD-CLASS-PLAN.md` (WS8), not a current service.

## 8. Open questions for counsel and maintainers

- The discussion-window lengths in section 3.2 and the reviewer counts in section 3.3.
- Whether a Rejected status is needed.
- How decisions are recorded once more than one organisation is involved.

See also: `CHARTER.md`, `VERSIONING.md`, `EXTENSION-REGISTRY.md`, `../adr/0024-governance-charter-and-change-process.md`, `../../CONTRIBUTING.md`.
