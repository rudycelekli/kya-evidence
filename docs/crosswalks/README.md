Draft input for practitioner and legal review. Not legal advice. Not a compliance claim.

# Crosswalks: what KYA evidence can and cannot support

These files map clauses and controls of four frameworks to the KYA artifacts that could serve as input evidence, and state what KYA does not show. They are drafts for workstream WS7 in docs/WORLD-CLASS-PLAN.md. They have had no practitioner or legal review yet.

| Framework | File | Rows | Primary text read |
| :--- | :--- | ---: | :--- |
| EU AI Act (Articles 9, 12, 14, 15) | eu-ai-act.md | 16 | EUR-Lex page fetched through a condensing tool; paragraph topics are paraphrases |
| NIST AI RMF 1.0 | nist-ai-rmf.md | 28 | Yes, full PDF text extracted and read |
| ISO/IEC 42001:2023 | iso-iec-42001.md | 16 | No, paywalled; secondary summaries only |
| SOC 2 trust services criteria | soc-2.md | 12 | No; secondary summaries only |

## Row format

Each row has five cells: the framework clause or control, the basis of the citation (`primary text read`, `primary page, condensed fetch` or `secondary; needs primary re-check`), the KYA input evidence (a requirement ID from evidence/requirements.json or a document), what KYA does not show, and a status.

Allowed statuses: `supports as input`, `partial`, `not addressed`. None of them means a clause is satisfied. Assessment evidence is one input among many; the organization, its practitioner, auditor or counsel decides what counts.

## Limits that apply to every file

- A KYA assessment binds exact manifest, suite, evaluator, policy and evidence digests. Signature validity shows integrity and key possession, not truthful execution, human identity, legal authority or independent review (AGENTS.md).
- Assessment is not an authorization grant, a certification, or a conformity assessment.
- Clause numbers were not invented. Where a number could not be verified, the clause is described by topic.
- Rows resting on secondary sources are flagged `needs primary re-check` and must be checked against the licensed or official text before use.

Proposals for requirements and specification text are in INTEGRATION.md. The test is test/crosswalks.test.mjs.
