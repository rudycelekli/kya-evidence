# Invitation to an independent implementer

This page is for a person or team outside the project who might write a second implementation of the KYA assessment semantics from the written specification. It says what you would get, how to report where the specification and the reference disagree, and what you should not assume. It is not an outreach message: no one has been sent this page, and the project owner decides if and when to share it.

**No outside implementation has run the vectors.** The only second implementation (`interop/second-impl/`) and the Python checker (`interop/python/`) were written by the same team as the reference. They show that the text is precise enough for that team to follow once the gaps it exposed were written down. They are not independent, and the project has never had an independent check of its own claims. You would be the first.

## What you get

| Item | Where | What it is |
| :--- | :--- | :--- |
| Specification | `docs/SPECIFICATION.md`, `docs/SCORING.md` | The normative text. Each requirement in `docs/REQUIREMENTS.md` names the section it comes from. |
| Requirement registry | `evidence/requirements.json`, `docs/REQUIREMENTS.md` | Every MUST, MUST NOT, SHOULD and MAY with an ID, its section and the tests that check the reference. |
| Assessment vectors | `evidence/assessment-vectors.json` | Public vectors for nine operations: `assess`, `currency`, `canonicalize`, `digest`, `verify-envelope`, `compare`, `verify-credential`, `verify-score-card` and `compare-score-cards`. Each carries its input, the expected result, the requirement IDs it exercises and a rationale. Refusals (inputs that must be rejected) are included. |
| Byte level vectors | `evidence/golden-vectors.json` | Canonical bytes, digests, signing inputs and incident vectors. Start here: if your digests differ, nothing above can match. |
| Contract | `interop/impl-contract/README.md` | How an implementation is wrapped: one command, one JSON object on standard input, one on standard output, a non zero exit for a refusal, no state, no network, no clock. |
| Harness | `scripts/run-vectors.mjs` | Runs your command once per vector and reports passes, failures, `unsupported` and the first differing JSON path. |
| Guide | `docs/IMPLEMENTERS-GUIDE.md` | Build order, how to read the report, what the vectors do not cover, known specification gaps and how to claim a result. Read it before you start. |
| Gap log | `interop/second-impl/AMBIGUITIES.md` | The specification gaps the same team found while writing its second implementation. Read it after your first attempt if you want to stay independent. |
| Reference | `src/`, `interop/impl-contract/js-reference.mjs` | The JavaScript implementation. Reading it is allowed. Then say so: an implementation derived from it is not independent. |

Everything is public and under the repository's Apache-2.0 licence. You need Node.js 22 or later to run the harness, and nothing else: the project has no dependencies and the harness needs no network. Your implementation may be in any language, as long as it is a command the harness can start.

## How to run it

Run the harness against your command from a checkout of the repository at a commit the project owner names:

```sh
node scripts/run-vectors.mjs --impl "python3 my_impl.py" --name my-impl --language python --impl-version 0.1 --out report.json
```

The summary is one JSON line with vector counts and the first failing vectors. The exit code is 0 only when every vector passed. To check the harness itself before you write anything, run it against the reference:

```sh
node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs"
```

An operation you do not implement answers `unsupported`, and those vectors are counted as not run, not as passed. You may implement a subset (the guide gives a build order that works) and say which.

## How to report a disagreement

A disagreement is a vector where your result differs from `expected`, or a requirement you think is wrong, ambiguous or missing a case.

1. Re-run the single vector (`--vectors` with a one vector file) and keep the harness output, including the first differing path.
2. Read the cited requirement and the vector rationale and decide which side is wrong. If you are wrong, fix yours.
3. If the vector or the specification is wrong or ambiguous, report it with the vector ID, the requirement ID, both outputs and your reading of the text. Do not argue that the reference is right because it exists, and do not edit the vectors to make yours pass.
4. Say whether you had read the reference source or the gap log before you reached the disagreement. That decides how much weight an agreement or a disagreement carries.
5. Report a crash or a hang as a failure, not as a skip.

A disagreement about specified behaviour is reported as a public issue if the repository offers one. No contact is published yet, see [SECURITY.md](../../SECURITY.md); until the owner publishes one, send nothing private to the project and ask the person who shared this page how to reach the owner. If you believe a disagreement is a security defect (for example a way to make a verifier accept what it must refuse), do not post the details publicly: follow [SECURITY.md](../../SECURITY.md) and use the findings template in [REVIEW-KIT.md](../review/REVIEW-KIT.md).

A resolution is recorded by the project as a specification change, an ADR when the semantics change and a new vector with a regression test. The project does not promise a response time, and it does not promise to agree.

## What you should not assume

- **That the expected values are right.** They come from the JavaScript reference, checked against hand written claims by the same team. Two implementations agreeing shows consistency, not correctness against intent. Your disagreement may be the useful result.
- **That the vectors are complete.** Only some requirements are exercised by any vector. The rest are covered, if at all, by in process tests that you cannot run from outside. The guide lists what the vectors do not cover: runtime capture, truthfulness, privacy, resource limits, the credential bridge, the campaign ledger, holdouts and size limits of the strict parser.
- **That the vectors are private.** They are public and fixed. An implementation could memorize them. The project has no private held out vectors today.
- **That the specification is stable.** The project is an alpha. Contract version 2 and several decisions are recorded as Proposed. A change that breaks your implementation is possible.
- **That a green run means conformance.** A passing run claims only that those published vectors passed, for that harness version and commit. It is not conformance to a standard, not certification, not an endorsement by the project and not a claim about W3C, Open-KYA, A2A, MCP or any other body. Do not describe it as any of those, and the project will not.
- **That any standard, community or governance body exists.** There is a draft charter and a draft decision process; no lawyer has reviewed them and no neutral body has adopted anything.
- **That the project will adopt, credit or pay for your work.** No credit, authorship, co-ownership, compensation or support is offered by this page. If the owner offers any, it will be in writing and separate.
- **That the project has users.** No organization has used the evidence for a real decision.
- **That the reference is secure.** It has never been reviewed from outside. A bug you find in it is welcome and expected.

## What to tell the project when you finish

Whatever the result, a short written account is the most valuable output: which operations you implemented, the language and runtime, your independence statement (what you read and when), the harness report file, which vectors failed and why, which sentences of the specification you had to guess at, and how long it took. Failure and partial results are as useful as a full pass. Do not publish an account of the project, or use its name in a claim, without the owner's written agreement; likewise the project will not quote your result without yours.
