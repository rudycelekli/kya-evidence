# Fix lane 15: review kit, pilot kit and implementer invitation

Status: proposal for the integrator. `evidence/requirements.json` is not edited by this lane, and neither is anything under `src/`. Nothing was published, tagged, released, dispatched or announced, nothing contacted anyone, and nothing used the network.

The three outside gates (an independent security review, a first relying-party pilot, an independent implementer) cannot be closed by the project. This lane makes each cheap and safe to start. It does not close any of them and it does not change any status in `evidence/world-class-status.json`.

## Files

| File | What it is |
| :--- | :--- |
| `docs/review/REVIEW-KIT.md` | Scope, trust model and attacker model (by link), pinned evaluator digest and its limits, code to requirement to test map, reproduction commands with measured outputs, a table of every quoted number, known limitations, the project's own earlier findings, review questions and a findings template. States that no outside review exists. |
| `docs/pilot/PILOT-KIT.md` | Private offline pilot protocol for two or three agents, phases with the shipped commands, success and stop criteria, what the pilot can and cannot show, disagreement and surprise logging, a no-publication rule and a result-log template. |
| `docs/pilot/IMPLEMENTER-INVITATION.md` | What an independent implementer gets, how to report disagreements and what not to assume. |
| `scripts/review-kit-check.mjs` | Read-only checker. Recomputes every quoted number, checks every command and path the three documents name, and checks a few required statements. `--print` prints current values, `--deep` also runs the reference implementation over every vector. |
| `test/review-kit.test.mjs` | 16 tests, including that a drifted number, a missing file, a missing script, an unknown subcommand and a removed required statement each fail the check. |
| `docs/THREAT-MODEL.md` | Corrected where it was wrong (see below). No threat model was added: one already exists, and the kit links to it. |
| `README.md`, `docs/RELEASING.md` | One link paragraph each. |

## Corrections to existing text

- `docs/THREAT-MODEL.md` said `.github/workflows/ci.yml` used mutable tag references (`actions/checkout@v4`) and that mutable action references were an unmitigated risk. The workflow files pin every `uses:` by full commit SHA. Three places were corrected (the CI gate row, abuse case AC9 and the "Not mitigated" list). The new text also says the pins were resolved by the project and were not independently re-checked, and that the release workflow contains a provenance attestation job that has never been run.
- Not corrected by this lane, for the integrator to decide: the hardening backlog row in `docs/SUPPLY-CHAIN.md` that still lists pinning `actions/checkout` and `actions/setup-node` in `ci.yml` as work to do (it is done), and the sentence in `docs/fixlane13-integration.md` that the registry holds 252 requirements (it holds 258 now; that file also calls the 245 and 247 elsewhere stale).

## Things to know when merging

- The review kit quotes numbers that other lanes change: vector counts, the requirement count, the number of test files and test declarations, the number of source files. After any merge that changes one, `node scripts/review-kit-check.mjs` exits 1 and names the row. Run `node scripts/review-kit-check.mjs --print`, paste the new values into the table in section 6 of the review kit, and rerun. This is the intended behaviour. The checker cannot tell a deliberate change from drift, so it is the merger's job to confirm the change was intended.
- The `testFiles` and `testDeclarations` rows include `test/review-kit.test.mjs` itself.
- The `harness.*` rows are checked only with `--deep` (about ten seconds); the plain run reports them as not checked. A change to the harness output format by another lane will break `--deep` only.
- The frozen commit named in the review kit is `5ab469e`, the base this lane started from. The checker requires it to be an ancestor of `HEAD`. At handover the owner should name the full id of the exact commit being reviewed in the review request.
- Run `node scripts/review-kit-check.mjs` in the release gate sequence if wanted; this lane did not add it to `scripts/check.mjs`, `package.json` or CI, to avoid editing shared gates.

## Requirement proposals

Not added to `evidence/requirements.json`. Each id is three letters then three digits, each test title is exact and exists exactly once in `test/review-kit.test.mjs`, and each section is an existing `## ` heading of `docs/SPECIFICATION.md`.

| Proposed ID | Level | Area | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-RVK-001 | MUST | docs | Governance documents | Every number the external review kit quotes MUST equal the value recomputed from the repository, and a drifted number MUST make the review kit check fail. | `a drifted requirement count fails the review kit check`; `a drifted vector count fails the review kit check`; `a drifted mutation control count fails the review kit check`; `a quoted number the checker cannot recompute fails the review kit check` |
| KYA-RVK-002 | MUST | docs | Governance documents | The evaluator digest the review kit quotes MUST equal the digest pinned in `evidence/evaluator-identity.json`, and the pinned digest MUST equal the digest computed from source. | `a drifted evaluator digest in the kit fails the review kit check`; `a pinned evaluator digest that differs from the computed digest fails the check` |
| KYA-RVK-003 | MUST | docs | Governance documents | Every script, npm script, `kya` subcommand and repository path that the review kit, the pilot kit or the implementer invitation names MUST exist. | `a reference to a file that does not exist fails the review kit check`; `a command that names a missing script or npm script fails the pilot kit check`; `a command that names an unknown kya subcommand fails the invitation check` |
| KYA-RVK-004 | MUST | docs | Governance documents | The review kit MUST state that no outside security review exists, and the check MUST fail if that statement is removed. | `removing the statement that no outside review exists fails the check` |
| KYA-RVK-005 | MUST | docs | Governance documents | The review kit MUST name the frozen commit to review, and the check MUST fail when that commit is not in the history. | `a frozen commit that is not in this history fails the check` |
| KYA-RVK-006 | MUST | docs | Governance documents | The three kit documents MUST be plain ASCII and MUST carry no owner placeholder. | `an unmodified override passes and a non ASCII byte fails the check` |
| KYA-PLT-001 | MUST NOT | docs | Governance documents | The pilot kit MUST NOT allow publication of a pilot result without the written approval of the pilot owner, and the check MUST fail if that rule is removed. | `removing the owner approval rule from the pilot kit fails the check` |
| KYA-RVK-007 | MUST | docs | Governance documents | The review kit check MUST pass on the repository as committed, and it MUST say what it does not check. | `the review kit checker passes on this checkout`; `the quoted number table has a row for every number the checker recomputes for the review` |

KYA-RVK-006 and the placeholder rule are also enforced for markdown generally by `test/docs-claims.test.mjs`.

## What this lane did not verify

- It did not run the whole test suite, the full mutation check or `npm run release:readiness`. It ran the requirements check, the vector check, `mutation-check.mjs --preflight`, `scripts/check.mjs`, the privacy scan, both implementations through the vector harness, the review kit tests and the four documentation and release guard test files named in the brief.
- No outside party has read any of the three kits. They were written by the same assistant class that wrote most of the code and tests, and the commands in them were run by the lane author, not by a person unfamiliar with the project.
- The pilot protocol was dry run only on synthetic data in a scratch directory (init, keygen, policy generation, assess, currency after a change, capture demo and verify, privacy scan). The score card phase was not run because it needs per-item results from a harness that does not exist here.
- The kits say what an outsider should read and do; they do not establish that any outsider is willing, and they contain no contact, name, organisation or endorsement.
