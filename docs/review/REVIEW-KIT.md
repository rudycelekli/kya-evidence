# External security review kit

This kit exists so that when the owner finds a willing reviewer, nothing has to be written first. It says what to review, what to leave out, what the project already knows is weak, how to reproduce every verification claim from a clean checkout, and where to put findings.

**There is no outside security review today.** Every review so far was done by the project team, mostly with AI assistance, on code that was also largely written with AI assistance. Nothing in this kit, in the changelog or in the requirement registry is evidence that an independent party looked at the code. The first reader outside the team is the first independent look. Do not describe this project as reviewed, audited or certified until a named outside party has said so in a document the owner can link.

No contact for reports is published yet, see [SECURITY.md](../../SECURITY.md). Until the owner publishes one, send nothing to anyone on the project's behalf; the owner arranges the channel.

Frozen commit to review: `5ab469e`. That is the commit this kit was written and measured against. A file cannot name the commit that contains it, so at handover the owner writes the full 40 character id of the exact commit to review into the review request, runs `node scripts/review-kit-check.mjs` at that commit and sends the output. If the owner's handover commit differs from the one named here, the request wins and the numbers below must be re-measured (the checker prints them with `--print`).

## 1. What is being reviewed

KYA Evidence is a small Node.js 22 reference implementation with no runtime dependencies. A relying party gives it a manifest (a declaration of one agent configuration), a policy (who is trusted, in which role), a profile (the frozen list of checks) and signed evidence receipts. It returns a decision and a score, and later a currency verdict (is the assessment still current), taking signed incident records into account. Around that core sit a conformance evaluator, a campaign ledger, a CI gate and GitHub Action, a Verifiable Credential export bridge, a privacy scanner, a simulated capture cell and release tooling.

The security question is narrow and concrete: can an attacker who controls the inputs the threat model says an attacker controls cause the verifier to report a decision, a currency verdict or a signature check that the written specification says it must not?

### In scope

| Area | Where | Why a reviewer should look |
| :--- | :--- | :--- |
| Strict JSON parsing and canonical form | `src/shared/canonical.mjs` | Every digest and signature is over its output. A parser differential is a forgery vector. |
| Ed25519 verification, public key strictness, domain prefixes | `src/evidence/domain/services/signatures.mjs`, `src/shared/ed25519-point.mjs` | Small order and non canonical keys, malleability, cross domain replay. |
| Record validators (manifest, profile, policy, evidence, incident) | `src/identity/domain/services/validation.mjs`, `src/evidence/` | Exact keys, grammar, bounds, prototype member names. |
| Assessment: eligibility, run selection, duplicate quarantine, scoring, blockers, mandatory minimums | `src/assessment/application/assess.mjs` | The decision a relying party acts on. |
| Currency and incidents | `src/assessment/application/currency.mjs`, `src/evidence/domain/services/incidents.mjs` | Fail closed rules, ambiguity, time handling. Finding F-1 (below) lived here. |
| Conformance evaluator and pinned digest | `src/conformance/` | The 18 frozen checks and the evaluator identity (section 3). |
| Campaign ledger and capture issuer role | `src/campaign/` | Hash chain, planned entries first, head pinning, locks, private directory handling. |
| Simulated capture cell | `src/capture-cell/` | Canary detection, effect replay, bundle verification. Simulated only. |
| Verifiable Credential export bridge | `src/vc-bridge/` | `alg` confusion, embedded keys, status list decompression, key resolution. |
| CI gate and Action | `scripts/kya-check.mjs`, `action/action.yml`, `.github/workflows/ci.yml` | Pull request controlled input, pins, annotation injection. |
| Privacy scanner and field commitments | `src/privacy/`, `scripts/privacy-scan.mjs` | False negatives are the serious risk (see `docs/PRIVACY.md`). |
| Release tooling | `scripts/pack.mjs`, `scripts/verify-release.mjs`, `.github/workflows/release.yml` | Archive safety (tar handling), reproducibility, the gated publish job. Nothing has ever been released. |
| Rendering of untrusted data | `src/assessment/infrastructure/render.mjs`, `dashboard/index.html` | HTML injection and print layout. |
| Differential partners | `interop/second-impl/`, `interop/python/` | Same team. Useful as a source of disagreement, not as an oracle. |

### Out of scope, and why

- The correctness of `node:crypto` (Ed25519, SHA-256, HMAC). The threat model lists it as assumption A1.
- Operating system or container isolation of adapters. The package states that a child process is not a sandbox.
- Hosting settings: branch protection, required workflows, secrets, the `release` environment, npm account settings. These are outside the repository and cannot be reviewed from it.
- The behaviour, safety or quality of any real agent or model (Claude Code, Codex, any bot). No such agent has been measured; every shipped score is a synthetic fixture.
- The truth of a signer's statements. A signature proves bytes and key possession.
- The legal, governance and regulatory drafts (`docs/GOVERNANCE.md`, `docs/governance/`, `docs/crosswalks/`). No lawyer has reviewed them. A security reviewer is not asked to.
- Statistical validity of any score. No calibration data exists.

If a reviewer finds the boundary drawn wrongly, that is itself a finding; use the template in section 10.

## 2. Trust model and attacker model

The project already has a threat model: [THREAT-MODEL.md](../THREAT-MODEL.md). This kit does not copy it; read it first. It holds the trust boundary map (TB1 to TB9), the assets and actors, the assumptions registry (A1 to A14), a STRIDE table, ten abuse cases and the list of what is not mitigated. It is a design time document written by the project authors and has not been reviewed from outside. A review should treat it as a claim to test, not as ground truth. When this kit was written the model was checked against the repository and statements about CI action pins and release provenance were out of date; they were corrected. Other statements may still be wrong.

The short version a reviewer needs on page one:

- **Trusted by out of band choice:** the relying party's policy (trust anchors, roles, revocations, thresholds, pins). The code cannot tell whether a role was assigned truthfully.
- **Untrusted:** manifests, receipts, incident records, adapter responses, assessment files, credentials, pull request content, anything read from disk or a network that the caller did not pin.
- **Attacker capabilities assumed:** supplies arbitrary bytes for any untrusted input; holds ordinary (untrusted) Ed25519 keys; may hold one trusted key (dishonest or compromised issuer); may replay old files; may edit a pull request including its workflow files; has read every public check and vector.
- **Attacker capabilities not assumed:** breaking Ed25519 or SHA-256, code execution in the verifier's process before it starts, control of the relying party's policy source, control of the clock.
- **Goals worth finding:** a verifier that accepts what the specification says it must refuse; two verifiers that disagree on one input; a score or decision that changes when it should not (reordering, duplication, omission within the stated limits); any path that makes untrusted text reach a shell, a workflow command, a file outside the intended directory, or rendered HTML.
- **Known to be unmitigated, so not a surprise finding:** truthful execution, revocation freshness, omission of whole runs, organizational independence of keys, holdout leakage before reveal, unsigned releases. The full list is "Not mitigated" in the threat model.

## 3. The pinned evaluator digest

`evidence/evaluator-identity.json` pins one SHA-256 value, the evaluator digest. `test/evaluator-identity.test.mjs` (requirement KYA-EVL-001) fails if the digest computed from the source differs from the pinned value, so a change to evaluator source cannot go unnoticed in CI.

| | |
| :--- | :--- |
| Pinned and currently computed value | `d0bc7f7840e5ddf1a71eb3b9ac92e5c4d0be5d156eea2c6f4f909f7066b5e31b` |
| Computed in | `src/conformance/domain/scenarios.mjs` as `EVALUATOR_DIGEST` |

**What the digest covers:** the frozen evaluator descriptor, an inventory of every `.mjs` and `.js` file under `src/conformance/`, the source of `src/shared/canonical.mjs` and the exact bytes of `profiles/core-v1.json`. Changing a check, a gate, a transport or the canonicalizer changes it.

**What the digest does not cover:**

- Any code outside those inputs. In particular `src/assessment/` (scoring, run selection, currency), `src/evidence/` (signature checks), `src/identity/` (validators), `src/campaign/`, `src/capture-cell/`, `src/vc-bridge/` and every script are not hashed by it. A weakening of the assessor or the signature check does not change the evaluator digest. Those are guarded by tests and the mutation check, which are weaker than a pin.
- Whether the bytes were the bytes that ran. The digest identifies expected source; it is not an attestation of a loaded artifact.
- Truthful execution of anything. A receipt that names this digest says which evaluator the issuer claims to have used.
- The Python checker and the second implementation, which are separate code.

Read the digest as a version label for 18 frozen checks, not as an integrity guarantee for the verifier.

## 4. Map: code to requirement to test

The requirement registry is `evidence/requirements.json` (rendered in `docs/REQUIREMENTS.md`). Each requirement names its section in `docs/SPECIFICATION.md` and one or more exact test titles that must exist exactly once; `node scripts/requirements.mjs --check` fails on a stale trace. A passing trace shows a live, titled test exists. It does not show that the assertions cover the whole requirement (a known gap: see the "hollow test" row of the threat model).

| Requirement area (IDs) | Main code | Main tests |
| :--- | :--- | :--- |
| integrity, envelope, field rules (KYA-INT-001 to 006, KYA-ENV-001 to 007, KYA-FRL-001) | `src/shared/canonical.mjs`, `src/shared/ed25519-point.mjs`, `src/evidence/domain/services/signatures.mjs` | `test/canonical.test.mjs`, `test/envelope-canonical.test.mjs`, `test/second-impl-strictness.test.mjs`, `test/interop.test.mjs`, `test/spec-field-rules.test.mjs`, `test/property-canonical.test.mjs`, `test/property-signing.test.mjs` |
| binding, trust, run selection, scoring, principal, minimums, refusal (KYA-BND, KYA-TRU, KYA-RUN, KYA-SCO, KYA-DIM, KYA-PRN, KYA-MIN, KYA-REF) | `src/assessment/application/assess.mjs`, `src/assessment/application/codes.mjs`, `src/identity/domain/services/validation.mjs` | `test/assessment.test.mjs`, `test/metamorphic.test.mjs`, `test/mandatory-minimums.test.mjs`, `test/refusal-codes.test.mjs`, `test/property-assessment.test.mjs`, `test/property-validators.test.mjs` |
| monitoring, incidents (KYA-MON, KYA-MET, KYA-INC) | `src/assessment/application/currency.mjs`, `src/evidence/domain/services/incidents.mjs` | `test/incidents.test.mjs`, `test/assessment.test.mjs` |
| reporting (KYA-RPT) | `src/assessment/application/report-shape.mjs`, `src/assessment/infrastructure/render.mjs`, `src/reporting/` | `test/dossier.test.mjs`, `test/dossier-render.test.mjs`, `test/presentation.test.mjs`, `test/spec-reason-vocabulary.test.mjs` |
| evaluator, conformance (KYA-EVL, KYA-CON, KYA-CNF) | `src/conformance/`, `src/conformance-report/` | `test/evaluator-identity.test.mjs`, `test/conformance.test.mjs`, `test/conformance-report.test.mjs`, `test/native-adapters.test.mjs`, `scripts/mutation-check.mjs` |
| suites, holdouts (KYA-SUI, KYA-HLD) | `src/suites/`, `src/holdout/` | `test/suites.test.mjs`, `test/holdout.test.mjs` |
| campaign ledger (KYA-CMP, KYA-CAM) | `src/campaign/domain/ledger.mjs`, `src/campaign/domain/roles.mjs`, `src/campaign/application/runner.mjs` | `test/campaign-ledger.test.mjs`, `test/campaign-runner.test.mjs`, `test/campaign-hardening.test.mjs` |
| capture cell (KYA-CAP) | `src/capture-cell/bundle.mjs`, `src/capture-cell/proxy.mjs`, `src/capture-cell/canary.mjs` | `test/capture-cell.test.mjs`, `test/capture-cell-hardening.test.mjs` |
| CI gate and Action (KYA-ACT) | `scripts/kya-check.mjs`, `action/action.yml` | `test/kya-check.test.mjs`, `test/policy-templates.test.mjs`, `test/core-adversarial.test.mjs` |
| credential bridge (KYA-VCB) | `src/vc-bridge/jws.mjs`, `src/vc-bridge/credential.mjs`, `src/vc-bridge/status.mjs` | `test/vc-bridge.test.mjs`, `test/vc-cli-trust.test.mjs`, `test/fixlane9-adversarial.test.mjs` |
| interoperability bridges (KYA-IBR) | `src/interop-bridges/` | `test/interop-bridges.test.mjs` |
| privacy (KYA-PRV) | `src/privacy/`, `scripts/privacy-scan.mjs` | `test/privacy.test.mjs` |
| assessor standing, profiles, claim boundaries (KYA-ASR, KYA-PRF, KYA-CLB) | `src/assessor/`, `src/profiles/`, `src/claim-boundaries/` | `test/assessor.test.mjs`, `test/profiles.test.mjs`, `test/claim-boundaries.test.mjs` |
| score card (KYA-SCR, KYA-BEN) | `src/kya-score/`, `src/benchmarks/` | `test/kya-score.test.mjs`, `test/kya-score-second-verifier.test.mjs`, `test/benchmarks.test.mjs` |
| vectors (KYA-VEC) | `scripts/assessment-vectors.mjs`, `scripts/run-vectors.mjs`, `interop/` | `test/assessment-vectors.test.mjs`, `test/contract-operations.test.mjs`, `test/second-impl.test.mjs`, `test/vectors.test.mjs` |
| release (KYA-REL) | `scripts/pack.mjs`, `scripts/verify-release.mjs`, `scripts/release-readiness.mjs` | `test/release.test.mjs`, `test/release-workflow.test.mjs`, `test/release-readiness.test.mjs` |
| the requirement gate itself (KYA-REQ) | `scripts/requirements.mjs` | `test/requirements.test.mjs` |

To list the exact tests of one requirement: open `docs/REQUIREMENTS.md` and search for its ID. To find which requirement a test serves, search `evidence/requirements.json` for its title.

## 5. Reproduce the verification from a clean checkout

Needs Node.js 22 or later (measured here with v22.19.0), Git and no network. Nothing is installed: the package has no dependencies. Use a fresh clone and check out the commit under review.

```sh
git clone https://github.com/rudycelekli/kya-evidence.git kya-review
cd kya-review
git checkout 5ab469e
node --version
```

Replace the commit with the handover commit. Then run the cheap checks first. Each line shows the command and the output measured when the kit was written.

| Step | Command | Expected result |
| :--- | :--- | :--- |
| 1 | `node scripts/requirements.mjs --check` | exit 0; one JSON line starting `{"requirements":275,"areas":` and ending with `"traceable":true,"registryDigest":"96d1f350ed2ac04518d88d6756d2525ef5aa241538e08ccea29a6afac36cac2e"}` |
| 2 | `node scripts/assessment-vectors.mjs --check` | exit 0; the line `Assessment vectors match` |
| 3 | `node scripts/mutation-check.mjs --preflight` | exit 0; `{"preflight":"ok","controls":87,"anchorsPresent":true,"allMutantsParse":true}` |
| 4 | `node scripts/check.mjs` | exit 0; one JSON line with `"syntax":"passed"`, `"schemas":"matched"`, `"requirementTraceability":"passed"`, `"statusLedger":"passed"` (the `files` figure depends on the directory scanned and is not quoted) |
| 5 | `node scripts/privacy-scan.mjs examples test/fixtures profiles policies suites` | exit 0; `"clean": true` and `"findings": 0` |
| 6 | `node scripts/profile-registry.mjs --check` | exit 0; `Profile registry matches` |
| 7 | `node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs"` | exit 0 after about ten seconds; summary with `"vectors":{"total":799,"pass":799,...,"fail":0,"unsupported":0}` and `"requirements"` with `"pass":60`, `"notRun":215`, `"total":275` |
| 8 | `node scripts/run-vectors.mjs --impl "node interop/second-impl/adapter.mjs"` | exit 0 after about thirty seconds; the same vector and requirement counts. This is the same team's second implementation. |
| 8b | `node scripts/adr-index.mjs` | exit 0; `{"records":34,"danglingRefs":0,"storage":"evidence/adr-index.json"}`. It rewrites that file; `git status` must stay clean afterwards. |
| 9 | `node scripts/review-kit-check.mjs --deep` | exit 0; `"ok": true`. Confirms every number in the table below, including the harness rows. |

The expensive steps. They were not run when this kit was written; the numbers they print are not quoted here because they were not measured for this kit:

```sh
npm test
node scripts/mutation-check.mjs
npm run release:readiness
```

`npm test` runs every test file. CI requires it to report `# skipped 0` and `# todo 0`. `node scripts/mutation-check.mjs` without `--preflight` weakens the evaluator and assessment gates one at a time and requires each weakening to be caught; it is slow. The release notes quote a CI test count at an earlier commit; do not rely on it, read your own run. Expect `npm run release:readiness` to exit non zero or to list open outside gates, because those gates (an outside review, an outside implementation, a pilot) are exactly what this kit is for.

Fuzzing is separate and seeded. See `docs/lane-d-findings.md` for the seed and run count variables; a longer run (for example the 20x setting that found F-1) is worth repeating with new seeds and is not part of any default command.

A reviewer should also build the archive and verify it (`node scripts/pack.mjs`, then `node scripts/verify-release.mjs`), and delete `dist/` afterwards. That checks reproducibility of the package bytes only. Nothing has been published, tagged or released.

## 6. Numbers quoted by this kit

Every row is recomputed by `node scripts/review-kit-check.mjs` from the repository, not from any document. If a row is wrong the checker exits 1 and says which. Rows prefixed `harness.` are recomputed only with `--deep` because they run the reference implementation over every vector.

| Key | Value | How it is measured |
| :--- | :--- | :--- |
| `requirements` | `275` | `node scripts/requirements.mjs`, field `requirements` |
| `requirementsRegistryDigest` | `96d1f350ed2ac04518d88d6756d2525ef5aa241538e08ccea29a6afac36cac2e` | same command, field `registryDigest` |
| `vectorsTotal` | `799` | length of `vectors` in `evidence/assessment-vectors.json` |
| `vectors.assess` | `212` | vectors whose `operation` is `assess` |
| `vectors.currency` | `60` | operation `currency` |
| `vectors.canonicalize` | `72` | operation `canonicalize` |
| `vectors.digest` | `38` | operation `digest` |
| `vectors.verify-envelope` | `68` | operation `verify-envelope` |
| `vectors.compare` | `35` | operation `compare` |
| `vectors.verify-credential` | `223` | operation `verify-credential` |
| `vectors.verify-score-card` | `72` | operation `verify-score-card` |
| `vectors.compare-score-cards` | `19` | operation `compare-score-cards` |
| `mutationControls` | `87` | `node scripts/mutation-check.mjs --preflight`, field `controls` |
| `testFiles` | `75` | files matching `test/*.test.mjs` |
| `testDeclarations` | `921` | lines that begin with `test(` in those files. The four `test/property-*.test.mjs` files declare 38 seeded properties through a helper and contribute no such line. |
| `adrs` | `35` | files `docs/adr/NNNN-*.md` (20 marked Implemented and 15 Proposed in their status lines when counted) |
| `coreProfileChecks` | `18` | length of `checks` in `profiles/core-v1.json` |
| `srcFiles` | `88` | `.mjs` files under `src/` |
| `srcLines` | `5400` | newline characters in those files. The code is dense: long lines, so line count understates size. |
| `evaluatorDigestPinned` | `d0bc7f7840e5ddf1a71eb3b9ac92e5c4d0be5d156eea2c6f4f909f7066b5e31b` | `evidence/evaluator-identity.json`; the checker also requires it to equal the digest computed from source |
| `harness.vectorsPass` | `799` | `node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs"`, field `vectors.pass` |
| `harness.vectorsFail` | `0` | same command, field `vectors.fail` |
| `harness.requirementsPass` | `60` | same command, field `requirements.pass`: requirements for which a vector passed |
| `harness.requirementsNotRun` | `215` | same command, field `requirements.notRun` |

Read the harness rows carefully: 60 of 275 requirements are exercised by a vector. The other 215 are covered, if at all, by in process tests. That is a statement about where the evidence lives, not about defects.

## 7. Known limitations

Taken from the threat model "Not mitigated" list, the changelog "Known issues" and the findings below; none is softened.

- No outside review of any kind (this document, the threat model, the code, the vectors).
- Most of the code was written with AI assistance. The same assistant class wrote many of the tests. Tests and code can share a misreading of the specification.
- The expected values of all 799 vectors come from the JavaScript reference, checked against hand written claims by the same team. Agreement of two same team implementations shows the text is precise enough to follow, not that it is right.
- The second implementation, the Python checker and the Python score verifier were written by the same team. They are not independent.
- The capture cell is a simulation (`cell.isolation: none`). No real measured capture environment exists. Evidence from a native agent adapter is declaration source and cannot satisfy scored checks.
- All shipped scores are synthetic fixtures. No real agent has been scored in a way the project would publish.
- A byte identical duplicate receipt quarantines its own ID, so a qualified run drops to `insufficient-evidence` (fails closed; a specification decision is open).
- Removing evidence can create a qualification in general: the core has no completeness commitment, so whole runs and single records can be omitted by whoever supplies the bundle.
- The second implementation still differs from the reference at digest level for duplicate IDs, repeated observations across several runs and the rejection reason for invalid receipts in older runs. No vector pins these yet.
- There is no live revocation, no effective time on key revocation, no key rotation protocol, no timestamp or external anchor (ADR-0020 is Proposed), and no effective protection against backdating after key compromise.
- Releases are not signed. No release has been made. The manual release workflow has never been run.
- Repository hosting settings (branch protection, required checks) are unverified.
- The privacy scanner has expected false negatives (names, addresses, free text, unlisted national identifiers).
- Hollow assertions behind a traced requirement pass the requirement gate; review is the only control.
- The mutation check mutates only a fixed list of gates; the requirement gate, the canonical parser and the Python checker are not mutated.

## 8. The project's own earlier findings (not softened)

Every item below was found by the team itself, not by an outsider. They are listed so a reviewer can retest the fixes and, more usefully, look for the class of defect each one represents. Sources: `CHANGELOG.md` ("Security", "Fixed", "Changed", "Known issues"), `docs/lane-d-findings.md`.

**Fuzz and property testing (`docs/lane-d-findings.md`)**

- F-1, fixed: a future dated low severity copy of an incident report ID was ignored when judging ambiguity, so a resolved report looked resolved at one time and reopened later with no new record. Needed a trusted key to emit the duplicate. It appeared only at 20 times the default fuzz run count, which shows the default run is not exhaustive. Regression test added.
- O-1, open: `canonical` accepts lone surrogates (emits an escape). Implementations that cannot encode them could hash different bytes. The specification now states that unpaired surrogate escapes are kept; no decision on rejecting them.
- O-2, open: tied duplicate observations resolve by bundle order, so reported evidence identity and role fields depend on order (decision and score do not).
- O-3, fixed: the `ignored` list of the currency result followed input order, so the whole result was not canonical under permutation.
- O-4, open: omitting an invalid record from a bundle can lift the invalidated evidence veto. This is the undetectable omission limit.
- Minor, no action taken: `-0` and `0` share a digest; raw U+2028 and U+2029 pass unescaped; a PEM with CRLF endings verifies and yields the same key ID.

**Adversarial review rounds (changelog, "Security" for 0.1.0-alpha.4)**

- Public key strictness: non canonical PEM or DER spellings and small order, off curve or non canonical Ed25519 keys are now refused in the core, the second implementation and the Python checker. Before this, an identity point key could accept a signature over any payload.
- Symlink safe entry guard: a tool started through an npm bin link did nothing silently; a symlink could make a script a no-op.
- Campaign harness: needed an exclusive lock, refusal to replace a ledger whose on disk head changed, and a fix for a directory named with two leading dots being treated as outside the repository. A status ledger path check compared string prefixes instead of path segments.
- Capture cell and claim boundary: nine reproduced findings (changelog, PR #29), among them a canary secret sent without its prefix or in another encoding going undetected, re-signed bundles that contradicted their own recorded state still verifying, the attempt limit erasing the capture and a vacuous exfiltration pass. Remaining undetected canary transforms are documented.
- Privacy scanner and commitments: a run that scanned zero files passed; one salt reused across fields let one opening expose every other low entropy field.
- Assessor disclosure: a withdrawal bound only to a record id, not its digest, and could be future dated.
- Interoperability bridges did not fail closed on non qualified decisions or missing currency data.
- Profile validator accepted reserved namespaces and prose claiming a sign off that did not exist.
- CI gate: a symlinked input directory whose name begins with two dots was not refused until a review found it; `kya-capture verify` gained run, subject, scope and profile pins because a valid capture of another run read as clean.
- Behaviour changes found by metamorphic and review work: `checkCurrency` fires `assessment-expired` at the instant equal to `validUntil` (it fired only after before); a receipt quarantined as a duplicate ID now makes its check `unknown`, because replaying a failing receipt used to let a sibling raise the score.

**What these findings say about the project.** They show internal review found real defects, several of them in security relevant rules, and that fixes came with regression tests. They also show defects survived earlier rounds of the same review process. The right inference is that more defects of the same families are likely to remain, not that the list is complete.

## 9. Suggested review questions

1. Parser differential. Can any input be accepted by `parseJson` and by one other implementation (the second implementation, the Python checker, `JSON.parse`) while producing different canonical bytes or a different accept or reject answer? Pay attention to numbers, string escapes, member order, depth, size and prototype names.
2. Signature domain. Can an evidence signature be replayed as an incident, campaign, conformance report or credential signature, or the reverse? Are the domain prefixes complete and unambiguous?
3. Key strictness. Is every public key path (proof key, trust anchor, VC `did:key`, JWK) subject to the same canonical spelling and point checks? Is any path missing one?
4. Trust versus validity. Is there any path where a valid signature is treated as trust, or where a role (`self`, `independent`, `capture-issuer`) is taken from the record instead of the policy?
5. Run selection. Can the latest run be chosen differently by reordering, duplicating, back dating or omitting receipts within what the specification says is detectable? Which of these outcomes are inside the stated omission limit and which are not?
6. Fixed denominator. Can any input shrink the denominator, make an `abstain` or `error` count as a pass, or let a critical failure be averaged away?
7. Time. Where does the code read the clock? Can two calls with the same inputs differ? Are `validUntil`, `notBefore`, future dated incident and clock regression handled the same way in `assess`, `checkCurrency`, the VC bridge and the second implementation?
8. Incident handling. Re-derive the rules for ambiguity, resolution, appeal and future dating from the specification text and compare with `currency.mjs`. F-1 and O-3 were found there; is there a third?
9. Campaign ledger. Can a ledger be truncated, reordered, forked or replaced without a pinned head noticing? Can a lock or private directory check be raced?
10. CI gate. Can a pull request that cannot edit base branch policy still change what the gate evaluates, including through paths, symlinks, annotations, output variables or the step summary?
11. Credential bridge. Is every `alg: none`, HMAC key confusion, embedded key, `kid` and status list decompression path closed?
12. Capture cell. Within the stated simulation, can an agent reach the transcript, world, canary table or harness? (The cell claims no isolation; the question is whether it claims more than it does.)
13. Release tooling. Can `scripts/pack.mjs` or `scripts/verify-release.mjs` be made to read outside the repository, follow a link, or accept a crafted archive?
14. Claims versus code. Pick five sentences from `README.md` or `docs/CLAIM-BOUNDARIES.md` that state a capability and try to falsify them from the code. Where the wording is stronger than the code, that is a finding.
15. Test honesty. Pick ten requirements and read the test body of each trace. Does it assert the MUST, or only that the code runs?
16. Threat model. Which row of `docs/THREAT-MODEL.md` is wrong, missing or optimistic?

## 10. Findings template

One finding per file or section. Keep reproductions free of real credentials, personal data and private traces. Do not publish a finding before the owner has agreed a disclosure path.

```text
Title:
Reviewer (name, organisation, independence statement):
Date and reviewed commit (full 40 character id):
Component and file:
Boundary crossed (TB1 to TB9 or "none"):
Requirement ID affected, or "none":
Severity (reviewer's rating) and rationale:
Attacker capability needed:
Summary (two or three sentences):
Reproduction (smallest input and exact command; sanitized):
Expected behaviour (cite the specification section):
Actual behaviour:
Impact if exploited:
Is it inside a limitation already listed in section 7 or the threat model? (yes with row, or no):
Suggested fix (optional):
Test that would have caught it (optional):
Retest result after a fix (commit, date, pass or fail):
Confidence (confirmed by reproduction, likely, speculative):
```

Also useful from a reviewer: a list of what was read and not read, how long it took, which tools were used and which questions in section 9 were not reached. A review that says what it did not cover is more useful than one that says nothing.

## 11. What a review result may and may not be used for

- A reviewer's report is the reviewer's. The project may quote it only with the reviewer's written agreement and may not paraphrase a limited review as a general one.
- A clean report on a bounded scope is not a certification of the project. State scope, commit, date and method every time.
- Findings change the status of the world-class plan item WS5-04 only through the status ledger rules: an outside review is verified only with a named outside party, an https link and a date (see `evidence/world-class-status.json`).
- Publishing, announcing or contacting anyone about a review is an owner decision. This kit does not authorize any of it.
