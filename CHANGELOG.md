# Changelog

All notable changes to KYA Evidence are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning with pre-release tags (see [docs/governance/VERSIONING.md](docs/governance/VERSIONING.md)).

Read this file with two facts in mind. First, no version has been tagged, published to npm or released on GitHub: the alpha labels below mark the `version` field in `package.json` at the commit named in each heading, and nothing more. Second, nothing here is a certification, a safety claim or an outside validation. Every "Added" line means "the reference implementation now does this and a test checks it", not "an outside party confirmed it". The list of what is still not shown is in [docs/RELEASE-NOTES-ALPHA.md](docs/RELEASE-NOTES-ALPHA.md).

Entries come from `git log` and the merged pull requests (#1 to #30) of the repository. Where a commit message was too short to say what changed, the entry is limited to what the message says.

## [Unreleased]

### Added

- Conformance contract version 2 (ADR-0034, status Proposed): four pure operations `canonicalize`, `digest`, `verify-envelope` and `compare` beside `assess` and `currency`, in `interop/impl-contract/` (reference adapter, `js-operations.mjs`), the vector generator, the harness and `interop/second-impl/ops.mjs`. The envelope and result schema strings stay `kya.impl-input/v1` and `kya.impl-result/v1`; the vectors file becomes `kya.assessment-vectors/v2` with a `contract` member; the 272 earlier vectors are unchanged byte for byte. 213 vectors added (83 refusals), 485 in total; the reference and the same-team second implementation pass all 485. Registry effect measured with the harness: 39 of 252 requirements `pass` (was 37), 213 `not-run`. No outside implementation has run any vector.

- Three more pure contract operations, `verify-credential`, `verify-score-card` and `compare-score-cards` (ADR-0035, status Proposed), listed in the `contract.operations` member of the vectors file. The contract version stays 2: no schema string and no earlier vector changed (the earlier 485 are byte for byte identical, pinned in `test/contract-credential-score.test.mjs`), and an implementation that does not know them answers `unsupported` and gets `not-run`. 309 new vectors (refusals counted in `docs/fixlane14-integration.md`), the reference adapter operations in `interop/impl-contract/js-operations.mjs`, generators in `scripts/lib/vectors-credential.mjs` and `scripts/lib/vectors-score.mjs`, and a second implementation in `interop/second-impl/` written by a separate agent session from the specification text and the contract README (same team, not independent).

### Clarified

- SPECIFICATION CLARIFICATION: `docs/SPECIFICATION.md` gained "Credential verification" (the 21 opening steps and their codes, the six claim rules, report binding, policy trust, the status list check and the result order) and "Score card verification" (layout, generator, aggregates, rounding, problem codes and comparison). Both restate behaviour the reference already had, from `docs/VC-BRIDGE.md` and ADR-0033, so that a reader of the specification alone can reproduce it.
- SPECIFICATION CLARIFICATION (no behaviour change for any earlier vector): the specification now states the canonical form and strict parsing rules the reference already followed (refused member names `__proto__`, `prototype` and `constructor`; UTF-16 code unit order of member names; numbers judged by value with the 2^53-1 integer bound; the shortest round-trip number form; lowercase escapes; literal U+007F, U+2028 and U+2029; unpaired surrogate escapes kept; depth 32, 100000 values and 1 MiB bounds), that record digests are not domain separated (only the two signing inputs are), the one public key spelling and RFC 8032 point rules, the order of the envelope verification steps with eight failure codes, the field rules of an incident payload, and the comparison rules (reason codes in order, the evidence mode check, the shape checks on a report).
- CONTRACT CLARIFICATION: the implementation contract said input of up to 4 MiB; the strict parser, and so the reference, always refused above 1 MiB. The text now says so.

### Changed

- BEHAVIOR CHANGE in the alpha (nothing was published): the bytes of an exported status list change. `encodeList`, and so `buildStatusListCredential` and `exportAssessmentCredential`, now compress with a repository GZIP encoder (`src/shared/gzip-deterministic.mjs`: fixed header, fixed greedy matcher, one fixed-Huffman block) instead of `node:zlib` level 9, whose output depends on the build and the hardware. CI on Ubuntu x64 produced different vector bytes from macOS arm64 for the same inputs. The new output is larger (83 to 180 encoded characters for a 131072 entry list with three bits set) and identical on every platform by construction; any GZIP decoder reads it. Credentials signed earlier still verify, because decoding is unchanged. The vectors file was regenerated: the earlier 485 vectors are byte for byte identical, 799 vectors in total, and the reference and the second implementation pass all 799. A vector drift failure now names the first differing vector id, the JSON path and 200 characters of context. Whether the generator now reproduces the committed file on Linux is verified only by CI.
- BEHAVIOR CHANGE in the alpha (credential verification, found by writing the specification text): a `vc+jwt` whose header or payload bytes are ill-formed UTF-8 is now `MALFORMED` (the bytes used to be replaced and parsed); the evidence block of a credential is read only from an array (an object with a member named `0` used to be read as one); a status list is looked up by own member and only for a string URL (an inherited name such as `toString` used to be read as a list); and a report that passes its checksum but lacks `evidenceBundleDigest` or `acceptedEvidenceDigests` is `REPORT_INVALID` instead of making the verifier throw. `verifyAssessmentCredential` also returns `reportMismatch`, the sorted names of the differing top level members. No valid credential produced by `kya vc export` verifies differently.
- BEHAVIOR CHANGE in the alpha: `compareAssessments` now refuses (instead of comparing as equal by absence) a report that lacks a profile, evaluator or policy digest as a hash, a scope identifier, an evidence mode, a decision, an integer `score.earned` or well formed check entries. It is split into `describeComparison`, which names the first reason a pair cannot be compared. The second implementation's stdin parser now follows the written strict parsing rules (it refused one prototype name, allowed depth 64 and had no size bounds).
- The harness accepts the version 2 operations and a vectors file of schema v1 or v2. For a refusal vector of a version 2 operation, the exact `unsupported` reply for that operation is `not-run`, not `fail`.

- Assessment vectors grew from 111 to 272 (161 new, 71 of them refusals), written from the specification text before the reference was consulted: blocker order, scoring arithmetic, run recency, rejection reason precedence, public key strictness as proof key and trust anchor, strict parsing through a new `rawInput` vector field, field rules, principal binding, mandatory minimums and incident handling. Harness: `rawInput` and an empty `reasonContains`. Requirements passing in the harness report rose from 31 to 37 of 245. The writing exposed rules the reference enforced but the text did not state; they are now in `docs/SPECIFICATION.md` and `docs/SCORING.md` and the same-team second implementation was fixed against that text (it failed 26 of the 161 before). Nothing was tagged or published; no outside implementation has run the vectors.

- Prepared 0.1.0-alpha.4: version bump to `0.1.0-alpha.4` and changelog update (PR #30). Nothing was tagged or published.
- Core hardening from an adversarial review: the CI gate now refuses a symlinked input directory whose name begins with two dots, and `kya-capture verify` accepts run, subject, scope and profile pins and reports whether the capture is bound (KYA-ACT-016, KYA-CAP-019).
- BEHAVIOR CHANGE in the alpha: `checkCurrency` now fires `assessment-expired` at the instant equal to `validUntil` (previously it fired only after). Validity ends at `validUntil`, matching `assess`, which rejects a manifest or receipt at its expiry instant, so a relying party can no longer read current for an assessment that `assess` would already refuse (fail closed). The normative vector `currency.at-validity-boundary-is-current` (KYA-MON-001) is replaced by `currency.at-validity-boundary-is-expired` and `evidence/assessment-vectors.json` is regenerated. The second implementation had the inclusive reading for the currency boundary and also for manifest expiry, receipt expiry and receipt freshness inside `assess`; no vector covered those instants, and all are now exclusive like the reference (`interop/second-impl/AMBIGUITIES.md` C3 updated).
- BEHAVIOR CHANGE in the alpha: a check whose receipt is quarantined as a duplicate ID in the selected run is now `unknown` (it was the best surviving sibling). Found by the new metamorphic tests: replaying a failing receipt quarantined it and let a sibling pass raise the reported score and coverage and turned `blocked` into `insufficient-evidence`. The decision could never become `qualified` (RUN_CONFLICT blocks), so the effect was on score, coverage and label only. The second implementation follows. New seeded metamorphic tests (`test/metamorphic.test.mjs`) cover revocation, incident, removal, order, time, duplication, stricter policy and purity.

### Known issues

- A byte-identical duplicate receipt quarantines its own ID, so a qualified run drops to `insufficient-evidence`. This fails closed. Incident records skip exact duplicates and evidence does not; changing that is a specification decision.
- Removing evidence can create a qualification in general (a newer run omitted, or one copy of a duplicate-ID pair): the core has no completeness commitment, so completeness needs a bundle commitment from the party supplying the evidence. The invariant holds only for a single run with one receipt per check.
- The second implementation still differs from the reference at digest level for duplicate IDs, repeated observations across several runs, and the rejection reason for invalid receipts in older runs. No vector pins these yet.

## [0.1.0-alpha.4] - 2026-10-16

Everything after the commit that set `0.1.0-alpha.3`. Not tagged or published; the version label marks the `package.json` value at the release commit (procedure: [docs/RELEASING.md](docs/RELEASING.md)).

### Added

- Traced normative requirements: `evidence/requirements.json` with exact test titles, a gate that fails on a stale trace, and a generated `docs/REQUIREMENTS.md` (PR #1). Principal binding (an optional accountable-party declaration that policy can require) and monitoring triggers for currency checks (subject change, policy change, revocation, expiry, age limit, clock regression).
- Signed incident, resolution and appeal records, evaluated by the currency check (PR #1). Appeals are recorded and never clear a trigger.
- Conformance report format `kya.conformance-report/v1` with a builder, signer, TAP-mapped command, schema and ADR (PR #2). A scoped Python checker now also covers signed incident records with golden vectors.
- Named blocker codes and optional mandatory minimums (ADR-0016, PR #2). Machine-readable claim-boundary codes (PR #23).
- Design ADRs 0017 to 0020 for capture attestation, paired runs, the judge floor and anchoring (design only).
- Seeded property and fuzz tests for canonicalization, validators, signing, incident and currency evaluation, and assessment scoring (PR #3).
- Declarative scenario suites, the `reconstructions-v1` incident suite, and commit-reveal holdouts (PR #6).
- Campaign harness with a signed planned-attempt ledger and a capture-issuer role (ADR-0021, PR #6).
- `kya-check` CI gate, a GitHub composite action and policy templates (PR #6).
- W3C Verifiable Credentials 2.0 export bridge: `vc+jwt` assessment credential, `did:key` issuer, Bitstring Status List, and the `kya vc` commands (PR #6). The bridge is implemented and not outside-validated.
- Governance drafts: charter, IPR, trademark and claims rules, versioning, extension registry, decision process, code of conduct (PR #7). These are drafts that no lawyer has reviewed.
- Threat model, cryptographic agility inventory, a deterministic CycloneDX-style SBOM tool (`scripts/sbom.mjs`) and a disclosure policy draft (PR #9).
- A checked world-class status ledger in which an item that depends on outside parties cannot be marked verified from inside the project (PR #8).
- Golden assessment vectors (111 cases), a language-neutral implementation contract and an implementer harness (PR #10).
- A second implementation of assessment and currency semantics, written by the same team, matching all 111 vectors byte for byte after the spec gaps it exposed were written down (PR #11 to #13). It is not an outside implementation.
- Draft crosswalks to the EU AI Act, NIST AI RMF, ISO/IEC 42001 and SOC 2, with a validating test (PR #14). Drafts only, no counsel review.
- Assessor disclosure records and a standing check (PR #15), a profile specification, registry and metadata validator (PR #16), privacy scanner, field-commitment helper, PRIVACY and DPIA documents (PR #17), and offline interoperability bridges for in-toto, OpenTelemetry attributes, OAuth and SPIFFE, and A2A and MCP (PR #18).
- A pre-registered calibration study design and template (design only, no data collected) (PR #19).
- A reference measured capture cell (ADR-0032, PR #24). The cell is simulated; no real capture environment is measured.
- Mutation controls for the review-round fixes below; the harness now syntax-checks every mutant up front and has a `--preflight` mode.
- A documentation claims guard test (`test/docs-claims.test.mjs`) and cold-reader documentation fixes (PR #25).
- Release readiness (PR #28): the release procedure (`docs/RELEASING.md`), a launch note draft, a manual dry-run release workflow that publishes nothing by default, and `npm run release:readiness`, which checks the automated gates and lists the outside gates that remain open. Exit 0 means ready for an owner decision, not approved.

### Changed

- Evaluator code moved out of the pinned evaluator directory when the conformance report was added, so the evaluator identity stayed stable.
- Campaign command exit codes now follow the final attempt state, and open ledgers exit nonzero.
- `kya vc verify` requires a trust source (`--trust-did` or `--policy`) or the explicit `--allow-untrusted-issuer` flag, so an exit code of 0 cannot be read as an issuer check that never ran.
- The CI gate reads runtime-only reliability, requires digest pins and a core-profile requirement, and truncates summaries safely.
- Documentation overclaims found in review rounds were reworded, and stale lane notes removed.

### Fixed

- Incident evaluation no longer depends on the clock: a future-dated copy of a report ID could make a resolved report reopen as time passed (finding F-1 from the fuzz tests, PR #3).
- Incident and currency handling fail closed after independent review: all report records are kept, a resolution applies only when its reference is unambiguous, and currency inputs are validated.
- Campaign harness hardening after review: symlink-safe private directory, head pinning, mandatory signer trust, retry and duplicate-evidence rules, stricter evidence uniqueness (PR #6).

### Security

Each item below was found by an internal adversarial review of this project's own code and fixed with a regression test. They show review happened inside the team. They are not an outside security review, and none of them shows the absence of further defects.

- Public-key strictness now matches across implementations (PR #27): the second implementation and the Python checker refuse the same non-canonical PEM or DER spellings and small-order or non-canonical Ed25519 keys as the core, using independent point checks (no imports from `src/`). A 69-envelope differential test runs core, second implementation and Python together; all 111 assessment vectors still pass on both implementations. All three are same-team code; no outside implementation has run this.
- Capture cell and claim-boundary hardening after review (PR #29): nine reproduced findings, each fixed test-first. A canary secret sent without its prefix or in another encoding is now detected (matched on the secret part with a cross-call accumulator; remaining undetected transforms are documented). Re-signed bundles that contradict their own recorded state no longer verify, because the verifier replays effects. Also fixed: the attempt limit erasing the capture, a vacuous exfiltration pass, an adapter that trusted plain objects, an unbound probe set and forbidden list, dot-dot path segments, async agents, and gaps in the claim-boundary registry (git baseline, whole-source scan). The campaign lock is released on SIGINT and SIGTERM. `kya.capture/v1` gains a `forbidden` key (ADR-0032 is still Proposed). The cell is still simulated and in-process; no isolation is claimed.

- Symlink-safe entry guard: command-line entry points now compare real paths, so a tool started through an npm bin link actually runs its main function (and a symlink cannot make a script silently do nothing).
- Canonical key spelling: a public key in a proof or trust anchor must be the canonical SPKI PEM export of the parsed key. Other PEM or DER spellings are refused, so one signed payload has one envelope digest and a re-encoded copy of a conflict declaration cannot dodge its digest-bound withdrawal.
- Small-order, off-curve and non-canonical Ed25519 public keys are refused in the core verifiers as well as in the VC bridge (an identity-point key could otherwise accept a signature over any payload).
- Campaign runs take an exclusive lock for their duration, refuse to replace a ledger whose on-disk head changed, and no longer treat a directory named with two leading dots as outside the repository. The status-ledger path check compares path segments, not string prefixes.
- The Python checker reports an oversized integer literal as a structured failure, not a traceback.
- Privacy scanner and commitment helper: a run that scans zero files is an error, bare digest keys and more identifier shapes are checked, percent-encoded and Unicode email forms are flagged, and narrative fields inside nested records are checked. Field commitments now use a per-field salt derived from a 32-byte master salt; constant or short salts are refused, and the public `salt` parameter was removed (reusing a salt let one opening expose every other low-entropy field).
- Assessor disclosure and standing: a withdrawal binds to the digest of the record it withdraws (a different record that reuses the id is not withdrawn) and must not be future-dated; a third-party conflict declaration removes standing until the assessor lists the declared code in a current disclosure.
- Interoperability bridges fail closed: the report checksum is verified first, non-qualified decisions and missing, partial or contradictory currency data are refused unless the caller opts in, malformed inputs return a refusal instead of throwing, and exports document that free text copied from a report can still carry identifiers.
- Profile validator: reserved namespaces and names are refused (including `core.`, `reference.` and `fixture.`), an email in a contact is refused even when percent-encoded, deprecation dates and supersession are checked, and prose that claims a sign-off, certification or approval is refused when no sign-off record exists.

## [0.1.0-alpha.3]

State at the commit "Add evidence-replayed dossiers and exact scope comparison gates" (2026-10-13). Not tagged or published.

### Added

- Evidence dossiers replayed from originals, with explicit replay and assurance limits in the rendering, and exact scope comparison gates (comparison requires identical policy, profile, evaluator, scope digest and complete check populations).
- Frozen offline benchmark admission controls and replay.
- Adversarial rendering checks for dossiers (HTML injection and print layout).

### Fixed

- Fabricated standalone benchmark and telemetry projections are rejected.
- Critical failures and invalidated evidence are kept out of qualified dossier views.

## [0.1.0-alpha.2]

State at the commit "fix: bound native attempts and publish alpha two interface contracts" (2026-10-13). Not tagged or published.

### Added

- Strict identity, signed evidence and scope-bound assessments (alpha.1 contract made executable), a local command-line tool, declaration imports, JSON schemas and a private-safe inventory.
- A frozen conformance evaluator with bounded, opt-in adapters, including strict native declaration transports and private transcript capture, and a documented typed API.
- Content-addressed, replayable research universes and immutable forks, with correction references that expose affected descendants.
- Reproducible packaging: `scripts/pack.mjs` builds a deterministic archive from immutable Git blobs and `scripts/verify-release.mjs` checks it. Evaluator gate mutation controls.
- Canonical and Ed25519 golden vectors, and a scoped Python byte checker for canonical JSON and signatures.
- An animated identity, an offline assurance dashboard and open governance files.

### Fixed

- Tied-run and duplicate-quarantine score laundering, and replay binding to every executable source module and package routing.
- Signed JSON is snapshotted before scoring so a Proxy object cannot substitute outcomes; validators return captured plain data.
- Conflicting frozen outcomes and unsafe archives are rejected; native attempts are bounded and native approval prompts are disabled during bounded trials.

## [0.1.0-alpha.1]

State at the first commit, "docs: freeze KYA Evidence implementation and assurance contract" (2026-10-13). Not tagged or published.

### Added

- The frozen implementation and assurance contract: `docs/BUILD-CONTRACT.md` and `package.json`, which later versions implement.

[Unreleased]: https://github.com/rudycelekli/kya-evidence/compare/a4ac588...HEAD
[0.1.0-alpha.4]: https://github.com/rudycelekli/kya-evidence/compare/a670120...a4ac588
