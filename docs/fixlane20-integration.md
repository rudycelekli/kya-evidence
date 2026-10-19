# Fix lane 20: documentation claims found wrong by a cold read

## What changed

Documentation only, plus tests that fail when the same claims drift again. No file under `src/` changed. Numbers were taken from `node scripts/requirements.mjs`, `node scripts/review-kit-check.mjs --print` and `evidence/assessment-vectors.json`, not copied from the brief.

- README: the `kya assess` example no longer pins `--now`; `kya demo` stamps its manifest and evidence with the current clock and demo evidence expires after one hour. The status paragraph says the release workflow has never run and that most of the work was AI assisted. The Open-KYA sentence no longer characterizes a project the repository never fetched.
- Review kit: the kit no longer names commit 5ab469e (which does not contain it). A single `Handover commit:` line says none is set; the owner replaces it with a full 40 character id. `scripts/review-kit-check.mjs` fails if a named id is not an ancestor of HEAD, if 5ab469e reappears, and if a quoted ADR `"records"` count differs from the number of ADR files (it said 34, the index has 35).
- Release notes, implementer guide and second implementation README: counts refreshed (284 requirements, 799 vectors across nine operations, 87 mutation controls, 275 refusal vectors); the 915 test sentence is gone.
- SUPPLY-CHAIN.md now matches `release.yml` and the threat model: attestation and SBOM generation are implemented in a workflow that has never run, the signed tag is not done, the SBOM and receipt are unsigned, every `uses:` is SHA pinned and the pinning backlog row is deleted.
- Wording: "clean-room" replaced by the claim in ADR-0016 and NOTICE; security review "pending" replaced by "no independent security review has taken place"; the interim route is only the one in SECURITY.md and no monitored channel exists; mutation-check targets described as the scripts target them; ROADMAP names no invisible branch and states two same-team implementations; code of conduct states that recusal and independent appeal are not possible with one maintainer; private evidence is marked not included and not reproducible.

## Not changed, owner decisions

- Git history carries a company email on many commits and most commits have no `Signed-off-by:`. History was not touched. The CONTRIBUTING sentence now asks for a sign-off only from contributors outside the maintainer team. `docs/governance/IPR-POLICY.md` may still describe the sign-off more strongly; the owner should check it.
- `docs/research/2026-10-13-prior-art.md` line 28 says private Gradia code was read as architectural context. ADR-0016 says only a design idea was read from a public-facing README and ADR titles, and that no code, data, paths or logs are used. The two still differ in what was read; only the owner knows which is true. The new wording states only what ADR-0016 and NOTICE support (ideas informed the design, nothing copied).
- The HarnessArena row of `docs/research/2026-10-14-evaluation-blueprint.md` still carries a commit id of the containing workspace.

## What is not verified

- The Handover commit rule is tested against this checkout's history only; no real handover has happened.
- The README demo path was run once on this machine; the test reruns it. Behaviour after the demo's one hour evidence expiry follows from the code, not from waiting an hour.
- No statement about what the private product contains was checked beyond ADR-0016 and NOTICE.

## Requirement proposals

Not added to `evidence/requirements.json`. Each id is three letters then three digits, each test title is exact and exists once in the named file, and the section is an existing `## ` heading of `docs/SPECIFICATION.md`.

| Proposed ID | Level | Area | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-DOC-022 | MUST | docs | Interoperability and versioning | The README assess example MUST NOT pin `--now`, because `kya demo` stamps its manifest with the current clock. | `the README assess example carries no hardcoded --now and the demo path it describes is qualified` |
| KYA-DOC-023 | MUST | docs | Interoperability and versioning | Counts quoted in the alpha release notes MUST equal the repository values. | `every requirement and vector count quoted in the alpha release notes equals the repository value` |
| KYA-DOC-024 | MUST | docs | Interoperability and versioning | SUPPLY-CHAIN.md MUST NOT deny build provenance while `release.yml` contains an attestation step, and every `uses:` in `release.yml` MUST be SHA pinned. | `SUPPLY-CHAIN.md does not deny build provenance while release.yml has an attest-build-provenance step` |
| KYA-DOC-025 | MUST | docs | Interoperability and versioning | Top-level documents MUST NOT claim clean-room origin, a pending security review or a published security contact. | `top-level documents do not claim clean-room, a pending review or a published contact` |
| KYA-RVK-008 | MUST | release | Interoperability and versioning | The review kit checker MUST fail when the kit names a handover commit that is not an ancestor of HEAD, names the retired commit 5ab469e, or quotes an ADR record count that differs from the repository. | `a handover commit that is an ancestor of HEAD passes, and the shipped kit names no commit`; `a kit that names the frozen commit 5ab469e or drops the handover line fails the check`; `a drifted ADR record count in the kit fails the check` |

The existing test `a frozen commit that is not in this history fails the check` (KYA-RVK-005) kept its title because requirement traces match titles exactly; its body now proves a non-ancestor handover commit fails.
