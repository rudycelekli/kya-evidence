# Lane H integration notes

Edits needed in shared files that lane H may not touch.

## package.json

- `files`: add `"action/"` and `"policies/"` so the package carries the action and templates (`scripts/`, `docs/` and `test/` are already listed).
- `scripts`: add `"check:agent": "node scripts/kya-check.mjs"` and `"policy:init": "node scripts/kya-policy-init.mjs"`.
- `scripts/pack.mjs` and `scripts/verify-release.mjs` may enumerate release contents; confirm they accept the new `action/` and `policies/` directories and regenerate any expected file list.

## bin/kya.mjs (optional wiring)

Add thin subcommands that delegate to the standalone scripts: `kya check ...` calling `main()` exported from `scripts/kya-check.mjs`, and `kya policy-init ...` calling `main()` from `scripts/kya-policy-init.mjs`. Both `main` functions return the exit code. Add them to `HELP`. Until then the scripts run directly with `node`.

## README.md

Link `docs/GITHUB-ACTION.md`, `docs/POLICY-TEMPLATES.md`, `action/README.md` and `docs/examples/kya-check.workflow.yml` from the adoption or quickstart section, and mention `docs/QUICKSTART-RELYING-PARTY.md` as the next step after a first gate.

## evidence/requirements.json

Merge the `requirements` array from `docs/lane-h-requirements-proposal.json` (IDs KYA-ACT-001 to KYA-ACT-007). Each trace title appears once and matches a `test(...)` title exactly. The sections it cites already exist in `docs/SPECIFICATION.md`. Run `node scripts/requirements.mjs` to regenerate `docs/REQUIREMENTS.md` after the merge.

## docs/QUICKSTART-RELYING-PARTY.md

Optionally add a closing step: run `node scripts/kya-check.mjs --assessment-inputs ... --now "$NOW"` as the CI form of steps 4 to 6.

## .github/workflows/ci.yml

No change is required. The existing `node scripts/check.mjs` already validates the new JSON templates. If you want to exercise the action file in CI, add a YAML lint step; this lane did not add one.
