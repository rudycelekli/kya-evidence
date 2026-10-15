# Gate a pipeline with `kya-check`

`scripts/kya-check.mjs` runs `assess` and/or `checkCurrency` and prints one JSON summary (multi-line, indented). Only the `summary-json` step output is a single line. Under GitHub Actions it also writes workflow annotations, a Markdown step summary and step outputs. `action/action.yml` wraps it as a composite action. Nothing is published; wire it up yourself.

This is a local policy check. It is not an authorization grant.

## Run it locally

```sh
# Assess and check currency from one inputs file {manifest, profile, policy, evidence, evaluatorDigest}
node scripts/kya-check.mjs --assessment-inputs kya/inputs.json --now 2026-10-14T12:00:00.000Z

# The same with separate files
node scripts/kya-check.mjs --manifest m.json --profile p.json --policy pol.json --evidence e.json --evaluator <digest> --now ...

# Currency only, against a stored assessment, with signed incident records
node scripts/kya-check.mjs --assessment assessment.json --manifest m.json --policy pol.json --incidents inc.json --now ...
```

`--fail-on unreliable` (default) fails unless the assessment is `qualified` and nothing in `checkCurrency` fired. `--fail-on not-qualified` ignores currency triggers. `--fail-on never` always exits 0 for a readable result, for pipelines that want the outputs and a separate gate.

The summary holds `decision`, `score`, `coverage`, `independentCoverage`, `blockerCodes`, `blockers`, `currency` (`current`, `action`, `triggers` with codes, open incident IDs), `reliable`, `exitCode`, `clock` and `reportDigest`. With `--now` the output is deterministic. Without it the system clock is read, `clock.source` is `system-clock` and the summary says the result is not reproducible. An inputs file may carry `now`; it is used when `--now` is absent and reported as `inputs-file`.

## Evidence mode: runtime only by default

`reliable` and exit 0 require `evidenceMode` `runtime`. A `qualified` assessment built from fixture evidence reports `reliable: false`, the reason code `FIXTURE_EVIDENCE_NOT_RELIABLE` in `reasonCodes`, an `::error title=KYA evidence mode` annotation and a step-summary line, and exits 2. `mixed` evidence gives `MIXED_EVIDENCE_NOT_RELIABLE`; `declaration` or any unrecognised mode gives `EVIDENCE_MODE_NOT_RELIABLE`. `--allow-fixture` (Action input `allow-fixture: 'true'`) accepts fixture and mixed evidence for demos and tests; it never accepts declaration evidence, and the summary records `allowFixture: true`.

## Trust boundary: the gate comes from the base, the subject comes from the pull request

Two kinds of input, two sources:

- The policy, the profile, the evaluator digest and the expected digests come from the base branch or a protected path (and repository variables), never from the code under test. If a pull request supplied them, it could edit the question and the answer in one commit and pass.
- The manifest and evidence under test come from the pull request head. That is the thing being assessed. If they came from the base branch, a pull request that changed the agent would never be judged, and the gate would check the old agent forever.

The base-side inputs are held in place by three pin flags, each an exact 64 character lowercase SHA-256 digest:

- `--expect-policy-digest DIGEST` exits 1 with `POLICY_DIGEST_MISMATCH` unless the supplied policy hashes to the pin. The pin is the canonical `policyDigest` that `kya policy-init` prints and that the `kya check` summary reports, not the `sha256sum` of the file.
- `--expect-evaluator-digest DIGEST` exits 1 with `EVALUATOR_DIGEST_MISMATCH` unless the evaluator digest matches. Take it from `kya init DIR` or from the `evaluatorDigest` field of an assessment (the reference value is in `evidence/evaluator-identity.json`).
- `--expect-assessment-digest DIGEST` (currency-only mode only) exits 1 with `ASSESSMENT_DIGEST_MISMATCH` unless the assessment's `reportDigest` matches.

All pins are checked before anything is assessed or printed. `--require-pins` (Action input `require-pins`, default `true`) goes further: it exits 1 with `PINS_REQUIRED` when the policy or evaluator pin is missing, and in currency-only mode when the assessment pin is missing. An unset repository variable therefore fails the job instead of quietly running unpinned. Without `--require-pins` the summary shows the missing pin as `pins.policyPinned: false` and Actions raises a `KYA pins` warning.

`docs/examples/kya-check.workflow.yml` does this with two checkouts: the base commit into `base/` for the policy and profile, the pull request head into `head/` for the manifest and evidence, both read as data and never executed, and `actions/checkout` pinned by commit SHA. Review changes to the workflow, to `base/kya-gate/` and to the `KYA_*` variables like changes to branch protection. Pins do not prove the policy is a good one; they prove it is the one you chose.

### Currency-only mode: the evidence mode is only as trustworthy as the assessment file

With `--assessment`, the evidence mode, the decision and the score are read from the supplied assessment file, and only its internal checksum is verified. That checksum is unauthenticated: anyone can rewrite a fixture assessment to `evidenceMode: runtime`, drop the fixture limitation, recompute the digest and hand it over. In this mode the evidence mode is only as trustworthy as the assessment file, so the file's digest must be pinned from a trusted source with `--expect-assessment-digest`. Without that pin the result is `reliable: false` with the reason code `ASSESSMENT_NOT_PINNED` (an `::error title=KYA assessment pin` annotation and a step-summary line) and exit 2. `--allow-unpinned-assessment` (Action input `allow-unpinned-assessment: 'true'`) accepts an unpinned file for local experiments and is recorded as `allowUnpinnedAssessment: true`. Runtime-only reliability is not claimed for currency-only mode without the pin.

### Custom profiles

`kya-policy-init --allow-custom-profile` writes a policy built on a profile that is not the frozen core profile. The policy schema has no field for notes or a rationale, and `validatePolicy` rejects unknown members, so the generated file cannot carry a marker beyond its default id suffix `-custom-profile`. The marker therefore lives in the check: `kya-check` compares the policy's `profileDigest` with the frozen core profile and, when they differ, sets `customProfile: true` in the summary, raises an `::warning title=KYA custom profile` annotation and adds a step-summary line. The policy id is a name, not evidence; do not rely on it.

## Exit codes

| Code | Meaning |
| :--- | :--- |
| 0 | Reliable and current: `qualified` on runtime evidence, no reassessment trigger (or `--fail-on` relaxed the gate) |
| 2 | Exit code 2: not qualified (`blocked`, `insufficient-evidence`, `expired`, `revoked`) non-runtime evidence without `--allow-fixture`, or reassessment required (subject or policy changed, expiry, age, open incident, clock regression) |
| 1 | Usage or input error: unknown or duplicate flag, unreadable or non-regular file, bad JSON, malformed `--now`, a failed digest pin, `PINS_REQUIRED`, invalid inputs, unwritable `GITHUB_OUTPUT` |

## In GitHub Actions

See `docs/examples/kya-check.workflow.yml` and `action/README.md`. When `GITHUB_ACTIONS=true` the script prints `::error` and `::warning` annotations to standard output before the JSON. Text is escaped under the workflow command rules (`%`, CR and LF in data; also `:` and `,` in properties), reduced to one printable line and bounded, so an agent name or a blocker string cannot start another command. When `GITHUB_STEP_SUMMARY` is set a Markdown report is appended; untrusted text is escaped so HTML, links, images and headings do not render. When `GITHUB_OUTPUT` is set, single-line `key=value` pairs are appended. Neither file is overwritten, and no environment variable or file content other than the named fields is printed.

Pass `now` explicitly so the recorded time is a decision you made. A system-clock result raises a `KYA clock` warning.

## What it does NOT prove

- It does not authorize anything. A reliable result says the supplied manifest, profile, policy, evidence, incidents and clock were consistent when checked.
- It trusts only the inputs it is given. A report checksum is not a signature, so currency-only mode recomputes nothing: it checks the stored assessment against the manifest, policy and clock you supply.
- It does not observe the running agent, so it cannot see behavior after the evidence was gathered. An omitted incident is undetectable.
- Signatures prove byte integrity and key possession, not truthful execution, human identity or independent review.
- Fixture evidence is not reliable by default and, when allowed, must not be read as a real product assessment.
- `summary-json` in `GITHUB_OUTPUT` is never cut mid-string: past about 3800 characters it becomes a compact object with `truncated: true`, `decision`, `reliable`, `exitCode`, `evidenceMode`, `allowFixture`, `customProfile`, compact `pins` and capped code lists. The `evidence-mode` and `allow-fixture` outputs are always written, so a `reliable=true` output can be read together with the mode it rests on. The full summary is still printed to standard output.

## Not verified here

The action has not been run on a real GitHub runner. In particular, that the runner picks up workflow commands from standard output in your setup, and how a failed composite step exposes outputs to later steps, should be confirmed in your own pipeline before you depend on them.
