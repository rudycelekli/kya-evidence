# Gate a pipeline with `kya-check`

`scripts/kya-check.mjs` runs `assess` and/or `checkCurrency` and prints one compact JSON summary. Under GitHub Actions it also writes workflow annotations, a Markdown step summary and step outputs. `action/action.yml` wraps it as a composite action. Nothing is published; wire it up yourself.

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

## Trust boundary: do not let the code under test write its own gate

Inputs and pinned digests must come from the base branch or a protected path, never from the code under test. If a pull request supplies the policy, the profile, the evidence and the evaluator digest, it can edit all of them in one commit and pass. Two flags close that gap:

- `--expect-policy-digest DIGEST` exits 1 with `POLICY_DIGEST_MISMATCH` unless the SHA-256 digest of the supplied policy equals the pin.
- `--expect-evaluator-digest DIGEST` exits 1 with `EVALUATOR_DIGEST_MISMATCH` unless the evaluator digest matches.

Both are checked before anything is assessed or printed. Hold the pins in repository variables or another place the pull request cannot edit, check out gate inputs from the base commit, and review changes to the workflow itself. `docs/examples/kya-check.workflow.yml` does this. Without pins the summary shows `pins.policyPinned: false` and Actions raises a `KYA pins` warning. Pins do not prove the policy is a good one; they prove it is the one you chose.

## Exit codes

| Code | Meaning |
| :--- | :--- |
| 0 | Reliable and current: `qualified` on runtime evidence, no reassessment trigger (or `--fail-on` relaxed the gate) |
| 2 | Exit code 2: not qualified (`blocked`, `insufficient-evidence`, `expired`, `revoked`) non-runtime evidence without `--allow-fixture`, or reassessment required (subject or policy changed, expiry, age, open incident, clock regression) |
| 1 | Usage or input error: unknown or duplicate flag, unreadable or non-regular file, bad JSON, malformed `--now`, a failed digest pin, invalid inputs, unwritable `GITHUB_OUTPUT` |

## In GitHub Actions

See `docs/examples/kya-check.workflow.yml` and `action/README.md`. When `GITHUB_ACTIONS=true` the script prints `::error` and `::warning` annotations to standard output before the JSON. Text is escaped under the workflow command rules (`%`, CR and LF in data; also `:` and `,` in properties), reduced to one printable line and bounded, so an agent name or a blocker string cannot start another command. When `GITHUB_STEP_SUMMARY` is set a Markdown report is appended; untrusted text is escaped so HTML, links, images and headings do not render. When `GITHUB_OUTPUT` is set, single-line `key=value` pairs are appended. Neither file is overwritten, and no environment variable or file content other than the named fields is printed.

Pass `now` explicitly so the recorded time is a decision you made. A system-clock result raises a `KYA clock` warning.

## What it does NOT prove

- It does not authorize anything. A reliable result says the supplied manifest, profile, policy, evidence, incidents and clock were consistent when checked.
- It trusts only the inputs it is given. A report checksum is not a signature, so currency-only mode recomputes nothing: it checks the stored assessment against the manifest, policy and clock you supply.
- It does not observe the running agent, so it cannot see behavior after the evidence was gathered. An omitted incident is undetectable.
- Signatures prove byte integrity and key possession, not truthful execution, human identity or independent review.
- Fixture evidence is not reliable by default and, when allowed, must not be read as a real product assessment.
- `summary-json` in `GITHUB_OUTPUT` is never cut mid-string: past about 3800 characters it becomes a compact object with `truncated: true`, the decision, `reliable`, `exitCode` and capped code lists. The full summary is still printed to standard output.

## Not verified here

The action has not been run on a real GitHub runner. In particular, that the runner picks up workflow commands from standard output in your setup, and how a failed composite step exposes outputs to later steps, should be confirmed in your own pipeline before you depend on them.
