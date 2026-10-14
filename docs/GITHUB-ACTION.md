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

## Exit codes

| Code | Meaning |
| :--- | :--- |
| 0 | Reliable and current: `qualified`, no reassessment trigger (or `--fail-on` relaxed the gate) |
| 2 | Exit code 2: not qualified (`blocked`, `insufficient-evidence`, `expired`, `revoked`) or reassessment required (subject or policy changed, expiry, age, open incident, clock regression) |
| 1 | Usage or input error: unknown or duplicate flag, unreadable or non-regular file, bad JSON, malformed `--now`, invalid inputs, unwritable `GITHUB_OUTPUT` |

## In GitHub Actions

See `docs/examples/kya-check.workflow.yml` and `action/README.md`. When `GITHUB_ACTIONS=true` the script prints `::error` and `::warning` annotations to standard output before the JSON. Text is escaped under the workflow command rules (`%`, CR and LF in data; also `:` and `,` in properties), reduced to one printable line and bounded, so an agent name or a blocker string cannot start another command. When `GITHUB_STEP_SUMMARY` is set a Markdown report is appended; untrusted text is escaped so HTML, links, images and headings do not render. When `GITHUB_OUTPUT` is set, single-line `key=value` pairs are appended. Neither file is overwritten, and no environment variable or file content other than the named fields is printed.

Pass `now` explicitly so the recorded time is a decision you made. A system-clock result raises a `KYA clock` warning.

## What it does NOT prove

- It does not authorize anything. A reliable result says the supplied manifest, profile, policy, evidence, incidents and clock were consistent when checked.
- It trusts only the inputs it is given. A report checksum is not a signature, so currency-only mode recomputes nothing: it checks the stored assessment against the manifest, policy and clock you supply.
- It does not observe the running agent, so it cannot see behavior after the evidence was gathered. An omitted incident is undetectable.
- Signatures prove byte integrity and key possession, not truthful execution, human identity or independent review.
- Fixture evidence is flagged with a warning and must not be read as a real product assessment.

## Not verified here

The action has not been run on a real GitHub runner. In particular, that the runner picks up workflow commands from standard output in your setup, and how a failed composite step exposes outputs to later steps, should be confirmed in your own pipeline before you depend on them.
