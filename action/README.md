# KYA check action

A composite GitHub Action that runs `scripts/kya-check.mjs` from this repository. It assesses (or re-checks the currency of) an agent against a relying-party policy and fails the step when the result is not reliable and current. Nothing here is published; the files are ready for you to reference once you decide where to host them.

This is a local policy check. It is not an authorization grant, and it does not prove truthful execution, human identity, legal authority or independent review. See `docs/GITHUB-ACTION.md`.

## Usage

```yaml
# base/ is the pull request base commit, head/ is the pull request head commit (two checkouts; see docs/examples/kya-check.workflow.yml)
- uses: OWNER/kya-evidence/action@COMMIT_SHA   # pin a full commit SHA you have reviewed
  with:
    policy: base/kya-gate/policy.json
    profile: base/kya-gate/profile.json
    evaluator: ${{ vars.KYA_EVALUATOR }}
    expect-policy-digest: ${{ vars.KYA_POLICY_DIGEST }}
    expect-evaluator-digest: ${{ vars.KYA_EVALUATOR_DIGEST }}
    manifest: head/kya-gate/manifest.json
    evidence: head/kya-gate/evidence.json
    now: ${{ env.KYA_NOW }}
```

The policy and profile come from the base checkout, the evaluator digest and both pins from repository variables (never from the code under test), and the manifest and evidence from the pull request head, because they are what is being assessed. `KYA_POLICY_DIGEST` is the canonical `policyDigest` printed by `kya policy-init` and shown in the `kya check` summary, not the `sha256sum` of the file. `KYA_EVALUATOR_DIGEST` and `KYA_EVALUATOR` come from `kya init DIR` and the `evaluatorDigest` field of an assessment.

A bare call that supplies only `assessment-inputs` and no pins exits 1 with `PINS_REQUIRED` unless `require-pins` is `'false'`. Set `require-pins: 'false'` for local use only, never in a gate.

Replace `OWNER/kya-evidence` and `COMMIT_SHA` with the repository you vendor or fork and a commit you reviewed. The action uses `actions/setup-node` pinned to a commit SHA (the v4 tag as of 2026-10-14) for Node.js 22 and runs with the repository workspace as the working directory, so input paths are relative to your checkout.

## Inputs

| Input | Meaning |
| :--- | :--- |
| `assessment-inputs` | One JSON file with `manifest`, `profile`, `policy`, `evidence`, `evaluatorDigest` and optionally `now`, which is ignored while `require-pins` is on (the default) because the file comes from the code under test; pass the `now` input instead |
| `manifest`, `profile`, `policy`, `evidence`, `evaluator` | The same inputs as separate files plus the evaluator digest |
| `assessment` | An existing assessment; with `manifest` and `policy` it selects currency-only mode |
| `incidents` | Signed incident records |
| `now` | ISO UTC timestamp with milliseconds. Empty means the system clock is read, and the summary and a warning annotation say so. The action has no input for `--allow-inputs-clock`: a clock inside the inputs file never counts here |
| `fail-on` | `unreliable` (default), `not-qualified` or `never` |
| `allow-fixture` | `true` lets fixture or mixed evidence count as reliable. Default `false`: only runtime evidence is reliable (reason code `FIXTURE_EVIDENCE_NOT_RELIABLE`) |
| `expect-policy-digest`, `expect-evaluator-digest` | Pinned SHA-256 digests; a mismatch exits 1 before any result. Take them from the base branch or a protected path, never from the code under test |
| `expect-assessment-digest`, `allow-unpinned-assessment` | Currency-only mode. The evidence mode is only as trustworthy as the assessment file, so pin its `reportDigest`; unpinned gives `ASSESSMENT_NOT_PINNED` unless allowed |
| `require-pins` | Default `true`: exit 1 `PINS_REQUIRED` unless the policy and evaluator pins (and the assessment pin in currency-only mode) are supplied |
| `node-version` | Defaults to `22` |

## Outputs

`decision`, `reliable`, `current`, `evidence-mode`, `allow-fixture`, `score`, `coverage`, `blocker-codes`, `trigger-codes`, `exit-code`, `clock-source` and `summary-json`. Outputs are written before a failing exit. A failing step may hide its outputs from later steps unless they use `if: always()`; to read outputs while still continuing, set `fail-on: never` and gate on `reliable` yourself.

## Exit codes

0 reliable and current. 2 not qualified or reassessment required. 1 usage or input error (bad file, unknown flag, malformed timestamp, unwritable output path).

## Security notes

Inputs reach the script as environment variables, not interpolated shell text. Annotation text is escaped under the GitHub workflow command rules and the Markdown step summary neutralizes HTML, links and headings from untrusted names. The script reads only the files you name, makes no network request and prints no secret. It cannot verify that the evidence is honest; that depends on the trust anchors in your policy.
