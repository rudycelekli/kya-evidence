# KYA check action

A composite GitHub Action that runs `scripts/kya-check.mjs` from this repository. It assesses (or re-checks the currency of) an agent against a relying-party policy and fails the step when the result is not reliable and current. Nothing here is published; the files are ready for you to reference once you decide where to host them.

This is a local policy check. It is not an authorization grant, and it does not prove truthful execution, human identity, legal authority or independent review. See `docs/GITHUB-ACTION.md`.

## Usage

```yaml
- uses: actions/checkout@v4
- uses: OWNER/kya-evidence/action@COMMIT_SHA   # pin a full commit SHA you have reviewed
  with:
    assessment-inputs: kya/inputs.json
    now: ${{ env.KYA_NOW }}
```

Replace `OWNER/kya-evidence` and `COMMIT_SHA` with the repository you vendor or fork and a commit you reviewed. The action uses `actions/setup-node@v4` for Node.js 22 and runs with the repository workspace as the working directory, so input paths are relative to your checkout.

## Inputs

| Input | Meaning |
| :--- | :--- |
| `assessment-inputs` | One JSON file with `manifest`, `profile`, `policy`, `evidence`, `evaluatorDigest` and optionally `now` |
| `manifest`, `profile`, `policy`, `evidence`, `evaluator` | The same inputs as separate files plus the evaluator digest |
| `assessment` | An existing assessment; with `manifest` and `policy` it selects currency-only mode |
| `incidents` | Signed incident records |
| `now` | ISO UTC timestamp with milliseconds. Empty means the system clock is read, and the summary and a warning annotation say so |
| `fail-on` | `unreliable` (default), `not-qualified` or `never` |
| `node-version` | Defaults to `22` |

## Outputs

`decision`, `reliable`, `current`, `score`, `coverage`, `blocker-codes`, `trigger-codes`, `exit-code`, `clock-source` and `summary-json`. Outputs are written before a failing exit. A failing step may hide its outputs from later steps unless they use `if: always()`; to read outputs while still continuing, set `fail-on: never` and gate on `reliable` yourself.

## Exit codes

0 reliable and current. 2 not qualified or reassessment required. 1 usage or input error (bad file, unknown flag, malformed timestamp, unwritable output path).

## Security notes

Inputs reach the script as environment variables, not interpolated shell text. Annotation text is escaped under the GitHub workflow command rules and the Markdown step summary neutralizes HTML, links and headings from untrusted names. The script reads only the files you name, makes no network request and prints no secret. It cannot verify that the evidence is honest; that depends on the trust anchors in your policy.
