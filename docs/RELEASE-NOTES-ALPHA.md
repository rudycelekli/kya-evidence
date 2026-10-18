# KYA Evidence 0.1.0-alpha.4: launch note

Status: alpha, built from a checkout. Nothing is published: there is no npm package, no git tag and no GitHub release yet. `package.json` reads `0.1.0-alpha.4`. At the commit the pull request #29 merged, the project's continuous integration reported 915 tests passing with none skipped or pending. This repository carries 211 traced requirements, 111 assessment vectors, 16 frozen controls and 87 mutation controls.

## What this is

KYA Evidence is a small, dependency-free Node.js reference implementation for "Know Your Agent" evidence. A signed receipt records what one exact agent system (a manifest: model, tools, configuration, scope) did on a fixed set of checks. A relying party's own policy turns receipts into a decision, and every decision can be replayed and explained from the inputs. It is a declaration-and-evidence format plus a checker, not an identity credential for an agent, and not a score of any real product.

## What is implemented

- Canonical JSON, strict parsing and domain-separated Ed25519 signing, with published golden vectors.
- Signed evidence, scope-bound assessments with a fixed denominator, run selection, critical-failure blocking, currency checks, signed incidents, resolutions and appeals.
- Replayable research universes, evidence dossiers, a frozen conformance evaluator and a frozen control benchmark.
- A campaign harness with a signed planned-attempt ledger, scenario suites and commit-reveal holdouts, a CI gate and GitHub composite action, and policy templates.
- Offline interoperability bridges (W3C Verifiable Credentials 2.0 export, in-toto, OpenTelemetry attributes, OAuth and SPIFFE, A2A and MCP), a privacy scanner and field-commitment helper, an assessor disclosure and standing check, and a profile registry.
- A traced requirement registry (each requirement names the tests that check it), a mutation check that weakens evaluator gates and requires each weakening to be caught, a deterministic release archive with a receipt, an SBOM tool and a release readiness report.

Details and dates: [CHANGELOG.md](../CHANGELOG.md).

## What is explicitly NOT shown or validated

- **No outside security review.** Several rounds of review were done inside the team. Their fixes are in the changelog. They are not an independent review and no retest by an outside party exists.
- **No outside implementation.** The second implementation of assessment and currency semantics, and the Python byte checker, were written by the same team. The second implementation matches all 272 assessment vectors byte for byte, which shows the written spec is precise enough for the team to follow. It does not show that an unrelated implementer would read it the same way.
- **No relying-party pilot.** No organization has used this evidence for a real decision.
- **Captured evidence is simulated.** The reference capture cell is a simulation. No real, measured capture environment exists, and receipts from the demo and benchmarks are synthetic fixtures. A perfect fixture score says nothing about Claude Code, Codex, a bot or any other real agent.
- **Calibration is unmeasured.** The study design is written down and pre-registered as a template; no data has been collected, so no threshold in any profile is shown to separate good agents from bad ones.
- **Governance, IPR, trademark, claims rules, crosswalks (EU AI Act, NIST AI RMF, ISO/IEC 42001, SOC 2) and the disclosure policy are drafts.** No lawyer has reviewed them. The crosswalks do not make anyone compliant with anything.
- **Domain profiles have no expert sign-off.**
- **Not a standard, certification, endorsement or authorization.** A signature shows key possession and byte integrity, not that an agent did what a report says. There is no live revocation service and no continuous monitoring. The README's "What this is not" section lists the rest.

## Try it in five minutes

Requires Node.js 22 or later and a clone of the repository. No network, API keys or installs. The output folder can be anywhere; use a scratch folder you delete afterwards.

```sh
S=$(mktemp -d)
node bin/kya.mjs demo --out "$S/demo"            # writes a synthetic, signed demo assessment
node bin/kya.mjs verify "$S/demo/assessment.json" # integrity true, authenticated false (a checksum is not a signature)
node bin/kya.mjs benchmark --out "$S/bench"       # control agents, including a gaming fixture that gets blocked
node scripts/golden-vectors.mjs --check           # published byte vectors still match
node scripts/assessment-vectors.mjs --check       # published assessment vectors still match
rm -rf "$S"
```

To see tamper detection, change `"decision": "qualified"` to `"blocked"` in a copy of `assessment.json` and run `verify` on the copy: it prints `kya: Assessment digest differs` and exits 1. To run the checks the maintainers run, use `npm test` in a clone.

## Where to file issues

Open an issue at <https://github.com/rudycelekli/kya-evidence/issues>. Useful reports are reproducible failures (a sanitized input and the command that fails), places where the specification is ambiguous, and evaluator weaknesses. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first. Never put credentials, personal data or raw private traces in an issue.

## Security

Follow [SECURITY.md](../SECURITY.md). Today it says: if the repository Security tab offers a private report button, use it; otherwise do not post exploit details publicly and open a public issue titled Security contact request containing no technical details, and the maintainer will reply with a private channel. No response time is promised and no monitored private channel is confirmed.
