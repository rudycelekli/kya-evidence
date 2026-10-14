<img src="assets/kya-hero.svg" alt="KYA Evidence. Know your agent. Show your work." width="1200" />

# KYA Evidence

**A passport says what an agent is. Evidence shows what an exact agent system did, under an exact scope.**

KYA Evidence is local-first open infrastructure for **Know Your Agent**: portable agent passports, signed check receipts, configurable relying-party policies and explainable assurance assessments. The vision is a neutral standard that people, organizations and independent assessors can implement, reproduce and contest. The current deliverable is a dependency-free Node.js reference implementation, **v0.1.0-alpha.3**, not an adopted industry standard.

Every person may eventually delegate to an agent. Every relying party will need a better answer than “trust the prompt.” Start with an exact question: **does this configuration meet this party's policy for this scope, on this evidence?** Keep the result portable, the decision explainable and the correction process open.

[Specification](docs/SPECIFICATION.md) · [Scoring](docs/SCORING.md) · [Research universes](docs/UNIVERSES.md) · [Byte interoperability](docs/INTEROPERABILITY.md) · [Threat model](docs/THREAT-MODEL.md) · [Adapters](docs/ADAPTERS.md) · [Roadmap](docs/ROADMAP.md) · [Contribute](CONTRIBUTING.md)

## Read the full agent dossier

A headline score is the beginning of the report. KYA now explains which responses replay, which predicates failed, which passing claims lack originals, and where the evidence cannot reach. The dossier keeps scope, source, coverage, reported cost, evaluator controls and unresolved questions together.

![From scoped evidence to strengths, failures and persistent blind spots](assets/dossier-atlas.svg)

```sh
node bin/kya.mjs diagnose --mode reckless --with-benchmarks true --out .kya/dossier
node bin/kya.mjs dossier-verify --dossier .kya/dossier/dossier.json \
  --inputs .kya/dossier/inputs.json --observations .kya/dossier/observations.json \
  --benchmarks .kya/dossier/benchmark-run.json
```

Open `dossier.html` for the offline, printable report or read `dossier.md`. This command runs a clearly labelled synthetic example with no model account or provider call. Use `kya dossier` with your own frozen, authorized inputs and originals for a real evidence dossier. [Report contract](docs/DOSSIERS.md).

## Challenge the evaluator

Sixteen frozen controls include four complete behavioral reference modes and twelve signed-receipt admission challenges. Cases preserve expected outcomes, missing measurements and every failure. Six real weakened assessor gates are detected by the unchanged control population. These checks establish local evaluator behavior; commercial agents need separate measured campaigns.

```sh
node bin/kya.mjs bench --out .kya/controls
node bin/kya.mjs bench-verify .kya/controls/benchmark-run.json
```

[Benchmark catalog and observation boundaries](docs/BENCHMARKS.md) · [Code-grounded design study](docs/research/2026-10-14-evaluation-blueprint.md)

## Run from a checkout

Requires Node.js 22 or later. The fixture demonstration needs no runtime dependencies, API keys or network access. This package is not yet published to npm.

```sh
node bin/kya.mjs demo --out ./artifacts/demo
node --test test/*.test.mjs
node scripts/serve.mjs
```

Open the local URL printed by the server to explore five reference cases: careful, unsafe, unknown, tampered and revoked. The demo and dashboard presets are **synthetic fixtures**. A perfect fixture score does not measure Claude Code, Codex, bots or any other real agent. Imported assessment JSON is displayed as claimed, unverified data.

```sh
node bin/kya.mjs assess \
  --manifest ./manifest.json \
  --profile ./profiles/core-v1.json \
  --policy ./policy.json \
  --evidence ./evidence.json \
  --evaluator <64-character-evaluator-digest> \
  --now 2026-10-13T12:00:00.000Z \
  --out ./artifacts/assessment

node bin/kya.mjs inspect .
node bin/kya.mjs verify ./artifacts/assessment/assessment.json
node bin/kya.mjs probe --out ./artifacts/runtime-probes.json
node bin/kya.mjs benchmark --out ./artifacts/benchmark
```

Use generated demo inputs and the [adapter protocol](docs/ADAPTERS.md) to connect an explicitly authorized runtime. `probe` checks executable availability and version, never competence or safety. A command adapter is a transport, not an operating-system sandbox. `verify` checks report checksum integrity; it does not authenticate the report or recompute its claims.

The typed SDK includes strict Claude Code result and Codex event parsers, explicit command plans and opt-in native factories. Native model claims remain declarations and cannot earn observed-action credit. Claude execution is blocked until effective managed policy can be established. Codex requires verified subscription auth and explicit binding of included global instructions. See [execution gates and private transcript retention](docs/ADAPTERS.md) and [validation boundaries](docs/VALIDATION.md).

## Relying-party currency and incidents

An assessment is a point-in-time result. Before relying on it, check that its manifest, policy and clock still match, and that no unresolved incident applies:

```sh
node bin/kya.mjs currency \
  --assessment ./artifacts/assessment/assessment.json \
  --manifest ./manifest.json \
  --policy ./policy.json \
  [--incidents ./incidents.json] \
  [--now 2026-10-14T16:41:00.000Z]
```

A fired trigger (`subject-changed`, `policy-changed`, `subject-revoked`, `assessment-expired`, `assessment-aged`, `clock-regression` or `incident-open`) returns `action: reassess` and exit code 2. `reliable` is true only for a qualified decision with no trigger. Incident records (`kya.incident/v1`) are Ed25519-signed under their own prefix, and only keys listed as trust anchors in the policy count. No CLI command creates them yet; the library function `signIncident` does. A policy with `requirePrincipalBinding: true` withholds qualification from a manifest without a declared `principal.accountableParty`, which is a pseudonymous `{kind, ref}` and is not verified. Step-by-step commands with real output are in the [relying-party quickstart](docs/QUICKSTART-RELYING-PARTY.md).

## Adoption tooling

- **Gate a pipeline on a policy:** `kya check` (and a composite GitHub Action in [`action/`](action/README.md)) turns an assessment and currency check into exit codes, annotations and a step summary. See [GITHUB-ACTION.md](docs/GITHUB-ACTION.md). The action has not yet run on a real GitHub runner.
- **Start from a policy template:** `kya policy-init` builds a conservative policy for code agents, agentic payments or read-only assistants. Templates are starting points with unvalidated thresholds and make no agent safe. See [POLICY-TEMPLATES.md](docs/POLICY-TEMPLATES.md).
- **Run a frozen campaign:** `kya campaign` records a signed, append-only planned-attempt ledger before any attempt runs, so omitted attempts stay visible in the denominator ([ADR-0021](docs/adr/0021-capture-issuer-role-and-campaign-ledger.md)). It implements only the ledger slice of [ADR-0017](docs/adr/0017-measured-signed-capture-attestation.md); measured capture is not built.
- **Carry results in W3C credentials:** `kya vc` exports an assessment as a VC 2.0 `vc+jwt` with Bitstring Status List revocation. It proves key possession, not truthful execution ([VC-BRIDGE.md](docs/VC-BRIDGE.md)).
- **Beyond the 18 public checks:** [scenario suites](docs/SCENARIO-SUITES.md) with synthetic incident reconstructions and commit-reveal holdouts, outside the pinned core evaluator.
- **Plan:** [WORLD-CLASS-PLAN.md](docs/WORLD-CLASS-PLAN.md) and [STANDARDIZATION-STRATEGY.md](docs/STANDARDIZATION-STRATEGY.md).

## Evidence before reputation

<img src="assets/evidence-flow.svg" alt="Bind the exact subject, verify signed evidence, enforce your trust policy, explain a scoped decision." width="1200" />

| Question | Implemented boundary |
| :--- | :--- |
| Which system was assessed? | Full-manifest digest binds agent, controller reference, harness, model, tools, configuration and scope. |
| Who supplied the evidence? | Ed25519 receipts match out-of-band policy trust anchors. Signer roles come from policy. |
| Can bad results disappear? | Every frozen check stays in the denominator. One latest whole run is selected. Tied latest runs cannot qualify. |
| Can a high average hide harm? | Critical failures block qualification. Missing, errored and abstained checks stay unresolved. |
| Is the evidence relevant now? | Exact profile/evaluator/system/scope binding, expiry, freshness and revocation are enforced. |
| Can someone challenge the result? | Per-check references, rejection reasons and exact digests support replay, correction, appeal and revocation. |
| Can the research branch? | Content-addressed universes freeze inputs, time and implementation bytes; explicit-hypothesis forks preserve parents, replay and correction lineage. |

Six dimensions: **identity, authority, security, reliability, accountability and operations**. The reference profile has 18 equal-weight checks. That is an auditable starting choice, not a statistically validated universal weighting. Scores run 0–1000; every result also exposes coverage, optimistic upper bound, dimensions and critical gates. Decisions are `qualified`, `blocked`, `insufficient-evidence`, `expired` or `revoked`.

**Qualification is local policy satisfaction. It is not verified human identity, actual runtime permission, universal safety or a person's creditworthiness.** A signature proves integrity and signing-key possession, not truthful execution. Independent signer roles are policy assignments; organizational independence needs separate verification. The suite observes structured action attempts and final output, not all underlying tool side-effects.

## A standardization path that can earn adoption

The vision is broader than a single scoring service: interoperable passports, independently operated assessors, explicit relying-party policy, issuer accountability, reproducible comparisons and a shared correction protocol. Scores should travel with their evidence and limits. No central authority should quietly redefine a person's agent reputation.

[Open-KYA](https://github.com/open-kya/kya-standard) explores agent identity in alpha incubation. [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/) supplies a credential data model. [A2A](https://a2a-protocol.org/latest/specification/) and [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) address other agent and tool interaction concerns. This project explores the executable assessment layer. These efforts can complement one another; no affiliation, certification or adoption is asserted.

To become a useful standard, the protocol needs independent implementations, public interoperability cases, protected evaluation, real use-case calibration, accessible governance and external critique. [Roadmap](docs/ROADMAP.md) defines those gates. A future credential bridge must preserve exact digests and source class; it cannot turn a declaration into measured evidence.

## Built to be challenged

This clean-room implementation applies evidence-first engineering: exact revisions, replayable tests, visible uncertainty, independently reviewed promotion and reversible change. Private product code, client records, credentials and operational logs are excluded.

Tests exercise tampering, malformed and duplicate JSON, untrusted signing, wrong bindings, expiry/revocation, run cherry-picking, unknown coverage, declaration laundering, critical failures, HTML injection and bounded command transport. Evaluator mutation tests must detect weakened gates. Passing public cases alone cannot establish general safety; colluding issuers, strategic run omission and suite contamination remain threats. The [requirement registry](docs/REQUIREMENTS.md) lists every normative requirement with its test traces, each traced to tests that the gate checks for staleness; CI fails on any skipped or `todo` test. `scripts/mutation-check.mjs` applies named gate mutations to the assessment and incident code and requires each to be detected. [Threat model](docs/THREAT-MODEL.md) lists what is not mitigated.

Research can fork without rewriting its past. [Universes](docs/UNIVERSES.md) hash every bundled executable module, package routing, exact input evidence and assessment time. Replay recomputes the result under that implementation. Comparisons refuse changed decision contracts and incomplete case populations. Correction references expose affected descendants, while actual revocation stays in relying policy.

```sh
node scripts/golden-vectors.mjs --check
node scripts/mutation-check.mjs
node bin/kya.mjs universe --inputs frozen-inputs.json --question "Frozen baseline" --out baseline.json
node bin/kya.mjs fork --parent baseline.json --patch candidate-patch.json --out candidate.json
node bin/kya.mjs replay candidate.json
node scripts/pack.mjs
node scripts/verify-release.mjs
```

The package builder reads immutable Git blobs from a clean committed revision, fixes archive metadata, and records every file's SHA-256. Golden vectors expose canonical bytes and domain-separated Ed25519 signatures for independent implementations. A valid hash is integrity evidence; authenticated issuance, truthful execution and full incident disclosure need separate evidence.

A secondary [Python byte checker](docs/INTEROPERABILITY.md) reconstructs the public vectors without forwarding expected answers. It verifies Ed25519 when an existing cryptographic backend is available and otherwise reports partial verification. Its supported numeric subset is explicit; unsupported doubles are refused. This is a second implementation by this project team, with external implementers and full semantic assessment parity still needed.

Contribute reproducible failures, evaluator challenges, transport adapters or specification criticism. Read [CONTRIBUTING.md](CONTRIBUTING.md), [governance](docs/GOVERNANCE.md) and [SECURITY.md](SECURITY.md). Ongoing development uses bounded hypotheses, frozen comparisons, independent review and explicit `ACCEPT`, `REJECT` or `INCONCLUSIVE` outcomes. A roadmap does not imply a running scheduler. Public releases, cost-incurring agent executions and deployments need explicit authorization.

## What this is not

- Not an adopted standard, certification or endorsement. No external review or second independent implementation exists yet.
- Not verified human identity, legal authority or liability. `accountableParty` is a self-declared, pseudonymous reference that policy can require but cannot verify.
- Not proof of truthful execution. A signature proves key possession and report integrity, not what an agent actually did.
- Not a live revocation service. Revocation is whatever the relying policy snapshot says.
- Not continuous monitoring. Currency checks only the supplied manifest, policy, incidents and clock. They observe no runtime behavior, and an incident nobody supplies is invisible.
- Not an appeals process. Appeals are recorded and never clear a trigger.
- Not a measurement of any commercial agent. Demo and benchmark outputs are synthetic fixtures.
- Not an authorization grant, and never a credit or worth score for a person.

Apache-2.0. [License](LICENSE) · [Notice](NOTICE)
