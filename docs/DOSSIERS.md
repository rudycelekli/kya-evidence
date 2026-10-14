# An agent dossier you can inspect and replay

A dossier explains one exact system, scope, frozen policy and supplied evidence population. It contains the assessment, replay-supported response strengths, failed predicates, unresolved checks, telemetry coverage and persistent observation limits. It does not grant execution authority or predict a person's creditworthiness.

## Generate and verify

```sh
node bin/kya.mjs diagnose --mode reckless --with-benchmarks true --out .kya/dossier
node bin/kya.mjs dossier-verify --dossier .kya/dossier/dossier.json \
  --inputs .kya/dossier/inputs.json --observations .kya/dossier/observations.json \
  --benchmarks .kya/dossier/benchmark-run.json
```

`diagnose` executes an owned synthetic fixture. Its `careful`, `reckless`, `silent` and `gaming` modes are local reference behaviors. They do not measure commercial agents. The output directory contains machine JSON, readable Markdown, offline printable HTML, frozen inputs and observation originals. When requested, it also contains the public evaluator-control run. No signing private key is exported. No model account, network or provider call is required.

For your own authorized evidence:

```sh
node bin/kya.mjs dossier --inputs frozen-inputs.json \
  --observations originals.json --out .kya/assessment-dossier
node bin/kya.mjs dossier-verify --dossier .kya/assessment-dossier/dossier.json \
  --inputs frozen-inputs.json --observations originals.json
```

Frozen inputs contain exactly `manifest`, `profile`, `policy`, `evidence`, `evaluatorDigest` and canonical UTC `now`. Evidence contains signed receipt envelopes. Originals use the existing `kya.observation/v1` shape, not arbitrary transcripts. Optional originals or benchmark arrays may be omitted; explicit null populations are refused. Creation snapshots caller input once under the strict canonical resource budget. Maximum populations are 4,096 supplied originals and eight attached benchmark runs, subject to the aggregate canonical byte limit.

```js
import { createDossier, verifyDossier, renderDossierHtml,
  runOfflineBenchmarks } from 'kya-evidence';

const controls = await runOfflineBenchmarks({ now: frozenInputs.now });
const dossier = createDossier({ inputs: frozenInputs,
  observations: originals, benchmarkRuns: [controls] });
const verification = verifyDossier(dossier, { inputs: frozenInputs,
  observations: originals, benchmarkRuns: [controls] });
const html = renderDossierHtml(dossier);
```

## Findings and their reach

| Field | What it supports | Limit |
| :--- | :--- | :--- |
| `reportedPasses` | Selected receipts assert passed checks under policy | A trusted signer can still make a false assertion |
| `strengths` | Matching original structured responses pass the supported frozen core predicate again | Response replay does not independently observe tool effects |
| `failureModes` | Selected checks failed; criticality and bounded replay reasons stay visible | A failed predicate does not establish a causal root cause |
| `assessment.checks` with unknown, abstain or error status | Required checks remain unresolved and feed check-specific blind spots | Missing measurement is not an observed agent failure |
| `blindSpots` | Specific missing channels and permanent trust boundaries | Completing the public suite does not resolve them |
| `benchmarkRuns` | Attached local evaluator controls are internally replayed | Neither external authentication nor protected evaluation |

Only originals matching a selected, accepted signed receipt can support detailed findings. Receipt ID, run, check, subject, scope, profile, evaluator, observation time and artifact digest are checked. Duplicate originals for the same run/check are all quarantined. Nonselected, malformed, contradictory or changed originals remain explicit rejections.

For the supported core profile/evaluator, KYA reconstructs the exact request and re-evaluates the structured response. Request-digest mismatch or a claimed outcome contradicting replay is quarantined. Diagnostics use bounded predicate codes; raw response text, arbitrary reason prose and private error messages are excluded. Other supported signed assertions do not acquire response-replayed strength merely because their signatures are valid. A matching error record is labelled separately.

Every failure currently records `rootCause: 'not-established'`. Proposed explanations need a separately recorded hypothesis and controlled intervention before becoming causal findings. Suggested next measurements remain requests for evidence, never claims of completed verification.

## Metrics retain their populations

Reported cost and transport latency distinguish known count, missing count, subtotal and complete total. A zero is retained as measured zero; null is retained as unknown. A subtotal of zero with a missing attempt cannot become a complete zero-cost run. Nonfinite, negative or unrepresentable aggregates cannot become fabricated totals. Telemetry counts cannot exceed the verified original population, while every required check remains in the planned denominator.

Cost is producer-reported USD. Latency is transport timing reported in the original. Neither field independently reconciles billing, model retries, infrastructure cost, human oversight or tool work. These remain unmeasured unless collected through a separate authorized protocol. The score's optimistic `upperBound` is a logical unresolved-case bound, not a confidence interval.

## Verification has two levels

`validateDossier` checks strict shape, checksum, report consistency, partition counts, measurement populations and renderer-safe projections. Renderers call it before producing output. It rejects, among other cases, altered benchmark summaries, invented complete measurements over missing originals, and a `qualified` narrative with retained critical failures. Standalone validity remains unauthenticated: an attacker can construct another internally consistent record.

`verifyDossier` takes the trusted original inputs, observations and attached controls. It recomputes the assessment and entire dossier and compares the complete body. It refuses altered claims and implementation mismatches. Successful replay still returns `authenticated:false`, `actualEffectsVerified:false` and `captureComplete:false`: the supplied sources and capture system need their own authority and truth evidence.

Source changes require the matching archived implementation for historical replay. Retain JSON, originals, release/source bytes and separate authority records together. [Research universes](UNIVERSES.md) preserve hypotheses and correction lineage; a dossier is a projection of one input population, not a global incident registry.

## Private review and public projection

The HTML is offline, contains no external fonts/scripts/assets, expands detail by default, escapes report values and includes a print stylesheet. Automated tests check source and output structure. Browser rendering and physical printing are separate validation steps.

Although raw responses are omitted, the dossier still exposes manifest labels, system identifiers, case IDs and the full assessment. Inspect and authorize a sanitized public projection before publication. Private research snapshots and original paths are excluded from the package. A hash or local retention permission does not grant publication rights.
