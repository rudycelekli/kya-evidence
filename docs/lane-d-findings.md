# Lane D findings: property based and fuzz testing

Scope: dependency free seeded property tests for canonicalization, the validators, signing, incident/currency evaluation and assessment scoring. Files: `test/helpers-fuzz.mjs`, `test/property-canonical.test.mjs`, `test/property-validators.test.mjs`, `test/property-signing.test.mjs`, `test/property-assessment.test.mjs`.

## Result

One real defect was found (F-1, low to medium severity, incident evaluation). It only appeared at 20x the default run count (seed 12648430, case 163 of 1000), which is why the default run is green: the property that exposes it is narrowed with a comment citing F-1. Four further behaviours worth a maintainer decision are recorded as observations (O-1 to O-4). No source file was changed and no failing test is committed.

## F-1 A future-dated low copy of a report ID is ignored when judging ambiguity, so a resolved report reopens as time passes

Rule (comment in `src/assessment/application/currency.mjs`): a resolution may target a report only when exactly one report carries that ID; equivocation and ID reuse fail closed, reports stay open and resolutions are listed as ambiguous. Observed: the duplicate-ID check counts all eligible reports, but `live` then drops a future-dated non-blocking report, so the remaining high or critical report appears unique and the resolution closes it. The result also contradicts itself: it lists `Conflicting records share an ID; reports kept open, resolutions cannot target them` while `open` is empty and `resolved` contains the ID. Once the clock passes the duplicate's date, the same inputs reopen the report, so `current` flips from true to false with no new record.

Failing property (narrowed out of the suite): "an unresolved trusted blocking report whose ID is shared by more than one eligible report stays open". Reproduce with `KYA_FUZZ_SEED=12648430 KYA_FUZZ_RUNS=2000` against the unnarrowed invariant (count all eligible copies, not only live ones in `test/property-assessment.test.mjs`), or run this minimal case from the repository root:

```
node --input-type=module -e "
import { generateKeyPairSync } from 'node:crypto';
import { assess, checkCurrency, signIncident, keyId, hashBytes } from './src/index.mjs';
import { inputs, keys } from './test/helpers.mjs';
const i = inputs(), rv = generateKeyPairSync('ed25519'), pem = rv.publicKey.export({ format:'pem', type:'spki' }).toString();
i.policy.trustedKeys.push({ id:keyId(pem), publicKey:pem, role:'independent' });
const report = assess(i);
const rec = (key, patch) => signIncident({ schema:'kya.incident/v1', id:'inc:1', subjectDigest:report.subjectDigest, kind:'report', severity:'critical', refId:null, reportedAt:'2026-10-13T12:00:30.000Z', detailsDigest:hashBytes('d'), ...patch }, key);
const incidents = [rec(keys.privateKey, {}), rec(rv.privateKey, { id:'res:1', kind:'resolution', severity:'low', refId:'inc:1', reportedAt:'2026-10-13T12:10:00.000Z' }), rec(keys.privateKey, { severity:'low', reportedAt:'2026-10-13T12:40:00.000Z', detailsDigest:hashBytes('dup') })];
for (const now of ['2026-10-13T12:30:00.000Z', '2026-10-13T12:50:00.000Z']) { const r = checkCurrency(report, { manifest:i.manifest, policy:i.policy, now, incidents }); console.log(now, 'current', r.current, 'open', r.incidents.open, 'resolved', r.incidents.resolved); }"
```

Prints `current true open [] resolved [ 'inc:1' ]` at 12:30 and `current false open [ 'inc:1' ] resolved []` at 12:50. Suggested fix: judge ambiguity over the same set that `targets` uses (or over all eligible reports) so both views agree; then a future-dated duplicate also fails closed. Impact is bounded: it needs a trusted key to emit the duplicate and an independent resolver to have resolved the report; it can only make a legitimately resolved report look resolved earlier than the fail-closed rule says, and the time flip is surprising for a reliance check.

## How the suite runs

- PRNG: mulberry32 written in `test/helpers-fuzz.mjs`. Default seeds: `12648430` (0xC0FFEE), `20261014`, `7`.
- `KYA_FUZZ_SEED=<int[,int]>` replaces the seed list. `KYA_FUZZ_RUNS=<int>` replaces the base run count (default 100); each property requests `weight` cases per seed, scaled by `RUNS/100`. Example: `KYA_FUZZ_RUNS=2000` is 20x.
- A failure message starts with `[KYA_FUZZ_SEED=<seed> case=<n> of <total>]`. Reproduce with `KYA_FUZZ_SEED=<seed> node --test test/property-<file>.test.mjs`.
- `KYA_FUZZ_STATS=1` prints how often interesting branches (open, resolved, appealed incidents; each assessment decision) were reached.
- Default cases per seed (times 3 seeds, 38 properties in total): canonical 13 properties (6 to 400 cases each), validators 12 (60 to 150), signing 7 (25 to 50), assessment 6 (40 to 60).

## Defects

F-1 above. Nothing else. Run history: default seeds at 20x (`KYA_FUZZ_RUNS=2000`, 38 properties, about 2.3 minutes) passes after F-1 is narrowed and two test-side mistakes found by that run were fixed (an overly strong decision monotonicity claim, see O-4, and an unsafe-integer perturbation in the generator). Seeds `101,202,303,404` at `KYA_FUZZ_RUNS=1000` exposed one more over-strong assertion (order independence of role fields under tied observations, see O-2), now narrowed.

Checks that were deliberately made strong enough to detect weakening: a scratch copy of `src/` was mutated 15 ways (dropping the reporter-cannot-resolve rule, the independent-role rule, the strict-after-time rule, the future-dated skip, the trust-anchor skip, the ambiguous-reference rule, critical-failure blocking, critical-unknown handling, the fixed denominator, evidence domain separation, duplicate-key rejection, key sorting, expiry strictness, case-insensitive accountable party, and lowercase-only hashes). Every mutant was killed by at least one property. The mutated copy lived outside the repository and was discarded.

Things that were probed and held:
- Single mutations of manifest, policy, evidence, profile and incident (delete, add, rename, retype, truncate, extend, case flip, boundary length, odd strings, malformed and shifted timestamps): every result either threw or was a fixed point (`validate(validate(x))` deep equals `validate(x)`), the input was never modified, and unknown members, renamed or retyped members, and enum/hash alterations always threw.
- Exact oracles for text/identifier length limits, timestamp ordering over 1970 to 9999, manifest permission set rules, and policy numeric bounds.
- Signing: round trip, deterministic signatures, every single bit of the signature, bit flips of the signed payload, key or proof swaps, wrong prefixes and cross-domain signatures between evidence and incident, and Ed25519 `S + L` malleation (rejected).
- `checkCurrency`: an independent restatement of the documented incident rules agrees with `evaluateIncidents` on random sets; permutation and duplicate delivery do not change the open, resolved, appealed or observed sets, triggers, `current`, `reliable` or `action`; untrusted-key, other-subject and malformed records are inert.
- `assess`: the check list always equals the profile; scores are exact integer arithmetic; `earned <= upperBound <= 1000`; removing evidence from a conflict free single run never raises the earned score or creates a qualification; a critical failure never yields `qualified`.
- `parseJson` is a strict subset of `JSON.parse` under differential fuzzing of mutated documents (every extra rejection has a documented reason: duplicate or forbidden member, unsafe number, resource limit).

## Observations (not defects, documented behaviour is silent)

### O-1 Lone surrogates are accepted by `canonical`
`canonical('\ud800')` returns `"\ud800"` (an ASCII escape, deterministic, round trips through `JSON.parse` and `parseJson`). The specification does not say whether lone surrogates should be rejected. Implementations that cannot encode them to UTF-8 (or that normalise them to U+FFFD) would disagree on the bytes being hashed. A well formed string never produces this. Suggested decision: reject in `canonical` or state the behaviour in the specification. The suite pins the current behaviour (test title says documented behaviour: accepted); change it together with the decision.

### O-2 Tied duplicate observations resolve by bundle order
Two observations of one check in the selected run with the same outcome and the same `observedAt` are tie broken by array position. Which one is reported changes `checks[].evidenceId`, `keyId`, `independence`, `independentCoverage` and `acceptedEvidenceDigests`. The decision, `score`, `coverage` and blockers do not change, because a repeated check in the selected run already forces `insufficient-evidence` (or a higher precedence decision such as `blocked` applies) (verified over random bundles by the order independence property). Only the reported evidence identity and role fields depend on order.

### O-3 The `ignored` list of `checkCurrency` follows input order
The sets that drive the decision are order independent, but `incidents.ignored` is emitted in input order, so `JSON.stringify` of the whole result (and any digest of it) differs for permuted input. Repro, from the repository root:

```
node --input-type=module -e "
import { generateKeyPairSync } from 'node:crypto';
import { assess, checkCurrency, signIncident, hashBytes } from './src/index.mjs';
import { inputs } from './test/helpers.mjs';
const i = inputs(), report = assess(i), k = generateKeyPairSync('ed25519');
const rec = id => signIncident({ schema:'kya.incident/v1', id, subjectDigest:report.subjectDigest, kind:'report', severity:'low', refId:null, reportedAt:'2026-10-13T12:10:00.000Z', detailsDigest:hashBytes('d') }, k.privateKey);
const run = incidents => checkCurrency(report, { manifest:i.manifest, policy:i.policy, now:'2026-10-13T12:30:00.000Z', incidents });
const a = run([rec('inc:a'), rec('inc:b')]), b = run([rec('inc:b'), rec('inc:a')]);
console.log(a.incidents.ignored.map(x => x.id), b.incidents.ignored.map(x => x.id), JSON.stringify(a) === JSON.stringify(b));"
```

Prints `[ 'inc:a', 'inc:b' ] [ 'inc:b', 'inc:a' ] false`. Sorting `ignored` before returning would make the whole report canonical. The property compares the sorted list so it stays green.

### O-4 Omitting an invalid record can lift the invalidated-evidence veto
When the latest run contains bound but invalid evidence (stale, expired, revoked, disallowed source), `assess` returns `insufficient-evidence` ("no fallback qualification"). Removing exactly that record from the bundle yields `qualified` for the remaining valid checks. This is the same undetectable omission limit that `checkCurrency` states for incidents; the supplier of the bundle chooses its contents. The monotonicity property therefore only asserts the decision claim for bundles with no rejected record, and still asserts the earned score claim for every conflict free single run bundle.

Minor, no action needed: `canonical(-0)` is `0`, so `-0` and `0` share a digest; raw U+2028 and U+2029 pass through unescaped (legal JSON); a PEM with CRLF line endings verifies and yields the same key id as the LF form.

## Not covered

- Cryptographic soundness of Node's Ed25519 beyond the cases above (no known-answer vectors beyond the repository's existing tests).
- Multi-run assessment monotonicity: omitting a newer failing run can raise the score by design (latest whole run wins) and an omitted record is undetectable, so no property asserts it.
- Policy minimum comparisons against the rounded `coverage` field (the gate uses the unrounded ratio).
- CLI, adapters, native transports, conformance runner, dossier rendering, benchmarks and schemas in `schemas/` versus the validators.
- Inputs above one million bytes are covered only at the boundary, not with random content; Proxy-based time-of-check attacks are covered by existing scripted tests, not by fuzzing.
- Concurrency and clock behaviour of `new Date()` defaults.
