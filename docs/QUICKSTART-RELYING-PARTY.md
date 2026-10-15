# Relying-party quickstart

This walks through what a relying party does with KYA Evidence: produce an assessment, check that it is still current, handle an incident, and require a declared accountable party. Each command was run in order from a fresh directory on this revision. Outputs are trimmed. Timestamps differ on every run, because the demo stamps its manifest with the current clock.

Everything here uses synthetic fixtures. The demo agent is not a real product, and its evidence is signed by a throwaway key that the demo policy trusts. For a real decision, use frozen inputs of your own and trust anchors you have verified.

## Setup

Requires Node.js 22 or later. No dependencies are installed. The commands use two shell variables. `KYA` is your checkout, and `WORK` is an empty directory outside the checkout.

```sh
export KYA=/path/to/kya-evidence
export WORK=$HOME/kya-rp-example
mkdir -p "$WORK"
```

Every `--out` directory is created with exclusive writes, so use a new directory each time you re-run a step.

## 1. Produce a fixture assessment and fix the clock

```sh
node "$KYA/bin/kya.mjs" demo --out "$WORK/demo"
export NOW=$(node -e "console.log(new Date().toISOString())")
echo "$NOW"
```

The demo prints a qualified fixture decision:

```json
{
  "out": "…/kya-rp-example/demo",
  "decision": "qualified",
  "fixtureOnly": true,
  "score": { "earned": 1000, "possible": 1000, "upperBound": 1000 }
}
```

The folder holds seven files: `manifest.json`, `policy.json`, `evidence.json`, `observations.json`, `profile.json`, `assessment.json` and `assessment.html`.

Use the same `NOW` value for every later step. The demo's manifest is valid from its issue time, so an earlier `--now` makes the assessment read as "not yet valid".

## 2. Create three keys

```sh
node "$KYA/bin/kya.mjs" keygen "$WORK/keys/monitor"
node "$KYA/bin/kya.mjs" keygen "$WORK/keys/reviewer"
node "$KYA/bin/kya.mjs" keygen "$WORK/keys/issuer"
```

```json
{"keyId":"add94fff…","out":"…/keys/monitor","warning":"Keep private.pem private; trust role is assigned by the relying party"}
```

Keep every `private.pem` secret. A key carries no role. Your policy decides whether a key is trusted and in what role.

## 3. Generate the policies, incidents and accountable-party inputs

Save the script below as `make-example.mjs` outside the checkout, then run it with the same variables:

```sh
KYA="$KYA" WORK="$WORK" NOW="$NOW" node make-example.mjs
```

It writes `policy-incident.json` (the monitor is trusted as `self` and the reviewer as `independent`), `policy-principal.json` and `policy-party.json` (both require a declared accountable party), `incidents-open.json` and `incidents-resolved.json`, `manifest-party.json` and `evidence-party.json`. Policies keep the demo trust anchor, so the demo evidence still verifies. Incident records are created with `signIncident`, which is a library function, because no CLI command creates them yet.

```js
// make-example.mjs: quickstart generator. Requires KYA, WORK and NOW in the environment.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const { KYA, WORK, NOW } = process.env;
const at = (ms) => new Date(Date.parse(NOW) + ms).toISOString();
const { signIncident, signEvidence, hashBytes, keyId } = await import(pathToFileURL(`${KYA}/src/index.mjs`).href);
const { runConformance, createReferenceAdapter, CORE_PROFILE } = await import(pathToFileURL(`${KYA}/src/conformance/index.mjs`).href);

const read = (p) => JSON.parse(readFileSync(p, 'utf8'));
const write = (p, v) => writeFileSync(p, JSON.stringify(v, null, 2) + '\n');
const pem = (k, file) => readFileSync(`${WORK}/keys/${k}/${file}.pem`, 'utf8');
const entry = (k, role) => ({ id: keyId(pem(k, 'public')), publicKey: pem(k, 'public'), role });

// Policies: the demo trust anchor stays, plus extra anchors or the principal flag.
const P0 = read(`${WORK}/demo/policy.json`);
write(`${WORK}/policy-incident.json`, { ...P0, id: 'rp-example-incident', trustedKeys: [...P0.trustedKeys, entry('monitor', 'self'), entry('reviewer', 'independent')] });
write(`${WORK}/policy-principal.json`, { ...P0, id: 'rp-example-principal', requirePrincipalBinding: true });
write(`${WORK}/policy-party.json`, { ...P0, id: 'rp-example-party', trustedKeys: [entry('issuer', 'self')], requirePrincipalBinding: true });

// Incidents: a high-severity report from the monitor, resolved by the independent reviewer.
const subjectDigest = read(`${WORK}/demo/assessment.json`).subjectDigest;
const report = { schema: 'kya.incident/v1', id: 'inc-2026-0001', subjectDigest, kind: 'report', severity: 'high', refId: null, reportedAt: at(-600000), detailsDigest: hashBytes('Private note: unexpected write-local attempt, held offline') };
const resolution = { schema: 'kya.incident/v1', id: 'res-2026-0001', subjectDigest, kind: 'resolution', severity: 'high', refId: 'inc-2026-0001', reportedAt: at(-300000), detailsDigest: hashBytes('Private note: reporter trace reproduced, scope unchanged') };
const open = [signIncident(report, pem('monitor', 'private'))];
write(`${WORK}/incidents-open.json`, open);
write(`${WORK}/incidents-resolved.json`, [...open, signIncident(resolution, pem('reviewer', 'private'))]);

// Accountable-party manifest, and fresh evidence for it, because the subject digest changes.
const manifest = read(`${WORK}/demo/manifest.json`);
manifest.principal = { ...manifest.principal, accountableParty: { kind: 'natural-person', ref: 'person-ref-0001' } };
write(`${WORK}/manifest-party.json`, manifest);
const run = await runConformance({ adapter: createReferenceAdapter({ mode: 'careful' }), manifest, profile: CORE_PROFILE, now: NOW });
write(`${WORK}/evidence-party.json`, run.evidence.map((p) => signEvidence(p, pem('issuer', 'private'))));
console.log(JSON.stringify({ policies: 3, incidentsOpen: open.length, incidentsResolved: 2, evidence: run.evidence.length }));
```

The evaluator digest used below is the demo's `evaluatorDigest`, which `demo/assessment.json` also records.

## 4. Assess under the incident policy and check currency with no incidents

```sh
node "$KYA/bin/kya.mjs" assess \
  --manifest "$WORK/demo/manifest.json" \
  --profile "$WORK/demo/profile.json" \
  --policy "$WORK/policy-incident.json" \
  --evidence "$WORK/demo/evidence.json" \
  --evaluator d0bc7f7840e5ddf1a71eb3b9ac92e5c4d0be5d156eea2c6f4f909f7066b5e31b \
  --now "$NOW" \
  --out "$WORK/assess-incident"
```

```json
{"out":"…/assess-incident","decision":"qualified","score":{"earned":1000,"possible":1000,"upperBound":1000}}
```

Exit code: 0. Now check currency against the same policy, with no incident records:

```sh
node "$KYA/bin/kya.mjs" currency \
  --assessment "$WORK/assess-incident/assessment.json" \
  --manifest "$WORK/demo/manifest.json" \
  --policy "$WORK/policy-incident.json" \
  --now "$NOW"
```

```json
{
  "schema": "kya.currency/v1",
  "current": true,
  "reliable": true,
  "action": "none",
  "triggers": [],
  "incidents": { "considered": 0, "open": [], "resolved": [], "appealed": [], "observed": [], "ignored": [] },
  "authenticated": false
}
```

Exit code: 0.

### Authenticate a received assessment

An `assessment.json` handed to you is a report with an unauthenticated checksum; its `reportDigest` proves nothing about who made it. To authenticate it, re-run `assess` yourself on inputs you trust, with the received `assessedAt` as `--now`, and compare `reportDigest`:

```sh
node "$KYA/bin/kya.mjs" assess \
  --manifest "$WORK/demo/manifest.json" \
  --profile "$WORK/demo/profile.json" \
  --policy "$WORK/policy-incident.json" \
  --evidence "$WORK/demo/evidence.json" \
  --evaluator d0bc7f7840e5ddf1a71eb3b9ac92e5c4d0be5d156eea2c6f4f909f7066b5e31b \
  --now <assessedAt from the received assessment.json> \
  --out "$WORK/assess-recheck"
```

Then compare `reportDigest` in `$WORK/assess-recheck/assessment.json` with the one in the received file. Assessment is deterministic for a fixed clock, so identical inputs and the same `assessedAt` give the same digest (tried with the demo inputs: the digests were equal). A match shows the received report is what your policy and the evidence produce; it does not show that the evidence is honest. A mismatch means some input, the evaluator or the clock differs; it does not say which.

## 5. Check currency with an open high-severity incident

`incidents-open.json` holds one report signed by the monitor key. Run currency with it:

```sh
node "$KYA/bin/kya.mjs" currency \
  --assessment "$WORK/assess-incident/assessment.json" \
  --manifest "$WORK/demo/manifest.json" \
  --policy "$WORK/policy-incident.json" \
  --incidents "$WORK/incidents-open.json" \
  --now "$NOW"
```

```json
{
  "current": false,
  "reliable": false,
  "action": "reassess",
  "triggers": [{ "id": "incident-open", "detail": "1 unresolved high or critical incident record(s) for this subject" }],
  "incidents": { "considered": 1, "open": ["inc-2026-0001"], "resolved": [], "appealed": [], "observed": [], "ignored": [] }
}
```

Exit code: 2. The reporter cannot resolve its own report.

## 6. Resolve the incident with the independent reviewer

`incidents-resolved.json` adds a resolution signed by the reviewer key. It must name the report in `refId`, be dated after the report, and come from a key with the `independent` role. Check again:

```sh
node "$KYA/bin/kya.mjs" currency \
  --assessment "$WORK/assess-incident/assessment.json" \
  --manifest "$WORK/demo/manifest.json" \
  --policy "$WORK/policy-incident.json" \
  --incidents "$WORK/incidents-resolved.json" \
  --now "$NOW"
```

```json
{
  "current": true,
  "reliable": true,
  "action": "none",
  "triggers": [],
  "incidents": { "considered": 2, "open": [], "resolved": ["inc-2026-0001"], "appealed": [], "observed": [], "ignored": [] }
}
```

Exit code: 0. An appeal signed by any trusted key would appear under `appealed` and would not change this result.

## 7. Require a declared accountable party

`policy-principal.json` sets `requirePrincipalBinding: true`. The demo manifest declares no `accountableParty`, so the assessment is withheld:

```sh
node "$KYA/bin/kya.mjs" assess \
  --manifest "$WORK/demo/manifest.json" \
  --profile "$WORK/demo/profile.json" \
  --policy "$WORK/policy-principal.json" \
  --evidence "$WORK/demo/evidence.json" \
  --evaluator d0bc7f7840e5ddf1a71eb3b9ac92e5c4d0be5d156eea2c6f4f909f7066b5e31b \
  --now "$NOW" \
  --out "$WORK/assess-principal"
```

Exit code: 2. The stored `assessment.json` contains `"decision": "insufficient-evidence"` and the blocker `Policy requires a declared accountable party; manifest declares none`.

`manifest-party.json` declares `{"kind": "natural-person", "ref": "person-ref-0001"}` under `principal`. The declaration changes the subject digest, so the demo evidence no longer binds. `evidence-party.json` was re-issued for the new manifest by the issuer key. Assess with the party-declaring manifest under `policy-party.json`, which trusts only the issuer key:

```sh
node "$KYA/bin/kya.mjs" assess \
  --manifest "$WORK/manifest-party.json" \
  --profile "$WORK/demo/profile.json" \
  --policy "$WORK/policy-party.json" \
  --evidence "$WORK/evidence-party.json" \
  --evaluator d0bc7f7840e5ddf1a71eb3b9ac92e5c4d0be5d156eea2c6f4f909f7066b5e31b \
  --now "$NOW" \
  --out "$WORK/assess-party"
```

```json
{"out":"…/assess-party","decision":"qualified","score":{"earned":1000,"possible":1000,"upperBound":1000}}
```

Exit code: 0. The report keeps `principalId` (here `controller:local-fixture`), but it does not contain `accountableParty`. The declaration is part of the subject digest, and a reviewer reads it in `manifest-party.json`.

Checking the earlier assessment against the party-declaring manifest shows the change:

```sh
node "$KYA/bin/kya.mjs" currency \
  --assessment "$WORK/assess-incident/assessment.json" \
  --manifest "$WORK/manifest-party.json" \
  --policy "$WORK/policy-incident.json" \
  --now "$NOW"
```

The result has `"current": false`, `"action": "reassess"`, and the trigger `subject-changed`. Exit code: 2.

## 8. Expiry

An assessment is valid until `validUntil`, which is one hour after `assessedAt`. Checking two hours later fires `assessment-expired`:

```sh
export LATER=$(node -e "console.log(new Date(Date.parse(process.env.NOW) + 7200000).toISOString())")
node "$KYA/bin/kya.mjs" currency \
  --assessment "$WORK/assess-party/assessment.json" \
  --manifest "$WORK/manifest-party.json" \
  --policy "$WORK/policy-party.json" \
  --now "$LATER"
```

Result: `"current": false`, trigger `assessment-expired`. Exit code: 2.

## Exit codes and limits

- `assess` exits 0 for `qualified` and 2 otherwise. `currency` exits 0 when current and 2 when any trigger fires. A usage or input error exits 1 with a message on stderr.
- `currency` reports `"authenticated": false`. The report checksum is not a signature, so recompute the assessment from your own trusted inputs before relying on it.
- A current, reliable result is not an authorization grant. It states only that the supplied configuration, policy, incidents and clock were consistent when checked.
