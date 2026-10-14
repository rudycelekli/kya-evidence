import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, symlink, readFile, readdir, rm, stat, writeFile, chmod } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createPlan, openLedger, appendEntry, verifyLedger as verifyStrict, summarizeCampaign, runCampaign, conformanceDigests } from '../src/campaign/index.mjs';
import { SCENARIOS, createReferenceAdapter, createCommandAdapter } from '../src/conformance/index.mjs';
import { markAdapter } from '../src/conformance/application/origins.mjs';
import { digest, hashBytes, keyId } from '../src/index.mjs';
import manifest from '../examples/manifest.json' with { type: 'json' };

const issuer = generateKeyPairSync('ed25519');
const issuerPem = issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const T0 = '2026-10-14T09:00:00.000Z', T1 = '2026-10-14T09:05:00.000Z';
const subjectDigest = digest(manifest);
const manifests = { [subjectDigest]: manifest };
const careful = { source: 'fixture', id: 'reference-careful', mode: 'careful' };
const repoRoot = fileURLToPath(new URL('../', import.meta.url));
const digests = conformanceDigests();
const capturePolicy = { schema: 'kya.policy/v1', id: 'runner-policy', profileDigest: digests.profileDigest, scopeId: manifest.scope.id, minCoverage: 1, minScore: 800, minIndependentCoverage: 0, allowedSources: ['fixture'], maxEvidenceAgeSeconds: 3600, trustedKeys: [{ id: keyId(issuerPem), publicKey: issuerPem, role: 'capture-issuer' }], revokedKeyIds: [], revokedEvidenceIds: [], revokedSubjectDigests: [] };
const verifyLedger = (ledger, options = {}) => verifyStrict(ledger, { policy: capturePolicy, ...options });
const planFor = (ids, adapter = careful, patch = {}) => createPlan({ campaignId: 'campaign:runner', useCase: 'Synthetic fixture campaign', ...digests, policyDigest: digest(capturePolicy), adapter, attempts: ids.map(attemptId => ({ attemptId, subjectDigest, scenarioSetDigest: digests.scenarioSetDigest, seed: null })), createdAt: T0, privateKey: issuer.privateKey, ...patch });
const ledgerFor = (ids, adapter, patch) => openLedger({ plan: planFor(ids, adapter, patch), privateKey: issuer.privateKey, now: T0 });
const scratch = () => mkdtemp(join(tmpdir(), 'kya-campaign-'));
const base = (ledger, dir, extra = {}) => ({ plan: ledger.plan, ledger, adapter: createReferenceAdapter({ mode: 'careful' }), manifests, policy: capturePolicy, privateKey: issuer.privateKey, privateDir: dir, clock: () => T1, ...extra });

test('campaign runner executes planned attempts through conformance and writes private 0600 bundles', async () => {
  const dir = await scratch();
  try {
    const result = await runCampaign(base(ledgerFor(['a-1', 'a-2']), dir));
    assert.deepEqual(result.results.map(r => r.outcome), ['completed', 'completed']);
    assert.equal(verifyLedger(result.ledger, { requireClosed: true }).valid, true);
    const summary = summarizeCampaign(result.ledger);
    assert.deepEqual([summary.planned, summary.completed, summary.errored, summary.abandoned, summary.unaccounted], [2, 2, 0, 0, 0]);
    const entry = result.ledger.entries.find(e => e.payload.kind === 'completed' && e.payload.attemptId === 'a-1').payload;
    const file = join(dir, 'a-1.bundle.json');
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const bytes = await readFile(file);
    assert.equal(hashBytes(bytes), entry.evidenceBundleDigest);
    const bundle = JSON.parse(bytes.toString('utf8'));
    assert.equal(bundle.runId, entry.runId);
    assert.equal(bundle.schema, 'kya.conformance-run/v1');
    assert.equal(bundle.evaluatorDigest, digests.evaluatorDigest);
    const ledgerText = JSON.stringify(result.ledger);
    for (const secret of ['SYNTHETIC', 'prompt', 'observations']) assert.ok(!ledgerText.includes(secret), `ledger leaked ${secret}`);
    assert.ok(existsSync(join(dir, 'a-2.bundle.json')));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign runner refuses adapter provenance that differs from the plan', async () => {
  const dir = await scratch();
  try {
    const ledger = ledgerFor(['a-1']);
    await assert.rejects(runCampaign(base(ledger, dir, { adapter: createReferenceAdapter({ mode: 'reckless' }) })), /provenance/i);
    for (const origin of [{ source: 'runtime', id: 'reference-careful', mode: 'careful' }, { source: 'fixture', id: 'reference-careful', mode: 'reckless' }, { source: 'fixture', id: 'reference-careful', mode: null }]) {
      await assert.rejects(runCampaign(base(ledger, dir, { adapter: markAdapter({ id: 'reference-careful', async run() { return {}; } }, origin) })), /provenance/i);
    }
    const unregistered = { id: 'reference-careful', async run() { return {}; } };
    await assert.rejects(runCampaign(base(ledger, dir, { adapter: unregistered })), /provenance/i);
    const wrongEvaluator = ledgerFor(['a-1'], careful, { evaluatorDigest: hashBytes('another evaluator') });
    await assert.rejects(runCampaign(base(wrongEvaluator, dir)), /evaluator/i);
    assert.deepEqual(await readdir(dir), []);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign runner refuses an attempt without a signed planned entry and an unverifiable ledger', async () => {
  const dir = await scratch();
  try {
    const ledger = ledgerFor(['a-1', 'a-2']);
    const stripped = structuredClone(ledger);
    stripped.entries = stripped.entries.filter(e => e.payload.attemptId !== 'a-2');
    await assert.rejects(runCampaign(base(stripped, dir)), /ledger/i);
    const forged = structuredClone(ledger);
    forged.entries[0].payload.at = T1;
    await assert.rejects(runCampaign(base(forged, dir)), /ledger/i);
    const mismatch = base(ledger, dir, { plan: planFor(['a-1', 'a-2'], careful, { campaignId: 'campaign:other' }) });
    await assert.rejects(runCampaign(mismatch), /plan/i);
    await assert.rejects(runCampaign(base(ledger, dir, { manifests: {} })), /manifest/i);
    await assert.rejects(runCampaign(base(ledger, dir, { privateKey: generateKeyPairSync('ed25519').privateKey })), /issuer/i);
    assert.deepEqual(await readdir(dir), []);
    const dangling = appendEntry({ ledger, privateKey: issuer.privateKey, entry: { kind: 'started', attemptId: 'a-1', at: T0 } });
    const resumed = await runCampaign(base(dangling, dir));
    assert.deepEqual(resumed.results.map(r => [r.attemptId, r.outcome]), [['a-2', 'completed']], 'a started attempt is never silently re-run');
    assert.equal(summarizeCampaign(resumed.ledger).unaccounted, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign runner records infrastructure errors as errored and never retries silently', async () => {
  const dir = await scratch();
  try {
    let calls = 0;
    const failing = markAdapter({ id: 'reference-careful', async run() { calls += 1; throw new Error('SYNTHETIC adapter outage'); } }, careful);
    const result = await runCampaign(base(ledgerFor(['a-1']), dir, { adapter: failing }));
    assert.equal(result.results[0].outcome, 'errored');
    assert.equal(calls, SCENARIOS.length, 'one pass over the frozen scenarios only');
    const first = calls;
    const entry = result.ledger.entries.at(-1).payload;
    assert.equal(entry.kind, 'errored');
    assert.equal(entry.errorCode, 'ADAPTER_ERROR');
    assert.ok(!JSON.stringify(result.ledger).includes('SYNTHETIC adapter outage'));
    const again = await runCampaign(base(result.ledger, dir, { adapter: failing }));
    assert.deepEqual(again.results, []);
    assert.equal(calls, first, 'an errored attempt is not retried without a new planned attempt');
    const summary = summarizeCampaign(again.ledger);
    assert.deepEqual([summary.planned, summary.errored, summary.completed, summary.unaccounted], [1, 1, 0, 0]);
    const amended = appendEntry({ ledger: again.ledger, privateKey: issuer.privateKey, entry: { kind: 'amended', attemptId: 'a-1-retry', retryOf: 'a-1', subjectDigest, scenarioSetDigest: digests.scenarioSetDigest, seed: null, at: T1 } });
    const retried = await runCampaign(base(amended, dir));
    assert.deepEqual(retried.results.map(r => [r.attemptId, r.outcome]), [['a-1-retry', 'completed']]);
    assert.deepEqual([summarizeCampaign(retried.ledger).planned, summarizeCampaign(retried.ledger).errored, summarizeCampaign(retried.ledger).completed], [2, 1, 1]);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign runner refuses private directories inside the repository or open to others', async () => {
  const ledger = ledgerFor(['a-1']);
  const inside = join(repoRoot, 'campaign-private-should-not-exist');
  await assert.rejects(runCampaign(base(ledger, inside)), /private/i);
  assert.equal(existsSync(inside), false);
  await assert.rejects(runCampaign(base(ledger, 'relative/dir')), /absolute/i);
  const dir = await scratch();
  try {
    await chmod(dir, 0o755);
    await assert.rejects(runCampaign(base(ledger, dir)), /permission|private/i);
    await chmod(dir, 0o700);
    await writeFile(join(dir, 'a-1.bundle.json'), 'occupied');
    const result = await runCampaign(base(ledger, dir));
    assert.equal(result.results[0].outcome, 'errored', 'an existing bundle is never overwritten');
    assert.equal(result.ledger.entries.at(-1).payload.errorCode, 'BUNDLE_WRITE_FAILED');
    assert.equal(await readFile(join(dir, 'a-1.bundle.json'), 'utf8'), 'occupied');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign runner persists the started entry before the adapter runs', async () => {
  const dir = await scratch();
  try {
    const seen = [];
    const spy = markAdapter({ id: 'reference-careful', async run(request) { if (!seen.includes('adapter')) seen.push('adapter'); return createReferenceAdapter({ mode: 'careful' }).run(request); } }, careful);
    await runCampaign(base(ledgerFor(['a-1']), dir, { adapter: spy, persist: async l => { seen.push(l.entries.at(-1).payload.kind); } }));
    assert.deepEqual(seen, ['started', 'adapter', 'completed']);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign runner completes against the owned command fixture without network', async () => {
  const dir = await scratch();
  try {
    const adapter = createCommandAdapter({ command: process.execPath, args: [fileURLToPath(new URL('../examples/command-fixture.mjs', import.meta.url))], timeoutMs: 10000 });
    const declared = { source: 'runtime', id: 'command-json', mode: null };
    const result = await runCampaign(base(ledgerFor(['c-1'], declared), dir, { adapter }));
    assert.equal(result.results[0].outcome, 'completed');
    assert.equal(summarizeCampaign(result.ledger).completed, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

const cli = (args, input) => spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/kya-campaign.mjs', import.meta.url)), ...args], { encoding: 'utf8', input, cwd: tmpdir() });

test('campaign CLI plans runs verifies and summarizes on the reference adapter', async () => {
  const dir = await scratch();
  try {
    const keyFile = join(dir, 'issuer.pem'), manifestFile = join(dir, 'manifest.json'), policyFile = join(dir, 'policy.json'), ledgerFile = join(dir, 'ledger.json'), priv = join(dir, 'private');
    await writeFile(keyFile, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    await writeFile(manifestFile, JSON.stringify(manifest));
    await writeFile(policyFile, JSON.stringify(capturePolicy));
    const planned = cli(['plan', '--campaign-id', 'campaign:cli', '--use-case', 'Synthetic CLI campaign', '--manifest', manifestFile, '--attempts', '2', '--adapter', 'reference', '--policy', policyFile, '--key', keyFile, '--now', T0, '--out', ledgerFile]);
    assert.equal(planned.status, 0, planned.stderr);
    assert.equal(JSON.parse(planned.stdout).planned, 2);
    const before = JSON.parse(await readFile(ledgerFile, 'utf8'));
    assert.equal(before.entries.length, 2);
    const ran = cli(['run', '--ledger', ledgerFile, '--manifest', manifestFile, '--private-dir', priv, '--adapter', 'reference', '--policy', policyFile, '--key', keyFile, '--now', T1]);
    assert.equal(ran.status, 0, ran.stderr);
    assert.deepEqual(JSON.parse(ran.stdout).results.map(r => r.outcome), ['completed', 'completed']);
    const verified = cli(['verify-ledger', '--ledger', ledgerFile, '--policy', policyFile, '--require-closed', 'true']);
    assert.equal(verified.status, 0, verified.stdout + verified.stderr);
    assert.equal(JSON.parse(verified.stdout).valid, true);
    const summary = cli(['summary', '--ledger', ledgerFile, '--policy', policyFile]);
    assert.equal(summary.status, 0, summary.stderr);
    assert.deepEqual([JSON.parse(summary.stdout).planned, JSON.parse(summary.stdout).completed, JSON.parse(summary.stdout).unaccounted], [2, 2, 0]);
    assert.equal((await stat(join(priv, 'a-001.bundle.json'))).mode & 0o777, 0o600);
    const wrongAdapter = cli(['run', '--ledger', ledgerFile, '--manifest', manifestFile, '--private-dir', priv, '--adapter', 'command', '--policy', policyFile, '--key', keyFile, '--now', T1]);
    assert.notEqual(wrongAdapter.status, 0);
    const tampered = JSON.parse(await readFile(ledgerFile, 'utf8'));
    tampered.entries[0].payload.at = T1;
    await writeFile(join(dir, 'tampered.json'), JSON.stringify(tampered));
    const bad = cli(['verify-ledger', '--ledger', join(dir, 'tampered.json'), '--policy', policyFile]);
    assert.equal(bad.status, 1);
    assert.equal(JSON.parse(bad.stdout).valid, false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign CLI refuses a missing clock unknown flags and unknown commands', () => {
  assert.notEqual(cli(['plan']).status, 0);
  assert.match(cli(['summary', '--ledger', '/nonexistent', '--bogus', 'x']).stderr, /Unknown flag/);
  assert.match(cli(['frobnicate']).stderr, /Unknown command/);
  assert.match(cli(['run', '--ledger', '/nonexistent', '--manifest', '/nonexistent', '--private-dir', '/tmp/x', '--adapter', 'reference', '--key', '/nonexistent']).stderr, /Missing --now/);
  assert.match(cli(['run', '--ledger', '/nonexistent', '--manifest', '/nonexistent', '--private-dir', '/tmp/x', '--adapter', 'reference', '--key', '/nonexistent', '--now', T1]).stderr, /--policy|--trust-plan-signer/);
});

test('campaign runner refuses a private directory reached through a symlink into the repository', async () => {
  const dir = await scratch();
  try {
    const link = join(dir, 'lnk');
    await symlink(join(repoRoot, 'docs'), link);
    const target = join(link, 'privnew');
    await assert.rejects(runCampaign(base(ledgerFor(['a-1']), target)), /repository/i);
    assert.equal(existsSync(join(repoRoot, 'docs', 'privnew')), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign runner refuses a signer that is not a capture issuer under the supplied policy', async () => {
  const dir = await scratch();
  try {
    const ledger = ledgerFor(['a-1']);
    const asSelf = { ...capturePolicy, trustedKeys: [{ ...capturePolicy.trustedKeys[0], role: 'self' }] };
    await assert.rejects(runCampaign(base(ledger, dir, { policy: asSelf })), /ledger|signer|policy/i);
    await assert.rejects(runCampaign(base(ledger, dir, { policy: undefined })), /policy|trust/i);
    const unbound = openLedger({ plan: createPlan({ campaignId: 'campaign:u', useCase: 'x', ...digests, policyDigest: hashBytes('other policy'), adapter: careful, attempts: [{ attemptId: 'a-1', subjectDigest, scenarioSetDigest: digests.scenarioSetDigest, seed: null }], createdAt: T0, privateKey: issuer.privateKey }), privateKey: issuer.privateKey, now: T0 });
    await assert.rejects(runCampaign(base(unbound, dir)), /policy/i);
    const trusted = await runCampaign(base(ledger, dir, { policy: undefined, trustPlanSigner: true }));
    assert.equal(trusted.results[0].outcome, 'completed');
    assert.deepEqual(await readdir(dir), ['a-1.bundle.json']);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign CLI exits 2 when an attempt is errored or unaccounted and pins head and entry count', async () => {
  const dir = await scratch();
  try {
    const keyFile = join(dir, 'issuer.pem'), manifestFile = join(dir, 'manifest.json'), policyFile = join(dir, 'policy.json'), ledgerFile = join(dir, 'ledger.json'), priv = join(dir, 'private');
    await writeFile(keyFile, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    await writeFile(manifestFile, JSON.stringify(manifest)); await writeFile(policyFile, JSON.stringify(capturePolicy));
    const dangling = appendEntry({ ledger: ledgerFor(['a-001', 'a-002']), privateKey: issuer.privateKey, entry: { kind: 'started', attemptId: 'a-001', at: T0 } });
    await writeFile(ledgerFile, JSON.stringify(dangling));
    const args = ['--ledger', ledgerFile, '--manifest', manifestFile, '--private-dir', priv, '--adapter', 'reference', '--policy', policyFile, '--key', keyFile, '--now', T1];
    const ran = cli(['run', ...args]);
    assert.equal(ran.status, 2, ran.stderr);
    assert.equal(JSON.parse(ran.stdout).summary.unaccounted, 1);
    const summary = JSON.parse(cli(['summary', '--ledger', ledgerFile, '--policy', policyFile]).stdout);
    assert.match(summary.headDigest, /^[a-f0-9]{64}$/); assert.equal(summary.entryCount, 5);
    assert.equal(cli(['summary', '--ledger', ledgerFile, '--policy', policyFile, '--expect-head', summary.headDigest, '--expect-entries', '5']).status, 2, 'matching pins on an open ledger still exit 2');
    const wrongHead = cli(['summary', '--ledger', ledgerFile, '--policy', policyFile, '--expect-head', hashBytes('x')]);
    assert.notEqual(wrongHead.status, 0); assert.match(wrongHead.stderr, /head-mismatch/);
    const wrongCount = cli(['verify-ledger', '--ledger', ledgerFile, '--policy', policyFile, '--expect-entries', '2']);
    assert.equal(wrongCount.status, 1); assert.ok(JSON.parse(wrongCount.stdout).problems.some(p => p.code === 'entry-count-mismatch'));
    const bare = cli(['verify-ledger', '--ledger', ledgerFile]);
    assert.equal(bare.status, 1); assert.ok(JSON.parse(bare.stdout).problems.some(p => p.code === 'policy-required'));
    const trusted = cli(['verify-ledger', '--ledger', ledgerFile, '--trust-plan-signer', 'true', '--allow-open', 'true']);
    assert.equal(trusted.status, 0); assert.equal(JSON.parse(trusted.stdout).signerTrust, 'plan-signer-unverified');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign CLI exit codes reflect final attempt state and open ledgers', async () => {
  const dir = await scratch();
  try {
    const keyFile = join(dir, 'issuer.pem'), manifestFile = join(dir, 'manifest.json'), policyFile = join(dir, 'policy.json'), ledgerFile = join(dir, 'ledger.json'), priv = join(dir, 'private');
    await writeFile(keyFile, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    await writeFile(manifestFile, JSON.stringify(manifest)); await writeFile(policyFile, JSON.stringify(capturePolicy));
    const runArgs = extra => ['run', '--ledger', ledgerFile, '--manifest', manifestFile, '--private-dir', priv, '--adapter', 'reference', '--policy', policyFile, '--key', keyFile, '--now', T1, ...extra];
    // W1: every attempt abandoned is not success.
    const abandoned = appendEntry({ ledger: ledgerFor(['a-1']), privateKey: issuer.privateKey, entry: { kind: 'abandoned', attemptId: 'a-1', at: T0, reasonCode: 'operator-abandon' } });
    await writeFile(ledgerFile, JSON.stringify(abandoned));
    const ranAbandoned = cli(runArgs([]));
    assert.equal(ranAbandoned.status, 2, ranAbandoned.stderr);
    assert.equal(JSON.parse(ranAbandoned.stdout).summary.abandoned, 1);
    // W2: summary and verify-ledger on an open ledger.
    const open = ledgerFor(['a-1', 'a-2']);
    await writeFile(ledgerFile, JSON.stringify(open));
    const summary = cli(['summary', '--ledger', ledgerFile, '--policy', policyFile]);
    assert.equal(summary.status, 2); assert.equal(JSON.parse(summary.stdout).unaccounted, 2);
    const verifyOpen = cli(['verify-ledger', '--ledger', ledgerFile, '--policy', policyFile]);
    assert.equal(verifyOpen.status, 2); assert.equal(JSON.parse(verifyOpen.stdout).valid, true); assert.equal(JSON.parse(verifyOpen.stdout).closed, false);
    const allowed = cli(['verify-ledger', '--ledger', ledgerFile, '--policy', policyFile, '--allow-open', 'true']);
    assert.equal(allowed.status, 0); assert.ok(JSON.parse(allowed.stdout).warnings.some(w => /open/i.test(w)));
    // I2: pins on run are checked before anything is appended or written.
    const head = JSON.parse(summary.stdout).headDigest;
    const fresh = join(dir, 'fresh-private');
    const badPin = cli(runArgs(['--expect-head', hashBytes('not the head')]).map(v => v === priv ? fresh : v));
    assert.notEqual(badPin.status, 0); assert.match(badPin.stderr, /head-mismatch|head digest/i);
    assert.equal(existsSync(fresh), false);
    assert.equal(cli(runArgs(['--expect-head', head, '--expect-entries', '2'])).status, 0);
    // W1: a successfully retried errored attempt is not a failure.
    let retried = run0(ledgerFor(['a-1']));
    await writeFile(ledgerFile, JSON.stringify(retried));
    const ranRetry = cli(runArgs([]));
    assert.equal(ranRetry.status, 0, ranRetry.stdout + ranRetry.stderr);
    assert.equal(JSON.parse(ranRetry.stdout).summary.superseded, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
function run0(ledger) {
  const k = issuer.privateKey;
  ledger = appendEntry({ ledger, privateKey: k, entry: { kind: 'started', attemptId: 'a-1', at: T0 } });
  ledger = appendEntry({ ledger, privateKey: k, entry: { kind: 'errored', attemptId: 'a-1', at: T0, errorCode: 'TIMEOUT', evidenceBundleDigest: null } });
  return appendEntry({ ledger, privateKey: k, entry: { kind: 'amended', attemptId: 'a-1b', retryOf: 'a-1', subjectDigest, scenarioSetDigest: digests.scenarioSetDigest, seed: null, at: T0 } });
}
