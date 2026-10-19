import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, symlink, readFile, readdir, rm, writeFile, chmod } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createPlan, openLedger, appendEntry, runCampaign, conformanceDigests } from '../src/campaign/index.mjs';
import { signEntry } from '../src/campaign/domain/records.mjs';
import { createReferenceAdapter } from '../src/conformance/index.mjs';
import { digest, hashBytes, keyId } from '../src/index.mjs';
import manifest from '../examples/manifest.json' with { type: 'json' };

// Second, independent killers for single-killer campaign controls. Ledger defects are forged with the issuer key
// (so signatures stay valid) and judged through the public kya-campaign CLI; runner gates use real adapters and the CLI.
const issuer = generateKeyPairSync('ed25519');
const issuerPem = issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const T0 = '2026-10-14T09:00:00.000Z', T1 = '2026-10-14T09:05:00.000Z', T2 = '2026-10-14T09:06:00.000Z', T3 = '2026-10-14T09:07:00.000Z';
const subjectDigest = digest(manifest);
const digests = conformanceDigests();
const careful = { source: 'fixture', id: 'reference-careful', mode: 'careful' };
const repoRoot = fileURLToPath(new URL('../', import.meta.url));
const campaignScript = fileURLToPath(new URL('../scripts/kya-campaign.mjs', import.meta.url));
const capturePolicy = { schema: 'kya.policy/v1', id: 'redundancy-policy', profileDigest: digests.profileDigest, scopeId: manifest.scope.id, minCoverage: 1, minScore: 800, minIndependentCoverage: 0, allowedSources: ['fixture'], maxEvidenceAgeSeconds: 3600, trustedKeys: [{ id: keyId(issuerPem), publicKey: issuerPem, role: 'capture-issuer' }], revokedKeyIds: [], revokedEvidenceIds: [], revokedSubjectDigests: [] };
const planFor = (ids, adapter = careful) => createPlan({ campaignId: 'campaign:redundancy', useCase: 'Synthetic redundancy campaign', ...digests, policyDigest: digest(capturePolicy), adapter, attempts: ids.map(attemptId => ({ attemptId, subjectDigest, scenarioSetDigest: digests.scenarioSetDigest, seed: null })), createdAt: T0, privateKey: issuer.privateKey });
const ledgerFor = (ids, adapter) => openLedger({ plan: planFor(ids, adapter), privateKey: issuer.privateKey, now: T0 });
const add = (ledger, entry) => appendEntry({ ledger, privateKey: issuer.privateKey, entry });
// A correctly signed, correctly chained entry that the replay rules (not the signature) must judge.
const forge = (ledger, fields) => {
  const last = ledger.entries.at(-1);
  const payload = { schema: 'kya.campaign-ledger-entry/v1', campaignId: ledger.plan.payload.campaignId, planDigest: digest(ledger.plan), seq: ledger.entries.length, prevDigest: digest(last), ...fields };
  return { ...structuredClone(ledger), entries: [...structuredClone(ledger.entries), signEntry(payload, issuer.privateKey)] };
};
const scratch = () => mkdtemp(join(tmpdir(), 'kya-redundancy-campaign-'));
const cli = args => spawnSync(process.execPath, [campaignScript, ...args], { encoding: 'utf8', cwd: tmpdir(), timeout: 60000 });
async function verifyViaCli(ledger, extra = ['--trust-plan-signer', 'true']) {
  const dir = await scratch();
  try {
    const file = join(dir, 'ledger.json'); await writeFile(file, JSON.stringify(ledger));
    const p = cli(['verify-ledger', '--ledger', file, '--allow-open', 'true', ...extra]);
    return { status: p.status, codes: (JSON.parse(p.stdout || '{"problems":[]}').problems ?? []).map(x => x.code), raw: p };
  } finally { await rm(dir, { recursive: true, force: true }); }
}

test('cli verify refuses a re-signed edit of history because the next entry no longer commits to it', async () => {
  const ledger = add(add(ledgerFor(['a-1', 'a-2']), { kind: 'started', attemptId: 'a-1', at: T1 }), { kind: 'completed', attemptId: 'a-1', at: T1, runId: 'run-1', evidenceBundleDigest: hashBytes('b1') });
  assert.equal((await verifyViaCli(ledger)).status, 0);
  const rewritten = structuredClone(ledger);
  const target = rewritten.entries[2].payload;
  rewritten.entries[2] = signEntry({ ...target, at: T2 }, issuer.privateKey);
  const r = await verifyViaCli(rewritten);
  assert.equal(r.status, 1);
  assert.ok(r.codes.includes('chain-broken'), JSON.stringify(r.codes));
});

test('cli verify refuses completion without a start and a second start of one attempt', async () => {
  const base = ledgerFor(['a-1', 'a-2']);
  const skipped = forge(base, { kind: 'completed', attemptId: 'a-1', at: T1, runId: 'run-1', evidenceBundleDigest: hashBytes('b1') });
  const a = await verifyViaCli(skipped);
  assert.equal(a.status, 1); assert.ok(a.codes.includes('bad-transition'), JSON.stringify(a.codes));
  const started = add(base, { kind: 'started', attemptId: 'a-1', at: T1 });
  const twice = await verifyViaCli(forge(started, { kind: 'started', attemptId: 'a-1', at: T2 }));
  assert.equal(twice.status, 1); assert.ok(twice.codes.includes('bad-transition'));
  const done = add(started, { kind: 'abandoned', attemptId: 'a-1', at: T2, reasonCode: 'operator-abandon' });
  const revived = await verifyViaCli(forge(done, { kind: 'started', attemptId: 'a-1', at: T3 }));
  assert.ok(revived.codes.includes('bad-transition'));
});

test('cli verify under a policy refuses a signer whose anchor is not a capture issuer', async () => {
  const dir = await scratch();
  try {
    const ledger = ledgerFor(['a-1']), ledgerFile = join(dir, 'ledger.json');
    await writeFile(ledgerFile, JSON.stringify(ledger));
    const write = async (name, role) => { const f = join(dir, name); await writeFile(f, JSON.stringify({ ...capturePolicy, trustedKeys: [{ ...capturePolicy.trustedKeys[0], role }] })); return f; };
    const good = cli(['verify-ledger', '--ledger', ledgerFile, '--policy', await write('issuer.json', 'capture-issuer'), '--allow-open', 'true']);
    assert.equal(good.status, 0, good.stdout);
    for (const role of ['independent', 'self']) {
      const p = cli(['verify-ledger', '--ledger', ledgerFile, '--policy', await write(role + '.json', role), '--allow-open', 'true']);
      assert.equal(p.status, 1);
      assert.ok(JSON.parse(p.stdout).problems.some(x => x.code === 'untrusted-signer'), role);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('cli verify refuses a retry of an attempt that did not error', async () => {
  const retry = (attemptId, retryOf) => ({ kind: 'amended', attemptId, retryOf, subjectDigest, scenarioSetDigest: digests.scenarioSetDigest, seed: null, at: T3 });
  const planned = await verifyViaCli(forge(ledgerFor(['a-1']), retry('a-1b', 'a-1')));
  assert.equal(planned.status, 1); assert.ok(planned.codes.includes('bad-retry'), JSON.stringify(planned.codes));
  const completed = add(add(ledgerFor(['a-1']), { kind: 'started', attemptId: 'a-1', at: T1 }), { kind: 'completed', attemptId: 'a-1', at: T1, runId: 'run-1', evidenceBundleDigest: hashBytes('b1') });
  const c = await verifyViaCli(forge(completed, retry('a-1b', 'a-1')));
  assert.ok(c.codes.includes('bad-retry'));
  const errored = add(add(ledgerFor(['a-1']), { kind: 'started', attemptId: 'a-1', at: T1 }), { kind: 'errored', attemptId: 'a-1', at: T1, errorCode: 'TIMEOUT', evidenceBundleDigest: null });
  assert.equal((await verifyViaCli(forge(errored, retry('a-1b', 'a-1')))).status, 0);
});

test('cli verify treats run IDs as case insensitive across completions', async () => {
  let ledger = ledgerFor(['a-1', 'a-2']);
  for (const [id, run] of [['a-1', 'run-alpha'], ['a-2', 'Run-Alpha']]) {
    ledger = add(ledger, { kind: 'started', attemptId: id, at: T1 });
    if (id === 'a-1') ledger = add(ledger, { kind: 'completed', attemptId: id, at: T1, runId: run, evidenceBundleDigest: hashBytes('bundle-' + id) });
    else ledger = forge(ledger, { kind: 'completed', attemptId: id, at: T1, runId: run, evidenceBundleDigest: hashBytes('bundle-' + id) });
  }
  const r = await verifyViaCli(ledger);
  assert.equal(r.status, 1);
  assert.ok(r.codes.includes('duplicate-evidence'), JSON.stringify(r.codes));
});

test('cli verify refuses an errored entry that reuses an evidence bundle digest', async () => {
  const shared = hashBytes('shared bundle');
  const afterComplete = add(add(add(ledgerFor(['a-1', 'a-2']), { kind: 'started', attemptId: 'a-1', at: T1 }), { kind: 'completed', attemptId: 'a-1', at: T1, runId: 'run-1', evidenceBundleDigest: shared }), { kind: 'started', attemptId: 'a-2', at: T2 });
  const a = await verifyViaCli(forge(afterComplete, { kind: 'errored', attemptId: 'a-2', at: T2, errorCode: 'TIMEOUT', evidenceBundleDigest: shared }));
  assert.equal(a.status, 1); assert.ok(a.codes.includes('duplicate-evidence'), JSON.stringify(a.codes));
  const afterError = add(add(add(add(ledgerFor(['a-1', 'a-2']), { kind: 'started', attemptId: 'a-1', at: T1 }), { kind: 'errored', attemptId: 'a-1', at: T1, errorCode: 'TIMEOUT', evidenceBundleDigest: shared }), { kind: 'started', attemptId: 'a-2', at: T2 }), { kind: 'abandoned', attemptId: 'a-2', at: T2, reasonCode: 'operator-abandon' });
  assert.equal((await verifyViaCli(afterError)).status, 0);
  const twoErrors = add(add(ledgerFor(['a-1', 'a-2']), { kind: 'started', attemptId: 'a-1', at: T1 }), { kind: 'errored', attemptId: 'a-1', at: T1, errorCode: 'TIMEOUT', evidenceBundleDigest: shared });
  const b = await verifyViaCli(forge(forge(twoErrors, { kind: 'started', attemptId: 'a-2', at: T2 }), { kind: 'errored', attemptId: 'a-2', at: T2, errorCode: 'ABORTED', evidenceBundleDigest: shared }));
  assert.ok(b.codes.includes('duplicate-evidence'));
});

test('campaign runner refuses a plan whose declared adapter source differs from the real adapter', async () => {
  const dir = await scratch();
  try {
    const ledger = ledgerFor(['a-1'], { source: 'runtime', id: 'reference-careful', mode: 'careful' });
    const args = { plan: ledger.plan, ledger, adapter: createReferenceAdapter({ mode: 'careful' }), manifests: { [subjectDigest]: manifest }, policy: capturePolicy, privateKey: issuer.privateKey, privateDir: dir, clock: () => T1 };
    await assert.rejects(runCampaign(args), /provenance/i);
    assert.deepEqual(await readdir(dir), []);
    const matching = ledgerFor(['a-1']);
    const ok = await runCampaign({ ...args, plan: matching.plan, ledger: matching });
    assert.equal(ok.results[0].outcome, 'completed');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('campaign runner refuses a plan whose declared adapter mode differs from the real adapter', async () => {
  const dir = await scratch();
  try {
    for (const mode of ['reckless', null]) {
      const ledger = ledgerFor(['a-1'], { source: 'fixture', id: 'reference-careful', mode });
      const args = { plan: ledger.plan, ledger, adapter: createReferenceAdapter({ mode: 'careful' }), manifests: { [subjectDigest]: manifest }, policy: capturePolicy, privateKey: issuer.privateKey, privateDir: dir, clock: () => T1 };
      await assert.rejects(runCampaign(args), /provenance/i, String(mode));
    }
    assert.deepEqual(await readdir(dir), []);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

async function cliWorld(dir, ids = ['a-001']) {
  const keyFile = join(dir, 'issuer.pem'), manifestFile = join(dir, 'manifest.json'), policyFile = join(dir, 'policy.json'), ledgerFile = join(dir, 'ledger.json');
  await writeFile(keyFile, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  await writeFile(manifestFile, JSON.stringify(manifest)); await writeFile(policyFile, JSON.stringify(capturePolicy));
  await writeFile(ledgerFile, JSON.stringify(ledgerFor(ids)));
  return { runArgs: priv => ['run', '--ledger', ledgerFile, '--manifest', manifestFile, '--private-dir', priv, '--adapter', 'reference', '--policy', policyFile, '--key', keyFile, '--now', T1] };
}

test('cli refuses a private directory open to group or others and accepts an owner only one', async () => {
  const dir = await scratch();
  try {
    const world = await cliWorld(dir), priv = join(dir, 'private');
    await mkdir(priv, { mode: 0o700 });
    for (const mode of [0o750, 0o770, 0o705, 0o707]) {
      await chmod(priv, mode);
      const p = cli(world.runArgs(priv));
      assert.equal(p.status, 1, mode.toString(8));
      assert.match(p.stderr, /permissions/i);
      assert.deepEqual(await readdir(priv), []);
    }
    await chmod(priv, 0o700);
    const ok = cli(world.runArgs(priv));
    assert.equal(ok.status, 0, ok.stderr);
    assert.deepEqual(await readdir(priv), ['a-001.bundle.json']);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('cli never overwrites an existing evidence bundle and records the write failure', async () => {
  const dir = await scratch();
  try {
    const world = await cliWorld(dir, ['a-001', 'a-002']), priv = join(dir, 'private');
    await mkdir(priv, { mode: 0o700 });
    await writeFile(join(priv, 'a-002.bundle.json'), 'occupied', { mode: 0o600 });
    const p = cli(world.runArgs(priv));
    assert.equal(p.status, 2, p.stderr);
    const out = JSON.parse(p.stdout);
    assert.deepEqual(out.results.map(r => [r.attemptId, r.outcome, r.errorCode]), [['a-001', 'completed', null], ['a-002', 'errored', 'BUNDLE_WRITE_FAILED']]);
    assert.equal(out.summary.errored, 1);
    assert.equal(await readFile(join(priv, 'a-002.bundle.json'), 'utf8'), 'occupied');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('cli refuses a private directory that a nested symlink resolves into the repository', async () => {
  const dir = await scratch(), created = join(repoRoot, 'examples', 'redundancy-priv-a', 'inner');
  try {
    const world = await cliWorld(dir), link = join(dir, 'via-link');
    await symlink(join(repoRoot, 'examples'), link);
    const p = cli(world.runArgs(join(link, 'redundancy-priv-a', 'inner')));
    assert.equal(p.status, 1);
    assert.match(p.stderr, /repository/i);
    assert.equal(existsSync(join(repoRoot, 'examples', 'redundancy-priv-a')), false);
    assert.equal(existsSync(created), false);
  } finally {
    await rm(join(repoRoot, 'examples', 'redundancy-priv-a'), { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});
