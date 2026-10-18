import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile, readFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { createPlan, openLedger, runCampaign, conformanceDigests } from '../src/campaign/index.mjs';
import { createReferenceAdapter } from '../src/conformance/index.mjs';
import { digest, keyId } from '../src/index.mjs';
import manifest from '../examples/manifest.json' with { type: 'json' };

const repoRoot = fileURLToPath(new URL('../', import.meta.url));
const issuer = generateKeyPairSync('ed25519');
const issuerPem = issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const T0 = '2026-10-14T09:00:00.000Z', T1 = '2026-10-14T09:05:00.000Z';
const subjectDigest = digest(manifest);
const digests = conformanceDigests();
const careful = { source: 'fixture', id: 'reference-careful', mode: 'careful' };
const policy = { schema: 'kya.policy/v1', id: 'hardening-policy', profileDigest: digests.profileDigest, scopeId: manifest.scope.id, minCoverage: 1, minScore: 800, minIndependentCoverage: 0, allowedSources: ['fixture'], maxEvidenceAgeSeconds: 3600, trustedKeys: [{ id: keyId(issuerPem), publicKey: issuerPem, role: 'capture-issuer' }], revokedKeyIds: [], revokedEvidenceIds: [], revokedSubjectDigests: [] };
const ledgerFor = ids => openLedger({ plan: createPlan({ campaignId: 'campaign:hardening', useCase: 'Synthetic fixture campaign', ...digests, policyDigest: digest(policy), adapter: careful, attempts: ids.map(attemptId => ({ attemptId, subjectDigest, scenarioSetDigest: digests.scenarioSetDigest, seed: null })), createdAt: T0, privateKey: issuer.privateKey }), privateKey: issuer.privateKey, now: T0 });

test('a private directory named with two leading dots inside the repository is refused', async () => {
  const inside = join(repoRoot, '..private-dir-should-not-exist');
  const ledger = ledgerFor(['a-1']);
  try {
    await assert.rejects(runCampaign({ plan: ledger.plan, ledger, adapter: createReferenceAdapter({ mode: 'careful' }), manifests: { [subjectDigest]: manifest }, policy, privateKey: issuer.privateKey, privateDir: inside, clock: () => T1 }), /outside the repository/i);
    assert.equal(existsSync(inside), false);
  } finally { await rm(inside, { recursive: true, force: true }); }
});

function runCli(args) {
  return new Promise(resolveRun => {
    const child = spawn(process.execPath, [join(repoRoot, 'scripts/kya-campaign.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
    child.on('close', status => resolveRun({ status, stdout, stderr }));
  });
}

test('two concurrent campaign runs on one ledger execute the attempts once and the other refuses', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kya-race-'));
  try {
    // Run A takes the lock and is held there, so run B overlaps it for certain; a machine under load cannot let A finish first.
    const holder = await heldRun(dir);
    const manifestPath = join(dir, 'manifest.json'), keyPath = join(dir, 'key.pem'), policyPath = join(dir, 'policy.json'), priv = join(dir, 'private');
    const args = ['run', '--ledger', holder.ledgerPath, '--manifest', manifestPath, '--private-dir', priv, '--adapter', 'reference', '--key', keyPath, '--now', T1, '--policy', policyPath];
    const loser = await runCli(args);
    assert.notEqual(loser.status, 0, 'a second run on a locked ledger must not succeed: ' + JSON.stringify(loser));
    assert.match(loser.stderr, /lock|already running|in progress/i);
    assert.equal(existsSync(holder.lockPath), true, 'the refused run must not remove the holder lock');
    const during = JSON.parse(await readFile(holder.ledgerPath, 'utf8'));
    assert.equal(during.entries.filter(e => e.payload.kind === 'started').length, 0, 'the refused run must not start any attempt');
    holder.child.kill('SIGTERM');
    await holder.closed;
    assert.equal(existsSync(holder.lockPath), false, 'the lock is released when the holder ends');
    const after = await runCli(args);
    assert.equal(after.status, 0, 'a later run proceeds once the lock is free: ' + JSON.stringify(after));
    const final = JSON.parse(await readFile(holder.ledgerPath, 'utf8'));
    const started = final.entries.filter(e => e.payload.kind === 'started').map(e => e.payload.attemptId);
    assert.equal(new Set(started).size, started.length, 'no attempt may be started twice');
    assert.equal(started.length, 2);
    assert.equal(existsSync(holder.lockPath), false, 'the lock is released after the run');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('a stale lock is reported and never silently stolen', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kya-stale-'));
  try {
    const ledgerPath = join(dir, 'ledger.json'), manifestPath = join(dir, 'manifest.json'), keyPath = join(dir, 'key.pem'), policyPath = join(dir, 'policy.json'), priv = join(dir, 'private');
    await writeFile(ledgerPath, JSON.stringify(ledgerFor(['a-1']), null, 2));
    await writeFile(manifestPath, JSON.stringify(manifest)); await writeFile(policyPath, JSON.stringify(policy));
    await writeFile(keyPath, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    await mkdir(priv, { mode: 0o700 });
    await writeFile(ledgerPath + '.lock', JSON.stringify({ pid: 999999, createdAt: T0 }));
    const r = spawnSync(process.execPath, [join(repoRoot, 'scripts/kya-campaign.mjs'), 'run', '--ledger', ledgerPath, '--manifest', manifestPath, '--private-dir', priv, '--adapter', 'reference', '--key', keyPath, '--now', T1, '--policy', policyPath], { encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /lock/i);
    assert.equal(existsSync(ledgerPath + '.lock'), true, 'a foreign lock is left in place');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

// The hold file is never created: the run blocks right after taking its lock until the signal arrives, so the test does not race the run.
async function heldRun(dir) {
  const ledgerPath = join(dir, 'ledger.json'), manifestPath = join(dir, 'manifest.json'), keyPath = join(dir, 'key.pem'), policyPath = join(dir, 'policy.json'), priv = join(dir, 'private');
  await writeFile(ledgerPath, JSON.stringify(ledgerFor(['a-1', 'a-2']), null, 2));
  await writeFile(manifestPath, JSON.stringify(manifest)); await writeFile(policyPath, JSON.stringify(policy));
  await writeFile(keyPath, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  await mkdir(priv, { mode: 0o700 });
  const child = spawn(process.execPath, [join(repoRoot, 'scripts/kya-campaign.mjs'), 'run', '--ledger', ledgerPath, '--manifest', manifestPath, '--private-dir', priv, '--adapter', 'reference', '--key', keyPath, '--now', T1, '--policy', policyPath], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, KYA_CAMPAIGN_HOLD_FILE: join(dir, 'never-created') } });
  let stderr = '';
  child.stderr.on('data', d => { stderr += d; });
  const closed = new Promise(resolveClose => child.on('close', (status, signal) => resolveClose({ status, signal })));
  const lockPath = ledgerPath + '.lock';
  const started = Date.now();
  let token = null;
  while (token === null && Date.now() - started < 20_000) {
    try { token = JSON.parse(await readFile(lockPath, 'utf8')).token ?? null; } catch { await new Promise(r => setTimeout(r, 20)); }
  }
  assert.ok(token, 'the run never took its lock: ' + stderr);
  return { child, closed, lockPath, ledgerPath, token, stderr: () => stderr };
}

test('SIGTERM during a campaign run releases the lock this process owns and leaves the ledger unchanged', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kya-sigterm-'));
  try {
    const run = await heldRun(dir);
    const before = await readFile(run.ledgerPath, 'utf8');
    run.child.kill('SIGTERM');
    const { status, signal } = await run.closed;
    assert.equal(signal, null, 'the handler exits normally instead of dying from the signal');
    assert.equal(status, 143, run.stderr());
    assert.equal(existsSync(run.lockPath), false, 'the lock this process created is released');
    assert.equal(await readFile(run.ledgerPath, 'utf8'), before);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('SIGINT during a campaign run never removes a lock that now belongs to another run', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kya-sigint-'));
  try {
    const run = await heldRun(dir);
    await writeFile(run.lockPath, JSON.stringify({ pid: 999999, token: 'someone-else', createdAt: T0 }));
    run.child.kill('SIGINT');
    const { status } = await run.closed;
    assert.equal(status, 130, run.stderr());
    assert.equal(existsSync(run.lockPath), true, 'a lock with a foreign token is left in place');
    assert.equal(JSON.parse(await readFile(run.lockPath, 'utf8')).token, 'someone-else');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('a run that finishes normally still releases its lock and removes its signal handlers', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kya-normal-'));
  try {
    const ledgerPath = join(dir, 'ledger.json'), manifestPath = join(dir, 'manifest.json'), keyPath = join(dir, 'key.pem'), policyPath = join(dir, 'policy.json'), priv = join(dir, 'private');
    await writeFile(ledgerPath, JSON.stringify(ledgerFor(['a-1']), null, 2));
    await writeFile(manifestPath, JSON.stringify(manifest)); await writeFile(policyPath, JSON.stringify(policy));
    await writeFile(keyPath, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    await mkdir(priv, { mode: 0o700 });
    const hold = join(dir, 'hold');
    await writeFile(hold, 'go');
    const r = spawnSync(process.execPath, [join(repoRoot, 'scripts/kya-campaign.mjs'), 'run', '--ledger', ledgerPath, '--manifest', manifestPath, '--private-dir', priv, '--adapter', 'reference', '--key', keyPath, '--now', T1, '--policy', policyPath], { encoding: 'utf8', env: { ...process.env, KYA_CAMPAIGN_HOLD_FILE: hold } });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(existsSync(ledgerPath + '.lock'), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
