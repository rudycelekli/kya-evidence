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
    const ledgerPath = join(dir, 'ledger.json'), manifestPath = join(dir, 'manifest.json'), keyPath = join(dir, 'key.pem'), policyPath = join(dir, 'policy.json'), priv = join(dir, 'private');
    await writeFile(ledgerPath, JSON.stringify(ledgerFor(['a-1', 'a-2', 'a-3', 'a-4']), null, 2));
    await writeFile(manifestPath, JSON.stringify(manifest)); await writeFile(policyPath, JSON.stringify(policy));
    await writeFile(keyPath, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    await mkdir(priv, { mode: 0o700 });
    const args = ['run', '--ledger', ledgerPath, '--manifest', manifestPath, '--private-dir', priv, '--adapter', 'reference', '--key', keyPath, '--now', T1, '--policy', policyPath];
    const [a, b] = await Promise.all([runCli(args), runCli(args)]);
    const codes = [a.status, b.status].sort();
    assert.equal(codes.filter(c => c === 0).length, 1, 'exactly one run may execute: ' + JSON.stringify([a, b]));
    const loser = a.status === 0 ? b : a;
    assert.notEqual(loser.status, 0);
    assert.match(loser.stderr, /lock|already running|in progress/i);
    const final = JSON.parse(await readFile(ledgerPath, 'utf8'));
    const started = final.entries.filter(e => e.payload.kind === 'started').map(e => e.payload.attemptId);
    assert.equal(new Set(started).size, started.length, 'no attempt may be started twice');
    assert.equal(started.length, 4);
    assert.equal(existsSync(ledgerPath + '.lock'), false, 'the lock is released after the run');
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
