import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { hashBytes, keyId } from '../src/index.mjs';
import { inputs, NOW } from './helpers.mjs';

test('capture cli verify takes binding pins and reports whether the capture is bound', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-capbind-'));
  try {
    const issuer = generateKeyPairSync('ed25519'), pem = issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString(), issuerId = keyId(pem);
    const keyFile = join(dir, 'issuer.pem'); writeFileSync(keyFile, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(), { mode: 0o600 });
    const cap = fileURLToPath(new URL('../scripts/kya-capture.mjs', import.meta.url));
    const cli = args => spawnSync(process.execPath, [cap, ...args], { encoding: 'utf8' });
    const evalId = 'e'.repeat(64), out = join(dir, 'c.json');
    assert.equal(cli(['demo', '--agent', 'careful', '--key', keyFile, '--evaluator-key-id', evalId, '--now', '2026-10-13T11:59:00.000Z', '--out', out]).status, 0);
    const trust = ['verify', '--bundle', out, '--trust-issuer', issuerId];
    const pins = ['--evaluator-key-id', evalId, '--run-id', 'run-1', '--subject-digest', hashBytes('demo-subject'), '--scope-digest', hashBytes('demo-scope'), '--profile-digest', hashBytes('demo-profile')];
    const unbound = cli(trust);
    assert.equal(unbound.status, 0);
    assert.equal(JSON.parse(unbound.stdout).bound, false);
    const ok = cli([...trust, ...pins]);
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(JSON.parse(ok.stdout).bound, true);
    const wrong = cli([...trust, ...pins.slice(0, 4), '--subject-digest', hashBytes('another-agent'), ...pins.slice(6)]);
    assert.equal(wrong.status, 1);
    assert.ok(JSON.parse(wrong.stdout).problems.some(p => p.code === 'binding-mismatch'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/kya-check.mjs');

test('kya-check refuses an input path routed through a workspace directory whose name starts with two dots', () => {
  const x = inputs(), outside = mkdtempSync(join(tmpdir(), 'kya-outside-')), ws = mkdtempSync(join(tmpdir(), 'kya-ws-'));
  try {
    writeFileSync(join(outside, 'inputs.json'), JSON.stringify({ manifest: x.manifest, profile: x.profile, policy: x.policy, evidence: x.evidence, evaluatorDigest: x.evaluatorDigest }));
    symlinkSync(outside, join(ws, '..link'));
    mkdirSync(join(ws, '..real'));
    const at = args => spawnSync(process.execPath, [script, ...args, '--now', NOW, '--allow-fixture'], { cwd: ws, encoding: 'utf8', timeout: 20000, env: { PATH: process.env.PATH } });
    const bad = at(['--assessment-inputs', '..link/inputs.json']);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /outside the workspace/);
    assert.equal(bad.stdout, '');
  } finally { rmSync(outside, { recursive: true, force: true }); rmSync(ws, { recursive: true, force: true }); }
});
