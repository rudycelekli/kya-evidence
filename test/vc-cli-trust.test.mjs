import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assess } from '../src/index.mjs';
import { inputs } from './helpers.mjs';
import { exportAssessmentCredential, didKeyFromPublicKey } from '../src/vc-bridge/index.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const issuer = generateKeyPairSync('ed25519');
const VF = '2026-10-13T12:00:00.000Z', AT = '2026-10-13T12:30:00.000Z';

function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'kya-vc-trust-'));
  const jwtPath = join(dir, 'c.jwt');
  writeFileSync(jwtPath, exportAssessmentCredential(assess(inputs()), { issuerKey: issuer.privateKey, validFrom: VF }).jwt + '\n');
  return { dir, jwtPath, run: args => spawnSync(process.execPath, [join(root, 'scripts/kya-vc.mjs'), ...args], { encoding: 'utf8', timeout: 20000 }) };
}

test('kya-vc verify without a trust source refuses unless untrusted issuers are explicitly allowed', () => {
  const { dir, jwtPath, run } = setup();
  try {
    const bare = run(['verify', '--jwt', jwtPath, '--now', AT]);
    assert.notEqual(bare.status, 0);
    assert.match(bare.stderr, /trust-did|policy|allow-untrusted-issuer/);
    const allowed = run(['verify', '--jwt', jwtPath, '--now', AT, '--allow-untrusted-issuer']);
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.equal(JSON.parse(allowed.stdout).issuerTrust, 'unchecked');
    const did = didKeyFromPublicKey(issuer.publicKey);
    const trusted = run(['verify', '--jwt', jwtPath, '--now', AT, '--trust-did', did]);
    assert.equal(trusted.status, 0, trusted.stderr);
    assert.equal(JSON.parse(trusted.stdout).issuerTrust, 'expected');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
