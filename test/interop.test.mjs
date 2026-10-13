import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, digest } from '../src/index.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'interop/python/kya_portability.py');
const probe = spawnSync('python3', ['--version'], { encoding: 'utf8', timeout: 2000, maxBuffer: 1024, shell: false });
const hasPython = !probe.error && probe.status === 0;
const env = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', LANG: 'C.UTF-8', PYTHONIOENCODING: 'utf-8' };
function python(args, input) {
  const result = spawnSync('python3', [script, ...args], { cwd: root, env, input, encoding: 'utf8', timeout: 5000, maxBuffer: 1_048_576, shell: false });
  assert.equal(result.error, undefined, result.error?.message);
  return { ...result, value: JSON.parse(result.stdout) };
}

test('Python reconstructs every published vector and records optional signature availability', { skip: !hasPython && 'Python 3 is optional; unavailable on this host' }, () => {
  const result = python(['check-vectors', join(root, 'evidence/golden-vectors.json')]);
  assert.equal(result.status, 0);
  assert.equal(result.value.canonicalCases, 6);
  assert.equal(result.value.externalIndependence, false);
  assert.equal(result.value.status === 'passed', result.value.signature.verified);
  assert.equal(result.value.signature.authenticatedIssuer, false);
});

test('Python string spelling, UTF-16 member order and supported numbers agree with JS', { skip: !hasPython }, () => {
  const cases = [
    { '\ue000': 2, '\u{10000}': 1, '\ud800': 3, '\udfff': 4 },
    { lone: '\ud800x\udfff', paired: '\ud83d\ude00', separators: '\u2028\u2029', controls: '\x00\b\t\n\f\r' },
    { numbers: [-0, 0.25, -0.125, 1e-6, 1e-7, 1e-10, Number.MAX_SAFE_INTEGER] },
    { unicode: '🧭 café', 'é': 'composed', 'e\u0301': 'decomposed' },
  ];
  for (const value of cases) {
    const result = python(['canonical'], JSON.stringify(value));
    assert.equal(result.status, 0);
    assert.equal(result.value.canonical, canonical(value));
    assert.equal(result.value.sha256, digest(value));
  }
});

test('Python explicitly refuses unsupported JS doubles rather than claiming agreement', { skip: !hasPython }, () => {
  for (const value of [0.3, 1.23456789, Number.MIN_VALUE]) {
    assert.equal(typeof canonical(value), 'string');
    const result = python(['canonical'], JSON.stringify(value));
    assert.equal(result.status, 2);
    assert.equal(result.value.status, 'unsupported');
    assert.equal(result.value.canonical, undefined);
  }
});

test('every supported small dyadic fraction and decimal power agrees in one bounded cross-language batch', { skip: !hasPython }, () => {
  const value = Array.from({ length: 513 }, (_, index) => (index - 256) / 256);
  for (let exponent = 1; exponent <= 15; exponent++) value.push(Number(`1e-${exponent}`), -Number(`1e-${exponent}`));
  const result = python(['canonical'], JSON.stringify(value));
  assert.equal(result.status, 0);
  assert.equal(result.value.canonical, canonical(value));
  assert.equal(result.value.sha256, digest(value));
});

test('Python standard-library-only checking remains partial without cryptographic verification', { skip: !hasPython }, () => {
  const result = python(['check-vectors', join(root, 'evidence/golden-vectors.json'), '--no-crypto']);
  assert.equal(result.status, 0);
  assert.equal(result.value.status, 'partial');
  assert.equal(result.value.signature.verified, false);
});

test('independently corrupted canonical/hash/signing-input vectors fail', { skip: !hasPython }, () => {
  const vectors = JSON.parse(readFileSync(join(root, 'evidence/golden-vectors.json'), 'utf8'));
  const dir = mkdtempSync(join(tmpdir(), 'kya-python-vectors-'));
  try {
    for (const mutate of [v => v.cases[0].canonical = '0', v => v.cases[0].sha256 = '0'.repeat(64), v => v.signature.signingInput += ' ']) {
      const changed = structuredClone(vectors);
      mutate(changed);
      const file = join(dir, 'corrupt.json');
      writeFileSync(file, JSON.stringify(changed));
      const result = python(['check-vectors', file, '--no-crypto']);
      assert.equal(result.status, 1);
      assert.equal(result.value.status, 'failed');
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('Python rejects duplicate members and bounded input abuse', { skip: !hasPython }, () => {
  for (const input of ['{"x":1,"\\u0078":2}', '{"__proto__":1}', '['.repeat(40) + '0' + ']'.repeat(40), '"' + 'x'.repeat(1_048_576) + '"']) {
    const result = python(['canonical'], input);
    assert.equal(result.status, 1);
    assert.equal(result.value.status, 'failed');
  }
});
