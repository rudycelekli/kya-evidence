import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { digest } from '../src/index.mjs';
import { buildReport, validateReport, signReport, verifyReport, parseTap, mapTapToRequirements, summarize, REPORT_DOMAIN } from '../src/conformance-report/index.mjs';

const REG = { schema: 'kya.requirements/v1', requirements: [
  { id: 'KYA-AAA-001', level: 'MUST', area: 'a', section: 's', statement: 'x MUST y', tests: [{ file: 'test/a.test.mjs', title: 't1' }] },
  { id: 'KYA-AAA-002', level: 'MUST', area: 'a', section: 's', statement: 'x MUST z', tests: [{ file: 'test/a.test.mjs', title: 't2' }] },
  { id: 'KYA-BBB-001', level: 'MAY', area: 'b', section: 's', statement: 'x MAY w', tests: [{ file: 'test/b.test.mjs', title: 't3' }] }
] };
const IMPL = { name: 'demo', version: '1.0.0', language: 'javascript', sourceDigest: null, declaredSubset: null };
const NOW = '2026-10-14T12:00:00.000Z';
const pass = id => ({ result: 'pass', evidence: 'executed-test', executed: ['test/a.test.mjs :: ' + id] });
const base = () => ({ 'KYA-AAA-001': pass('t1'), 'KYA-AAA-002': { result: 'not-run', evidence: null, executed: [] }, 'KYA-BBB-001': { result: 'fail', evidence: 'executed-test', executed: ['test/b.test.mjs :: t3'] } });
const build = (over = {}) => buildReport({ registry: REG, implementation: IMPL, results: base(), runAt: NOW, ...over });

test('conformance report is deterministic and binds the registry digest', () => {
  const a = build(), b = build({ results: Object.fromEntries(Object.entries(base()).reverse()) });
  assert.equal(digest(a), digest(b));
  assert.equal(a.schema, 'kya.conformance-report/v1');
  assert.equal(a.registryDigest, digest(REG));
  assert.deepEqual(a.results.map(r => r.id), ['KYA-AAA-001', 'KYA-AAA-002', 'KYA-BBB-001']);
  assert.equal(a.runAt, NOW);
});

test('conformance summary counts keep not-run in the denominator', () => {
  const s = build().summary;
  assert.deepEqual(s, { total: 3, pass: 1, fail: 1, notApplicable: 0, notRun: 1, applicable: 3, passPermille: 333, declarationEntries: 0 });
  const none = build({ results: { 'KYA-AAA-001': { result: 'not-run', evidence: null, executed: [] }, 'KYA-AAA-002': { result: 'not-run', evidence: null, executed: [] }, 'KYA-BBB-001': { result: 'not-run', evidence: null, executed: [] } } });
  assert.equal(none.summary.passPermille, 0);
  assert.equal(none.summary.notRun, 3);
});

test('conformance build rejects unknown missing and duplicate requirement IDs', () => {
  assert.throws(() => build({ results: { ...base(), 'KYA-ZZZ-999': pass('t9') } }), /unknown/i);
  const missing = base(); delete missing['KYA-BBB-001'];
  assert.throws(() => build({ results: missing }), /missing/i);
  const list = Object.entries(base()).map(([id, v]) => ({ id, ...v }));
  assert.throws(() => build({ results: [...list, list[0]] }), /duplicate/i);
  assert.equal(build({ results: list }).summary.total, 3);
});

test('conformance build rejects a pass claimed on declaration evidence', () => {
  assert.throws(() => build({ results: { ...base(), 'KYA-AAA-001': { result: 'pass', evidence: 'declaration', executed: [] } } }), /declaration/i);
  const ok = build({ results: { ...base(), 'KYA-AAA-001': { result: 'fail', evidence: 'declaration', executed: [] } } });
  assert.equal(ok.summary.pass, 0);
  assert.equal(ok.summary.declarationEntries, 1);
});

test('conformance build rejects a pass without executed test or vector IDs', () => {
  assert.throws(() => build({ results: { ...base(), 'KYA-AAA-001': { result: 'pass', evidence: 'executed-test', executed: [] } } }), /executed/i);
  assert.throws(() => build({ results: { ...base(), 'KYA-AAA-001': { result: 'pass', evidence: null, executed: ['x'] } } }));
  const v = build({ results: { ...base(), 'KYA-AAA-001': { result: 'pass', evidence: 'portable-vector', executed: ['vector:canonical-1'] } } });
  assert.equal(v.summary.pass, 1);
});

test('conformance build rejects registry digest mismatch', () => {
  assert.throws(() => build({ registryDigest: '0'.repeat(64) }), /digest/i);
  assert.equal(build({ registryDigest: digest(REG) }).registryDigest, digest(REG));
});

test('conformance not-applicable requires a declared subset that excludes the ID', () => {
  const na = { result: 'not-applicable', evidence: null, executed: [] };
  assert.throws(() => build({ results: { ...base(), 'KYA-BBB-001': na } }), /not-applicable/i);
  const sub = { ...IMPL, declaredSubset: ['KYA-AAA-001', 'KYA-AAA-002'] };
  const r = build({ implementation: sub, results: { ...base(), 'KYA-BBB-001': na } });
  assert.equal(r.summary.notApplicable, 1);
  assert.equal(r.summary.applicable, 2);
  assert.throws(() => build({ implementation: sub, results: { ...base(), 'KYA-AAA-002': na } }), /not-applicable/i);
  assert.throws(() => build({ implementation: sub, results: { ...base(), 'KYA-BBB-001': { result: 'not-run', evidence: null, executed: [] } } }), /subset/i);
  assert.throws(() => build({ implementation: { ...IMPL, declaredSubset: ['KYA-NOP-001'] } }), /unknown/i);
});

test('conformance validate is strict about shape and recomputes the summary', () => {
  const r = build();
  assert.equal(validateReport(r, { registry: REG }).summary.pass, 1);
  assert.throws(() => validateReport({ ...r, extra: 1 }));
  assert.throws(() => validateReport({ ...r, summary: { ...r.summary, pass: 3 } }), /summary/i);
  assert.throws(() => validateReport({ ...r, runAt: 'today' }));
  assert.throws(() => validateReport({ ...r, results: [...r.results].reverse() }), /order/i);
  assert.throws(() => validateReport({ ...r, results: [{ ...r.results[0], note: 'x' }, ...r.results.slice(1)] }));
  assert.throws(() => validateReport({ ...r, registryDigest: '1'.repeat(64) }, { registry: REG }), /digest/i);
  assert.throws(() => validateReport({ ...r, results: r.results.slice(1), summary: summarize(r.results.slice(1)) }, { registry: REG }), /missing/i);
  const tampered = JSON.parse(JSON.stringify(r)); tampered.results[1].result = 'pass';
  assert.throws(() => validateReport(tampered), /summary|evidence/i);
});

test('conformance report signature is domain separated and detects tampering', () => {
  const { privateKey } = generateKeyPairSync('ed25519'), other = generateKeyPairSync('ed25519');
  assert.equal(REPORT_DOMAIN, 'kya.conformance-report/v1\n');
  const env = signReport(build(), privateKey), v = verifyReport(env, { registry: REG });
  assert.equal(v.authenticated, false);
  assert.equal(v.truthfulnessVerified, false);
  assert.equal(v.payload.summary.pass, 1);
  const forged = JSON.parse(JSON.stringify(env)); forged.payload.results[1] = { id: 'KYA-AAA-002', ...pass('t2') }; forged.payload.summary = { ...forged.payload.summary, pass: 2, notRun: 0, passPermille: 666 };
  assert.throws(() => verifyReport(forged), /signature/i);
  assert.throws(() => verifyReport({ ...env, proof: { ...env.proof, publicKey: other.publicKey.export({ format: 'pem', type: 'spki' }).toString() } }));
  assert.throws(() => verifyReport({ ...env, proof: { ...env.proof, signature: 'A'.repeat(86) } }));
  assert.throws(() => signReport(build(), other.publicKey));
});

test('conformance signature does not verify under the incident domain', async () => {
  const { sign } = await import('node:crypto'), { canonical } = await import('../src/shared/canonical.mjs');
  const { privateKey } = generateKeyPairSync('ed25519'), env = signReport(build(), privateKey);
  const wrong = sign(null, Buffer.from('kya.incident/v1\n' + canonical(env.payload)), privateKey).toString('base64url');
  assert.throws(() => verifyReport({ ...env, proof: { ...env.proof, signature: wrong } }), /signature/i);
});

test('tap parser reads top level results with escapes and skips', () => {
  const tap = ['TAP version 13', '# Subtest: a', 'ok 1 - a \\# b \\\\ c', '  ---', '  ...', 'not ok 2 - bad one', '    ok 1 - nested hidden', 'ok 3 - sk # SKIP', 'ok 4 - td # TODO', '1..4'].join('\n');
  assert.deepEqual(parseTap(tap), [
    { title: 'a # b \\ c', status: 'pass' }, { title: 'bad one', status: 'fail' }, { title: 'sk', status: 'skip' }, { title: 'td', status: 'skip' }
  ]);
});

test('tap mapping passes only when every traced test passes and none is skipped', () => {
  const reg = { requirements: [
    { id: 'KYA-AAA-001', tests: [{ file: 'f1', title: 'a' }, { file: 'f1', title: 'b' }] },
    { id: 'KYA-AAA-002', tests: [{ file: 'f1', title: 'a' }, { file: 'f2', title: 'c' }] },
    { id: 'KYA-AAA-003', tests: [{ file: 'f2', title: 'd', hostConditional: true }] },
    { id: 'KYA-AAA-004', tests: [{ file: 'f2', title: 'e' }] },
    { id: 'KYA-AAA-005', tests: [{ file: 'f3', title: 'z' }] },
    { id: 'KYA-AAA-006', tests: [{ file: 'f1', title: 'a' }, { file: 'f2', title: 'd', hostConditional: true }] }
  ] };
  const runs = {
    f1: { exitCode: 0, tests: [{ title: 'a', status: 'pass' }, { title: 'b', status: 'pass' }] },
    f2: { exitCode: 1, tests: [{ title: 'c', status: 'fail' }, { title: 'd', status: 'skip' }] },
    f3: { exitCode: 1, tests: [] }
  };
  const m = mapTapToRequirements(reg, runs);
  assert.equal(m['KYA-AAA-001'].result, 'pass');
  assert.equal(m['KYA-AAA-001'].evidence, 'executed-test');
  assert.deepEqual(m['KYA-AAA-001'].executed, ['f1 :: a', 'f1 :: b']);
  assert.equal(m['KYA-AAA-002'].result, 'fail');
  assert.equal(m['KYA-AAA-003'].result, 'not-run');
  assert.equal(m['KYA-AAA-003'].evidence, null);
  assert.equal(m['KYA-AAA-004'].result, 'not-run');
  assert.equal(m['KYA-AAA-005'].result, 'not-run');
  assert.equal(m['KYA-AAA-006'].result, 'not-run');
});

test('tap mapping never reports pass for a file that exited non-zero, timed out or errored', () => {
  const reg = { requirements: [{ id: 'KYA-AAA-001', tests: [{ file: 'f', title: 'a' }] }] };
  const pass = [{ title: 'a', status: 'pass' }];
  assert.equal(mapTapToRequirements(reg, { f: { exitCode: 0, tests: pass } })['KYA-AAA-001'].result, 'pass');
  for (const run of [{ exitCode: 1, tests: pass }, { exitCode: null, tests: pass }, { exitCode: 0, error: 'ETIMEDOUT', tests: pass }, { tests: pass }]) {
    const r = mapTapToRequirements(reg, { f: run })['KYA-AAA-001'];
    assert.equal(r.result, 'not-run', JSON.stringify({ exitCode: run.exitCode, error: run.error }));
    assert.equal(r.evidence, null);
  }
  assert.equal(mapTapToRequirements(reg, { f: { exitCode: 1, tests: [{ title: 'a', status: 'fail' }] } })['KYA-AAA-001'].result, 'fail');
});

test('conformance CLI builds unsigned reports from traced tests and verifies them', () => {
  const root = mkdtempSync(join(tmpdir(), 'kya-conf-'));
  try {
    mkdirSync(join(root, 'evidence')); mkdirSync(join(root, 'docs')); mkdirSync(join(root, 'test'));
    writeFileSync(join(root, 'docs/SPEC.md'), '## s\n');
    const reg = { schema: 'kya.requirements/v1', specification: 'docs/SPEC.md', keywords: 'k', requirements: [
      { id: 'KYA-AAA-001', level: 'MUST', area: 'a', section: 's', statement: 'x MUST y', tests: [{ file: 'test/a.test.mjs', title: 'good one' }] },
      { id: 'KYA-AAA-002', level: 'MUST', area: 'a', section: 's', statement: 'x MUST z', tests: [{ file: 'test/a.test.mjs', title: 'bad one' }] }
    ] };
    writeFileSync(join(root, 'evidence/requirements.json'), JSON.stringify(reg));
    writeFileSync(join(root, 'test/a.test.mjs'), "import test from 'node:test';\ntest('good one',()=>{});\ntest('bad one',()=>{throw Error('no');});\n");
    const script = fileURLToPath(new URL('../scripts/conformance-report.mjs', import.meta.url));
    const run = args => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', cwd: root });
    const refuse = run(['--root', root]);
    assert.notEqual(refuse.status, 0);
    assert.match(refuse.stderr, /--now/);
    const out = join(root, 'report.json');
    const built = run(['--root', root, '--now', NOW, '--out', out]);
    assert.equal(built.status, 0, built.stderr);
    const summary = JSON.parse(built.stdout);
    assert.deepEqual([summary.pass, summary.fail, summary.notRun, summary.total], [1, 1, 0, 2]);
    const ver = run(['--root', root, '--verify', out]);
    assert.equal(ver.status, 0, ver.stderr);
    assert.equal(JSON.parse(ver.stdout).authenticated, false);
    writeFileSync(out, readTampered(out));
    assert.notEqual(run(['--root', root, '--verify', out]).status, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
function readTampered(path) {
  const r = JSON.parse(readFileSync(path, 'utf8')); r.summary.pass = 2; return JSON.stringify(r);
}
