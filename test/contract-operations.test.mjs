import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { digest, compareAssessments, assess } from '../src/index.mjs';
import { V2_OPERATIONS } from '../interop/impl-contract/js-operations.mjs';
import { runVectors } from '../scripts/run-vectors.mjs';

// Conformance contract version 2 (ADR-0034): canonicalize, digest, verify-envelope and compare.
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const FILE = JSON.parse(readFileSync(join(ROOT, 'evidence/assessment-vectors.json'), 'utf8'));
const NEW_OPS = ['canonicalize', 'digest', 'verify-envelope', 'compare'];
const LATER_OPS = ['verify-credential', 'verify-score-card', 'compare-score-cards'];
const run = (op, inputs) => V2_OPERATIONS[op](inputs);
const REFERENCE = join(ROOT, 'interop/impl-contract/js-reference.mjs');

test('canonicalize sorts members by UTF-16 code units and writes numbers by value', () => {
  const r = run('canonicalize', { text: '{"b":1.0,"a":[1e2,-0,0.5E1,0.1],"\\ud83d\\ude00":1,"\\uffff":2}' });
  assert.equal(r.canonical, '{"a":[100,0,5,0.1],"b":1,"\u{1f600}":1,"￿":2}');
  assert.equal(r.operation, 'canonicalize');
  assert.equal(r.sha256.length, 64);
});

test('canonicalize writes escapes in lowercase and leaves DEL and the line separators literal', () => {
  const r = run('canonicalize', { text: '"\\u007f\\u2028\\u001f\\n\\u0008\\ud800"' });
  assert.equal(r.canonical, '"\u007f \\u001f\\n\\b\\ud800"');
});

test('canonicalize refuses duplicates, prototype names, bad numbers, trailing text and deep nesting', () => {
  const bad = ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"__proto__":1}', '{"constructor":1}', '{"prototype":1}', '{} {}', '9007199254740992', '1e400', '1e22', '01', '+1', '.5', '1.', '﻿{}', '{"a":1,}', "'a'", '"\u0001"', '"\\x"', '[]'.repeat(2), '['.repeat(34) + ']'.repeat(34), ''];
  const refusing = bad.filter(text => { try { run('canonicalize', { text }); return false; } catch { return true; } });
  assert.deepEqual(refusing, bad);
});

test('canonicalize accepts a value at depth 32 and refuses one at depth 33', () => {
  assert.equal(run('canonicalize', { text: '['.repeat(32) + '1' + ']'.repeat(32) }).canonical, '['.repeat(32) + '1' + ']'.repeat(32));
  assert.throws(() => run('canonicalize', { text: '['.repeat(33) + '1' + ']'.repeat(33) }));
});

test('operations refuse unknown input members and wrong input types', () => {
  assert.throws(() => run('canonicalize', { text: '1', extra: 1 }));
  assert.throws(() => run('canonicalize', { text: 1 }));
  assert.throws(() => run('digest', { artifact: 'nope', value: {} }));
  assert.throws(() => run('verify-envelope', { kind: 'other', envelope: {} }));
  assert.throws(() => run('compare', { left: {} }));
});

test('digest of a signing input is domain separated and a record digest is not', () => {
  const m = FILE.vectors.find(v => v.operation === 'assess').inputs.manifest;
  const r = run('digest', { artifact: 'manifest', value: m });
  assert.equal(r.digest, digest(m));
  const ev = FILE.vectors.find(v => v.operation === 'assess').inputs.evidence[0].payload;
  const s = run('digest', { artifact: 'evidence-signing-input', value: ev });
  assert.equal(s.preimage.startsWith('kya.evidence/v1\n{'), true);
  assert.notEqual(s.digest, digest(ev));
  assert.throws(() => run('digest', { artifact: 'manifest', value: { ...m, extra: 1 } }));
});

test('verify-envelope reports a tampered payload as an invalid signature and trust is not consulted', () => {
  const ev = FILE.vectors.find(v => v.id === 'assess.qualified-all-pass-runtime').inputs.evidence[0];
  const ok = run('verify-envelope', { kind: 'evidence', envelope: ev });
  assert.equal(ok.valid, true);
  assert.equal(ok.failure, null);
  assert.equal(ok.keyId, ev.proof.keyId);
  assert.equal(ok.envelopeDigest, digest(ev));
  const bad = structuredClone(ev); bad.payload.outcome = 'fail';
  const r = run('verify-envelope', { kind: 'evidence', envelope: bad });
  assert.deepEqual([r.valid, r.failure, r.keyId, r.envelopeDigest, r.signingInputSha256], [false, 'SIGNATURE_INVALID', null, null, null]);
  assert.equal(run('verify-envelope', { kind: 'incident', envelope: ev }).failure, 'INVALID_PAYLOAD');
});

test('verify-envelope applies its steps in the order the specification lists', () => {
  const ev = FILE.vectors.find(v => v.id === 'assess.qualified-all-pass-runtime').inputs.evidence[0];
  const f = mut => { const e = structuredClone(ev); mut(e); return run('verify-envelope', { kind: 'evidence', envelope: e }).failure; };
  assert.equal(f(e => { e.extra = 1; }), 'MALFORMED_ENVELOPE');
  assert.equal(f(e => { e.payload.outcome = 'x'; e.proof.algorithm = 'RSA'; }), 'INVALID_PAYLOAD');
  assert.equal(f(e => { e.proof.extra = 1; }), 'MALFORMED_PROOF');
  assert.equal(f(e => { e.proof.algorithm = 'RSA'; e.proof.keyId = 'x'; }), 'UNSUPPORTED_ALGORITHM');
  assert.equal(f(e => { e.proof.keyId = 'x'; e.proof.signature = 'x'; }), 'INVALID_KEY');
  assert.equal(f(e => { e.proof.keyId = 'a'.repeat(64); e.proof.signature = 'x'; }), 'KEY_ID_MISMATCH');
  assert.equal(f(e => { e.proof.signature = e.proof.signature.slice(1); }), 'INVALID_SIGNATURE_ENCODING');
  assert.equal(f(e => { e.proof.signature = 'A'.repeat(85) + 'B'; }), 'INVALID_SIGNATURE_ENCODING');
});

test('compare refuses a resealed report that lacks a digest member and compareAssessments agrees', () => {
  const v = FILE.vectors.find(x => x.id === 'compare.same-population-different-scores');
  assert.ok(v, 'compare vectors are published');
  const { left, right } = v.inputs;
  const strip = r => { const { reportDigest, ...body } = structuredClone(r); delete body.policyDigest; return { ...body, reportDigest: digest(body) }; };
  assert.throws(() => run('compare', { left: strip(left), right: strip(right) }));
  assert.throws(() => compareAssessments(strip(left), strip(right)));
  assert.equal(run('compare', { left, right }).comparable, true);
});

test('compare gives a reason code for each rule and the first failing rule wins', () => {
  const v = FILE.vectors.find(x => x.id === 'compare.same-population-different-scores');
  const { left } = v.inputs;
  const reseal = (r, patch) => { const { reportDigest, ...body } = structuredClone(r); Object.assign(body, patch); return { ...body, reportDigest: digest(body) }; };
  const reason = patch => run('compare', { left, right: reseal(left, patch) }).reason;
  assert.equal(reason({ scopeId: 'other' }), 'SCOPE_ID_DIFFERS');
  assert.equal(reason({ scopeDigest: 'a'.repeat(64) }), 'SCOPE_DIGEST_DIFFERS');
  assert.equal(reason({ profileDigest: 'a'.repeat(64), evaluatorDigest: 'b'.repeat(64) }), 'PROFILE_DIFFERS');
  assert.equal(reason({ evaluatorDigest: 'a'.repeat(64) }), 'EVALUATOR_DIFFERS');
  assert.equal(reason({ policyDigest: 'a'.repeat(64) }), 'POLICY_DIFFERS');
  assert.equal(reason({ evidenceMode: 'fixture' }), 'EVIDENCE_MODE_DIFFERS');
  assert.equal(reason({ checks: left.checks.slice(1) }), 'CHECK_POPULATION_DIFFERS');
  assert.equal(reason({ checks: left.checks.map((c, i) => i === 0 ? { ...c, status: 'unknown' } : c) }), 'CHECKS_INCOMPLETE');
});

test('the vectors file is version 2, adds the four operations and keeps the 272 version 1 vectors byte for byte', () => {
  assert.equal(FILE.schema, 'kya.assessment-vectors/v2');
  assert.deepEqual(FILE.contract, { version: 2, operations: ['assess', 'currency', ...NEW_OPS, ...LATER_OPS] });
  const v1 = FILE.vectors.filter(v => ['assess', 'currency'].includes(v.operation));
  assert.equal(v1.length, 272);
  assert.equal(digest(v1.map(v => digest(v))), 'f72c4804607f372b65b3d641c49f9c0cfaaf4a14d73cd6dcc5badf957d650821');
  assert.equal(digest(FILE.keys), '02c677ab13a35f2bed1f00672e67933801dc6d984e1dbd1b738f447cc5cc4ff5');
  for (const op of NEW_OPS) assert.ok(FILE.vectors.filter(v => v.operation === op).length >= 10, op);
});

test('at least a third of the new vectors are refusals and every new vector cites a requirement and names it in its rationale', () => {
  const fresh = FILE.vectors.filter(v => NEW_OPS.includes(v.operation));
  const refusals = fresh.filter(v => v.expected.refused === true);
  assert.ok(refusals.length * 3 >= fresh.length, `${refusals.length} of ${fresh.length}`);
  for (const v of fresh) assert.ok(v.requirements.some(r => v.rationale.includes(r)), v.id);
});

test('every specified failure code and reason code appears in at least one vector', () => {
  const codes = ['MALFORMED_ENVELOPE', 'INVALID_PAYLOAD', 'MALFORMED_PROOF', 'UNSUPPORTED_ALGORITHM', 'INVALID_KEY', 'KEY_ID_MISMATCH', 'INVALID_SIGNATURE_ENCODING', 'SIGNATURE_INVALID'];
  for (const c of codes) assert.ok(FILE.vectors.some(v => v.operation === 'verify-envelope' && v.expected.failure === c), c);
  const reasons = ['SCOPE_ID_DIFFERS', 'SCOPE_DIGEST_DIFFERS', 'PROFILE_DIFFERS', 'EVALUATOR_DIFFERS', 'POLICY_DIFFERS', 'EVIDENCE_MODE_DIFFERS', 'CHECK_POPULATION_DIFFERS', 'CHECKS_INCOMPLETE'];
  for (const c of reasons) assert.ok(FILE.vectors.some(v => v.operation === 'compare' && v.expected.reason === c), c);
});

test('the reference adapter answers the four operations and still refuses malformed input', () => {
  const call = input => spawnSync(process.execPath, [REFERENCE], { input: JSON.stringify(input), encoding: 'utf8', timeout: 60000 });
  const ok = call({ schema: 'kya.impl-input/v1', operation: 'canonicalize', inputs: { text: '{"b":1,"a":2}' } });
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).canonical, '{"a":2,"b":1}');
  const refused = call({ schema: 'kya.impl-input/v1', operation: 'canonicalize', inputs: { text: '{"a":1,"a":1}' } });
  assert.notEqual(refused.status, 0);
  assert.equal(refused.stdout, '');
  const unknown = call({ schema: 'kya.impl-input/v1', operation: 'sign', inputs: {} });
  assert.equal(JSON.parse(unknown.stdout).unsupported, true);
});

test('an implementation that predates version 2 scores its version 1 vectors as before and the new vectors are not-run', async () => {
  const wrap = `import { spawnSync } from 'node:child_process';import { readFileSync } from 'node:fs';const input = readFileSync(0, 'utf8');const op = JSON.parse(input).operation;if (!['assess','currency'].includes(op)) { process.stdout.write(JSON.stringify({schema:'kya.impl-result/v1',operation:op,unsupported:true})); process.exit(0); }const r = spawnSync(process.execPath, [${JSON.stringify(REFERENCE)}], { input, encoding: 'utf8' });process.stdout.write(r.stdout);process.exit(r.status);`;
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'kya-old-'));
  try {
    writeFileSync(join(dir, 'old.mjs'), wrap);
    const { summary } = await runVectors({ impl: `"${process.execPath}" "${join(dir, 'old.mjs')}"`, vectorsFile: join(ROOT, 'evidence/assessment-vectors.json'), timeoutMs: 120000, jobs: 4 });
    // A refusal vector whose stdin text is not even JSON is refused by this wrapper like by any implementation, so it passes; every other new vector is not-run.
    const notJson = FILE.vectors.filter(v => !['assess', 'currency'].includes(v.operation) && typeof v.rawInput === 'string' && (() => { try { JSON.parse(v.rawInput); return false; } catch { return true; } })()).length;
    assert.equal(summary.vectors.pass, 272 + notJson);
    assert.equal(summary.vectors.fail, 0);
    assert.equal(summary.vectors.unsupported, FILE.vectors.length - 272 - notJson);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the new operations do not change the result of a version 1 assessment', () => {
  const v = FILE.vectors.find(x => x.id === 'assess.qualified-all-pass-runtime');
  assert.equal(assess(structuredClone(v.inputs)).reportDigest, v.expected.reportDigest);
});

test('both adapters refuse stdin above one mebibyte and accept an input just inside it', () => {
  const SECOND = join(ROOT, 'interop/second-impl/adapter.mjs');
  const wrapper = '{"schema":"kya.impl-input/v1","operation":"canonicalize","inputs":{"text":';
  const make = n => wrapper + JSON.stringify('"' + 'a'.repeat(n) + '"') + '}}';
  const overhead = Buffer.byteLength(make(0));
  const inside = make(1_048_576 - overhead), over = make(1_048_576 - overhead + 1);
  assert.equal(Buffer.byteLength(inside), 1_048_576);
  assert.equal(Buffer.byteLength(over), 1_048_577);
  for (const adapter of [REFERENCE, SECOND]) {
    const ok = spawnSync(process.execPath, [adapter], { input: inside, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024 });
    assert.equal(ok.status, 0, adapter + ' ' + ok.stderr.slice(0, 200));
    const refused = spawnSync(process.execPath, [adapter], { input: over, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024 });
    assert.notEqual(refused.status, 0, adapter);
    assert.equal(refused.stdout, '', adapter);
  }
});

test('an implementation of the six earlier operations scores the three later ones as not-run and keeps every other result', async () => {
  const six = ['assess', 'currency', 'canonicalize', 'digest', 'verify-envelope', 'compare'];
  const wrap = `import { spawnSync } from 'node:child_process';import { readFileSync } from 'node:fs';const input = readFileSync(0, 'utf8');let op = null;try { op = JSON.parse(input).operation; } catch { process.exit(2); }if (!${JSON.stringify(six)}.includes(op)) { process.stdout.write(JSON.stringify({schema:'kya.impl-result/v1',operation:op,unsupported:true})); process.exit(0); }const r = spawnSync(process.execPath, [${JSON.stringify(REFERENCE)}], { input, encoding: 'utf8' });process.stdout.write(r.stdout);process.exit(r.status);`;
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'kya-six-'));
  try {
    const earlier = six.flatMap(op => FILE.vectors.filter(v => v.operation === op).slice(0, 6));
    const later = LATER_OPS.flatMap(op => [...FILE.vectors.filter(v => v.operation === op && v.expected.refused !== true).slice(0, 5), ...FILE.vectors.filter(v => v.operation === op && v.expected.refused === true && v.inputs).slice(0, 3)]);
    writeFileSync(join(dir, 'old.mjs'), wrap);
    writeFileSync(join(dir, 'vectors.json'), JSON.stringify({ ...FILE, vectors: [...earlier, ...later] }));
    const { summary } = await runVectors({ impl: `"${process.execPath}" "${join(dir, 'old.mjs')}"`, vectorsFile: join(dir, 'vectors.json'), timeoutMs: 120000, jobs: 4 });
    assert.equal(summary.vectors.fail, 0);
    assert.equal(summary.vectors.pass, earlier.length);
    assert.equal(summary.vectors.unsupported, later.length);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
