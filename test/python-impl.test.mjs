import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { runVectors } from '../scripts/run-vectors.mjs';

// interop/python-impl/adapter.py implements six of the nine contract operations in Python 3 with the standard
// library only, including Ed25519 verification written from RFC 8032. canonicalize, digest, verify-envelope and
// compare were written first; assess and currency were added in a second round, from the specification text, the
// scoring document, the implementers guide and the contract README, then run against the vectors. It is a
// same-team implementation in a different language, not outside review. The other three operations
// (verify-credential, verify-score-card, compare-score-cards) answer unsupported and so are not-run. The title of
// the unsupported test below still says five because the registry traces tests by exact title.
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const ADAPTER = join(ROOT, 'interop/python-impl/adapter.py');
const VECTORS = join(ROOT, 'evidence/assessment-vectors.json');
const probe = spawnSync('python3', ['--version'], { encoding: 'utf8', timeout: 20000, maxBuffer: 1024, shell: false });
const hasPython = !probe.error && probe.status === 0;
const SKIP = !hasPython && 'Python 3 is optional; unavailable on this host, so the Python implementation was NOT run';

const IMPLEMENTED = { canonicalize: 72, digest: 38, 'verify-envelope': 68, compare: 35, assess: 212, currency: 60 };
const UNSUPPORTED = ['verify-credential', 'verify-score-card', 'compare-score-cards'];
const file = JSON.parse(readFileSync(VECTORS, 'utf8'));

// Every vector of the four implemented operations, plus up to four vectors per other operation (non-refusals first,
// then refusals) so that the unsupported answer is exercised without running all 799 vectors in a unit test.
function subset() {
  const out = [];
  for (const op of Object.keys(IMPLEMENTED)) out.push(...file.vectors.filter(v => v.operation === op));
  for (const op of UNSUPPORTED) {
    const mine = file.vectors.filter(v => v.operation === op);
    const plain = mine.filter(v => !v.expected.refused && v.rawInput === undefined);
    out.push(...plain.slice(0, 3));
  }
  return out;
}

async function harness(vectors) {
  const dir = mkdtempSync(join(tmpdir(), 'kya-py-'));
  try {
    const f = join(dir, 'vectors.json');
    writeFileSync(f, JSON.stringify({ ...file, vectors }));
    const { outcomes } = await runVectors({ impl: 'python3 -I "' + ADAPTER + '"', vectorsFile: f, timeoutMs: 120000, jobs: 4, root: ROOT });
    return outcomes;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const vectors = subset();
const opOf = new Map(file.vectors.map(v => [v.id, v.operation]));
const OUTCOMES = hasPython ? await harness(vectors) : [];
const counts = (op) => { const c = {}; for (const o of OUTCOMES.filter(x => opOf.get(x.id) === op)) c[o.status] = (c[o.status] ?? 0) + 1; return c; };

test('the vectors file still holds the counts this test pins for the four python operations', () => {
  for (const [op, n] of Object.entries(IMPLEMENTED)) assert.equal(file.vectors.filter(v => v.operation === op).length, n, op);
});

test('python passes every canonicalize vector through the harness', { skip: SKIP }, () => {
  assert.deepEqual(counts('canonicalize'), { pass: 72 });
});

test('python passes every digest vector through the harness', { skip: SKIP }, () => {
  assert.deepEqual(counts('digest'), { pass: 38 });
});

test('python passes every verify-envelope vector through the harness', { skip: SKIP }, () => {
  assert.deepEqual(counts('verify-envelope'), { pass: 68 });
});

test('python passes every compare vector through the harness', { skip: SKIP }, () => {
  assert.deepEqual(counts('compare'), { pass: 35 });
});

test('python passes every assess vector through the harness', { skip: SKIP }, () => {
  assert.deepEqual(counts('assess'), { pass: 212 });
});

test('python passes every currency vector through the harness', { skip: SKIP }, () => {
  assert.deepEqual(counts('currency'), { pass: 60 });
});

// The title says five for the registry; the operations Python does not implement are now the three of UNSUPPORTED.
test('python answers unsupported for the five operations it does not implement so the harness records not-run', { skip: SKIP }, () => {
  for (const op of UNSUPPORTED) assert.deepEqual(counts(op), { unsupported: 3 }, op);
});

test('the unsupported reply is exactly the three member object of the contract', { skip: SKIP }, () => {
  for (const op of UNSUPPORTED) {
    const r = spawnSync('python3', ['-I', ADAPTER], { input: JSON.stringify({ schema: 'kya.impl-input/v1', operation: op, inputs: {} }), encoding: 'utf8' });
    assert.equal(r.status, 0, op);
    assert.deepEqual(JSON.parse(r.stdout), { schema: 'kya.impl-result/v1', operation: op, unsupported: true });
  }
});

test('python refuses input that the strict parser refuses before it looks at the operation', { skip: SKIP }, () => {
  const bad = ['{"schema":"kya.impl-input/v1","operation":"assess","inputs":{},"inputs":{}}', '{"schema":"kya.impl-input/v1","operation":"assess","inputs":{}} x', '﻿{}', '{"schema":"kya.impl-input/v1","operation":"digest","inputs":{"__proto__":1}}'];
  for (const text of bad) {
    const r = spawnSync('python3', ['-I', ADAPTER], { input: text, encoding: 'utf8' });
    assert.notEqual(r.status, 0, text);
  }
  const ill = spawnSync('python3', ['-I', ADAPTER], { input: Buffer.from([0x7b, 0xc3, 0x28, 0x7d]) });
  assert.notEqual(ill.status, 0);
});

const STDLIB = new Set(['sys', 're', 'json', 'hashlib', 'base64', 'binascii', 'calendar', 'time']);
const SOURCE = readFileSync(ADAPTER, 'utf8');

test('the python source imports only standard library modules', () => {
  const found = [];
  for (const line of SOURCE.split('\n')) {
    const m = /^\s*(?:import\s+([A-Za-z0-9_., ]+)|from\s+([A-Za-z0-9_.]+)\s+import\s)/.exec(line);
    if (!m) continue;
    if (m[2]) found.push(m[2].split('.')[0]);
    else for (const part of m[1].split(',')) found.push(part.trim().split(/\s+as\s+/)[0].split('.')[0]);
  }
  assert.ok(found.length >= 5);
  for (const name of found) assert.ok(STDLIB.has(name), 'not an allowed standard library module: ' + name);
});

test('the python source makes no network subprocess file or dynamic code calls', () => {
  const code = SOURCE.split('\n').filter(l => !/^\s*#/.test(l)).join('\n');
  for (const word of ['socket', 'urllib', 'http', 'ssl', 'subprocess', 'os.', 'ctypes', 'importlib', '__import__', 'eval(', 'exec(', 'open(', 'pickle', 'cryptography', 'nacl', 'ecdsa'])
    assert.equal(code.includes(word), false, word);
  assert.equal(/\bimport\s+os\b/.test(code), false);
});

test('the python adapter is one file that does not read src or the vectors', () => {
  for (const word of ['src/', 'assessment-vectors', 'js-reference', 'second-impl']) assert.equal(SOURCE.includes(word), false, word);
});

function both(op, inputs) {
  const input = JSON.stringify({ schema: 'kya.impl-input/v1', operation: op, inputs });
  const py = spawnSync('python3', ['-I', ADAPTER], { input, encoding: 'utf8' });
  const js = spawnSync('node', [join(ROOT, 'interop/impl-contract/js-reference.mjs')], { input, encoding: 'utf8' });
  return [py, js];
}
const same = (op, inputs) => {
  const [py, js] = both(op, inputs);
  assert.equal(py.status === 0, js.status === 0, 'python status ' + py.status + ' reference status ' + js.status);
  if (py.status === 0) assert.deepEqual(JSON.parse(py.stdout), JSON.parse(js.stdout));
  return py.status === 0;
};
const firstOf = (op, art, refused = false) => structuredClone(file.vectors.find(v => v.operation === op && (art === undefined || v.inputs.artifact === art) && !v.expected.refused === !refused).inputs);

test('the rules the disagreement log says were written into the specification agree between python and the reference', { skip: SKIP }, () => {
  const profile = firstOf('digest', 'profile');
  profile.value.checks[0].title = '';
  assert.equal(same('digest', profile), false);
  const dim = firstOf('digest', 'profile');
  dim.value.checks[0].dimension = 'safety';
  assert.equal(same('digest', dim), false);
  const noTitle = firstOf('digest', 'profile');
  delete noTitle.value.checks[0].title;
  assert.equal(same('digest', noTitle), false);
  const manifest = firstOf('digest', 'manifest');
  manifest.value.agent.name = 'a\u0080b';
  assert.equal(same('digest', manifest), true);
  manifest.value.agent.name = 'a\u007fb';
  assert.equal(same('digest', manifest), false);
  const policy = firstOf('digest', 'policy');
  policy.value.mandatoryMinimums = [{ checkId: 'x.y', minimum: 'pass' }, { checkId: 'x.y', minimum: 'independent-pass' }];
  assert.equal(same('digest', policy), false);
});

const canon = x => x === null || typeof x !== 'object' ? JSON.stringify(x) : Array.isArray(x) ? '[' + x.map(canon).join(',') + ']' : '{' + Object.keys(x).sort().map(k => JSON.stringify(k) + ':' + canon(x[k])).join(',') + '}';
const seal = r => { delete r.reportDigest; r.reportDigest = createHash('sha256').update(canon(r)).digest('hex'); return r; };

test('python and the reference agree on the blocker code rules of a compared report', { skip: SKIP }, () => {
  const blocked = file.vectors.find(v => v.id === 'compare.two-blocked-reports-do-not-change-decision').inputs;
  const variant = f => { const i = structuredClone(blocked); f(i.left); seal(i.left); i.right = structuredClone(i.left); return i; };
  assert.equal(same('compare', variant(() => {})), true);
  assert.equal(same('compare', variant(r => { r.blockerCodes = ['NOT_A_CODE']; })), false);
  assert.equal(same('compare', variant(r => { r.blockerCodes = ['critical_check_failed']; })), false);
  assert.equal(same('compare', variant(r => { r.blockerCodes = ['COVERAGE_BELOW_POLICY']; })), false);
  assert.equal(same('compare', variant(r => { r.blockerCodes = ['SUBJECT_REVOKED']; })), true);
  const plain = file.vectors.find(v => v.id === 'compare.identical-reports').inputs;
  const q = structuredClone(plain); q.left.blockers = ['x']; q.left.blockerCodes = ['SCORE_BELOW_POLICY']; seal(q.left); q.right = structuredClone(q.left);
  assert.equal(same('compare', q), false);
});

test('python and the reference agree on number formatting for a spread of doubles', { skip: SKIP }, () => {
  const lits = [];
  let x = 1.1;
  for (let i = 0; i < 400; i++) { x = (x * 1.7183 + 0.0137) % 1; lits.push(String(x * 10 ** ((i % 20) - 14))); }
  lits.push('1e-7', '1.5e-7', '0.000001', '4503599627370495.5', '5e-324', '-0', '1e2', '0.99999999999999999999');
  assert.equal(same('canonicalize', { text: '[' + lits.join(',') + ']' }), true);
});

test('python and the reference agree on member order and escapes outside the basic multilingual plane', { skip: SKIP }, () => {
  const keys = ['a', '\u{1F600}', '￿', '\ud800', '', 'z\u{10000}', 'é'];
  const esc = s => '"' + s.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('') + '"';
  assert.equal(same('canonicalize', { text: '{' + keys.map((k, i) => esc(k) + ':' + i).join(',') + '}' }), true);
  assert.equal(same('canonicalize', { text: '"\\ud83d\\ude00\\u007f\\u2028"' }), true);
  assert.equal(same('canonicalize', { text: '"\\ud83d"' }), true);
});

// A signature whose R is the honest R plus a point of order two satisfies the cofactored equation of RFC 8032
// but not the cofactorless one. The specification pins the cofactorless equation; both implementations refuse it.
const COFACTOR_PAYLOAD = JSON.parse('{"artifactDigest":"da5dab956c4662becba293036bea41cab88ba0753f7087a33f6dac6a76fc2425","checkId":"id.binding","evaluatorDigest":"9c88f503c89b76e3e315902c90c53eeae140d9a2d532559033460600cc6fb03c","expiresAt":"2026-10-15T10:00:00.000Z","id":"run-1:id.binding","observedAt":"2026-10-14T10:00:00.000Z","outcome":"pass","profileDigest":"f5b37471b7f39013161bfb78b4b4cff18f662dd147b2ac76957bfc6c0b5ddaed","runId":"run-1","schema":"kya.evidence/v1","scopeId":"scope:vector","source":"runtime","subjectDigest":"b06abb3fd9bbc8eb4b6d6273b8805d65639a0926134acd58767ae71a2679def0"}');
const COFACTOR_PROOF = { algorithm: 'Ed25519', keyId: 'a050837d85070582ccf7394b0988847cc312cb88259b894899f6f239cf1791a5', publicKey: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----\n' };

test('python and the reference refuse a signature that satisfies only the cofactored equation and accept the honest one', { skip: SKIP }, () => {
  const only = { kind: 'evidence', envelope: { payload: COFACTOR_PAYLOAD, proof: { ...COFACTOR_PROOF, signature: 'VJ_8smIVkcQng4eqntEhhv2_i6jDOl0igTY12Xu8viAsdwuabIqWsLiyiwx6t9nr_w5kZBNeXHBr6gW20rShCg' } } };
  const honest = { kind: 'evidence', envelope: { payload: COFACTOR_PAYLOAD, proof: { ...COFACTOR_PROOF, signature: 'Gdt2XT1eX3oXzT1aI-2hXIl9qOya963EbNCJt6CzU-Dj41KsaM6w5E5UT3CxWm7T3Tl9jhSrynrEikPpr8P3BA' } } };
  const [py1, js1] = both('verify-envelope', only);
  assert.equal(JSON.parse(py1.stdout).failure, 'SIGNATURE_INVALID');
  assert.equal(JSON.parse(js1.stdout).failure, 'SIGNATURE_INVALID');
  const [py2, js2] = both('verify-envelope', honest);
  assert.equal(JSON.parse(py2.stdout).valid, true);
  assert.deepEqual(JSON.parse(py2.stdout), JSON.parse(js2.stdout));
});

// Free text for a record that never passed shape and signature validation is implementation specific by design, so the
// reason (and the digest that covers it) is masked before two implementations are compared.
function maskFree(text) {
  const o = JSON.parse(text);
  let masked = false;
  for (const list of [o.rejectedEvidence, o.incidents && o.incidents.ignored]) {
    if (Array.isArray(list)) for (const e of list) if (e.id === null) { e.reason = 'free text'; masked = true; }
  }
  if (masked) { delete o.reportDigest; delete o.resultDigest; }
  return o;
}
const sameMasked = (op, inputs) => {
  const [py, js] = both(op, inputs);
  assert.equal(py.status === 0, js.status === 0, 'python status ' + py.status + ' reference status ' + js.status);
  if (py.status === 0) assert.deepEqual(maskFree(py.stdout), maskFree(js.stdout));
  return py.status === 0;
};
const inputsOf = id => structuredClone(file.vectors.find(v => v.id === id).inputs);

test('python and the reference agree at the freshness boundary of a receipt and on the validity bound of an assessment', { skip: SKIP }, () => {
  const base = inputsOf('assess.qualified-all-pass-runtime');
  const at = Date.parse(base.now);
  const ages = base.evidence.map(e => (at - Date.parse(e.payload.observedAt)) / 1000);
  const oldest = Math.max(...ages);
  assert.ok(Number.isInteger(oldest) && oldest > 2);
  for (const limit of [oldest - 1, oldest, oldest + 1]) {
    const i = structuredClone(base);
    i.policy.maxEvidenceAgeSeconds = limit;
    assert.equal(sameMasked('assess', i), true);
  }
  const aged = structuredClone(base);
  aged.policy.maxAssessmentAgeSeconds = 60;
  assert.equal(sameMasked('assess', aged), true);
  const result = JSON.parse(both('assess', aged)[0].stdout);
  assert.equal(result.validUntil, JSON.parse(both('assess', base)[0].stdout).validUntil);
});

test('python and the reference agree on the evidence bundle digest with entries that are not envelopes and on the entry bounds', { skip: SKIP }, () => {
  const base = inputsOf('assess.qualified-all-pass-runtime');
  for (const junk of [null, 5, 'x', [], {}, { payload: 1, proof: 2 }, [1, [2]], 1.5]) {
    const i = structuredClone(base);
    i.evidence.splice(2, 0, junk);
    assert.equal(sameMasked('assess', i), true);
  }
  const many = structuredClone(base);
  many.evidence = new Array(4097).fill(null);
  assert.equal(sameMasked('assess', many), false);
  const few = structuredClone(base);
  few.evidence = new Array(4096).fill(null);
  assert.equal(sameMasked('assess', few), true);
  const cur = inputsOf('currency.current-and-reliable');
  cur.incidents = new Array(1025).fill(null);
  assert.equal(sameMasked('currency', cur), false);
  cur.incidents = new Array(1024).fill(null);
  assert.equal(sameMasked('currency', cur), true);
});

test('python and the reference agree on incident handling when records are reordered duplicated or moved in time', { skip: SKIP }, () => {
  const withIncidents = file.vectors.filter(v => v.operation === 'currency' && v.inputs && Array.isArray(v.inputs.incidents) && v.inputs.incidents.length > 0 && typeof v.inputs.now === 'string');
  assert.ok(withIncidents.length >= 20);
  for (const v of withIncidents.filter((_, i) => i % 2 === 0)) {
    const rev = structuredClone(v.inputs); rev.incidents.reverse();
    assert.equal(sameMasked('currency', rev), true, v.id + ' reversed');
    const dup = structuredClone(v.inputs); dup.incidents.push(structuredClone(dup.incidents[0]));
    assert.equal(sameMasked('currency', dup), true, v.id + ' duplicated');
    const early = structuredClone(v.inputs); early.now = new Date(Date.parse(early.now) - 86400000).toISOString();
    assert.equal(sameMasked('currency', early), true, v.id + ' earlier');
    const late = structuredClone(v.inputs); late.now = new Date(Date.parse(late.now) + 7 * 86400000).toISOString();
    assert.equal(sameMasked('currency', late), true, v.id + ' later');
  }
});
