import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, mkdir, cp, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BLOCKER_CODES, CURRENCY_CODES } from '../src/index.mjs';
import { validateReport } from '../src/conformance-report/index.mjs';
import { generate } from '../scripts/assessment-vectors.mjs';
import { describeDrift } from '../scripts/lib/vector-drift.mjs';
import { runVectors, firstDifference, splitCommand, LIMITS } from '../scripts/run-vectors.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const VECTORS = join(ROOT, 'evidence/assessment-vectors.json');
const REFERENCE = join(ROOT, 'interop/impl-contract/js-reference.mjs');
const REGISTRY = JSON.parse(await readFile(join(ROOT, 'evidence/requirements.json'), 'utf8'));
const FILE = JSON.parse(await readFile(VECTORS, 'utf8'));
const q = p => `"${p}"`;
const refImpl = `${q(process.execPath)} ${q(REFERENCE)}`;
const run = (impl, extra = {}) => runVectors({ impl, vectorsFile: VECTORS, name: 'test impl', language: 'javascript', timeoutMs: 120000, ...extra });
async function withTmp(f) { const dir = await mkdtemp(join(tmpdir(), 'kya-vec-')); try { return await f(dir); } finally { await rm(dir, { recursive: true, force: true }); } }
async function subsetFile(dir, ids, mutate = v => v) {
  const file = join(dir, 'subset.json');
  await writeFile(file, JSON.stringify({ ...FILE, vectors: FILE.vectors.filter(v => ids.includes(v.id)).map(v => mutate(structuredClone(v))) }));
  return file;
}
async function script(dir, name, body) { const p = join(dir, name); await writeFile(p, body); return `${q(process.execPath)} ${q(p)}`; }

test('assessment vector generator reproduces the committed file byte for byte', async () => {
  const generated = await generate(), committed = await readFile(VECTORS, 'utf8');
  assert.ok(generated === committed, describeDrift(committed, generated));
  assert.equal(FILE.schema, 'kya.assessment-vectors/v2');
});

test('drift description names the first differing vector id, the JSON path and bounded escaped context', () => {
  const doc = JSON.stringify({ schema: 'x', vectors: [{ id: 'one', expected: { n: 1 } }, { id: 'two', expected: { text: 'a'.repeat(500) + 'LINE\nBREAK' } }] }, null, 2) + '\n';
  assert.equal(describeDrift(doc, doc), null);
  const changed = doc.replace('LINE', 'LIN3');
  const msg = describeDrift(doc, changed);
  assert.match(msg, /first differing vector id two;/);
  assert.match(msg, /JSON path \$\.vectors\[1\]\.expected\.text;/);
  assert.match(msg, /committed context "[^"]*LINE/);
  assert.ok(msg.length < 1200, String(msg.length));
  assert.ok(!msg.includes('\n'), 'context must be escaped, never raw newlines');
  assert.match(describeDrift(doc, doc.replace('"schema": "x"', '"schema": "y"')), /vector id none/);
  assert.match(describeDrift(doc, '{not json'), /JSON path unavailable/);
});

test('assessment vector generator check mode succeeds on the committed file', () => {
  const check = spawnSync(process.execPath, [join(ROOT, 'scripts/assessment-vectors.mjs'), '--check'], { encoding: 'utf8', timeout: 240000 });
  assert.equal(check.status, 0, check.stderr);
});

test('assessment vector IDs are unique and the set is large enough to be meaningful', () => {
  const ids = FILE.vectors.map(v => v.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.length >= 60, `only ${ids.length} vectors`);
  assert.ok(FILE.vectors.filter(v => v.operation === 'assess').length >= 40);
  assert.ok(FILE.vectors.filter(v => v.operation === 'currency').length >= 20);
  for (const v of FILE.vectors) assert.ok(['assess', 'currency', 'canonicalize', 'digest', 'verify-envelope', 'compare', 'verify-credential', 'verify-score-card', 'compare-score-cards'].includes(v.operation), v.id);
});

test('every cited requirement ID exists in the registry and every vector states a rationale that names one', () => {
  const known = new Set(REGISTRY.requirements.map(r => r.id));
  for (const v of FILE.vectors) {
    assert.ok(v.requirements.length > 0, v.id);
    for (const r of v.requirements) assert.ok(known.has(r), `${v.id} cites unknown ${r}`);
    assert.ok(typeof v.rationale === 'string' && v.rationale.length > 20, `${v.id} lacks a rationale`);
    assert.ok(v.requirements.some(r => v.rationale.includes(r)), `${v.id} rationale does not name a cited requirement`);
    assert.ok(typeof v.description === 'string' && v.description.length > 10, v.id);
  }
});

test('every blocker code and every currency code appears in a vector or is declared unreachable', () => {
  const declared = new Set(FILE.unreachableBlockerCodes.map(u => u.code));
  for (const code of BLOCKER_CODES) {
    const hit = FILE.vectors.some(v => v.expected.blockerCodes?.includes(code));
    assert.ok(hit || declared.has(code), `blocker code ${code} is not exercised`);
    if (declared.has(code)) assert.ok(!hit, `${code} is declared unreachable yet a vector emits it`);
  }
  assert.deepEqual([...declared], ['NO_OBSERVED_CHECKS']);
  for (const code of Object.values(CURRENCY_CODES)) assert.ok(FILE.vectors.some(v => v.expected.triggers?.some(t => t.code === code)), `currency code ${code} is not exercised`);
});

test('vectors cover the named scenario families', () => {
  const ids = FILE.vectors.map(v => v.id).join('\n');
  for (const family of ['incident-open', 'incident-resolved', 'appeal', 'ambiguous-report', 'untrusted', 'identical-envelope', 'future', 'minimum-pass-met', 'minimum-failed', 'minimum-omitted', 'minimum-independent-pass', 'principal-required-unbound', 'revoked-key', 'revoked-evidence', 'subject-revoked', 'expired', 'tied-latest-runs', 'cherry-picking', 'duplicate-eligible', 'declaration-laundering', 'fixture-', 'capture-issuer', 'critical-failure', 'empty-evidence', 'refuse-']) assert.ok(ids.includes(family), `no vector for ${family}`);
  const refusals = FILE.vectors.filter(v => v.expected.refused === true);
  assert.ok(refusals.length >= 8);
  assert.ok(FILE.vectors.every(v => v.operation !== 'assess' || v.expected.refused === true || Array.isArray(v.expected.blockerCodes)));
  assert.ok(FILE.keys.self.seedHex.length === 64 && Object.values(FILE.keys).every(k => !/PRIVATE/.test(JSON.stringify(k))), 'keys publish seeds and public parts only');
});

test('the JS reference passes every vector through the harness CLI and the report is valid', async () => {
  await withTmp(async dir => {
    const out = join(dir, 'report.json');
    const p = spawnSync(process.execPath, [join(ROOT, 'scripts/run-vectors.mjs'), '--impl', refImpl, '--name', 'kya-js-reference', '--language', 'javascript', '--timeout-ms', '120000', '--out', out], { encoding: 'utf8', timeout: 300000 });
    assert.equal(p.status, 0, p.stdout + p.stderr);
    const summary = JSON.parse(p.stdout);
    assert.equal(summary.vectors.total, FILE.vectors.length);
    assert.equal(summary.vectors.pass, FILE.vectors.length);
    assert.equal(summary.vectors.fail, 0);
    const report = validateReport(JSON.parse(await readFile(out, 'utf8')), { registry: REGISTRY });
    const cited = new Set(FILE.vectors.flatMap(v => v.requirements));
    for (const r of report.results) {
      if (cited.has(r.id)) { assert.equal(r.result, 'pass', r.id); assert.equal(r.evidence, 'portable-vector'); assert.ok(r.executed.every(id => FILE.vectors.some(v => v.id === id))); }
      else { assert.equal(r.result, 'not-run', r.id); assert.deepEqual(r.executed, []); }
    }
    assert.equal(report.summary.pass, cited.size);
  });
});

test('a deliberately weakened implementation fails specific vectors and never appears as pass', async () => {
  await withTmp(async dir => {
    await cp(join(ROOT, 'src'), join(dir, 'src'), { recursive: true });
    await mkdir(join(dir, 'interop/impl-contract'), { recursive: true });
    await cp(REFERENCE, join(dir, 'interop/impl-contract/js-reference.mjs'));
    const assessPath = join(dir, 'src/assessment/application/assess.mjs'), original = await readFile(assessPath, 'utf8');
    const mutants = [
      { name: 'capture-issuer gate removed', from: "insist(k.role !== 'capture-issuer','A capture-issuer key cannot issue scoring evidence');", to: '', vector: 'assess.capture-issuer-signer-rejected', requirement: 'KYA-TRU-001' },
      { name: 'declaration gate removed', from: "insist(p.source !== 'declaration','A declaration cannot satisfy an observed check');", to: '', vector: 'assess.declaration-laundering-rejected', requirement: 'KYA-TRU-003' },
      { name: 'mandatory minimums ignored', from: "if (decision!=='revoked' && decision!=='expired') {", to: 'if (false) {', vector: 'assess.minimum-failed-check-caps-decision', requirement: 'KYA-MIN-002' },
      { name: 'ambiguous runs allowed to qualify', from: 'else if (ambiguousRuns || selectedRunConflict', to: 'else if (selectedRunConflict', vector: 'assess.tied-latest-runs-ambiguous', requirement: 'KYA-RUN-002' },
      { name: 'critical failure no longer blocks', from: 'else if (criticalFailures.length) {', to: 'else if (false) {', vector: 'assess.critical-failure', requirement: 'KYA-SCO-002' }
    ];
    const jsRef = join(dir, 'interop/impl-contract/js-reference.mjs');
    for (const m of mutants) {
      assert.equal(original.split(m.from).length - 1, 1, `mutation anchor for ${m.name} must match exactly once`);
      await writeFile(assessPath, original.replace(m.from, m.to));
      const { report, summary, outcomes } = await run(`${q(process.execPath)} ${q(jsRef)}`, { name: m.name });
      const failed = outcomes.filter(o => o.status === 'fail').map(o => o.id);
      assert.ok(failed.includes(m.vector), `${m.name}: expected ${m.vector} to fail, failed: ${failed.join(', ')}`);
      assert.ok(summary.vectors.fail >= 1 && summary.vectors.pass < FILE.vectors.length, m.name);
      const entry = report.results.find(r => r.id === m.requirement);
      assert.equal(entry.result, 'fail', `${m.name}: ${m.requirement} must be fail, not ${entry.result}`);
      assert.ok(report.summary.fail >= 1 && report.summary.pass < 32, m.name);
      for (const f of summary.failures) assert.match(f.detail, /^\$|exit|expected/, m.name);
    }
  });
});

test('tampering an expected value is detected and the first differing path is reported', async () => {
  await withTmp(async dir => {
    const id = 'assess.critical-failure';
    const decisionFile = await subsetFile(dir, [id], v => { v.expected.decision = 'qualified'; return v; });
    let r = await run(refImpl, { vectorsFile: decisionFile });
    assert.equal(r.summary.vectors.fail, 1);
    assert.match(r.summary.failures[0].detail, /^\$\.decision: expected "qualified", got "blocked"/);
    const scoreFile = await subsetFile(dir, [id], v => { v.expected.score.earned += 1; return v; });
    r = await run(refImpl, { vectorsFile: scoreFile });
    assert.match(r.summary.failures[0].detail, /^\$\.score\.earned/);
    const digestFile = await subsetFile(dir, [id], v => { v.expected.reportDigest = 'a'.repeat(64); return v; });
    r = await run(refImpl, { vectorsFile: digestFile });
    assert.match(r.summary.failures[0].detail, /^\$\.reportDigest/);
    const currencyFile = await subsetFile(dir, ['currency.incident-open-high'], v => { v.expected.incidents.open = []; return v; });
    r = await run(refImpl, { vectorsFile: currencyFile });
    assert.match(r.summary.failures[0].detail, /^\$\.incidents\.open/);
    const reasonFile = await subsetFile(dir, ['assess.tampered-evidence-payload'], v => { v.expected.rejectedEvidence[0].reasonContains = 'no such text'; return v; });
    r = await run(refImpl, { vectorsFile: reasonFile });
    assert.match(r.summary.failures[0].detail, /\.rejectedEvidence\[0\]\.reason: expected text containing/);
    assert.equal(r.report.results.find(x => x.id === 'KYA-TRU-002').result, 'fail');
  });
});

test('the harness refuses oversize output, non-JSON output, a crash and a hang without recording a pass', async () => {
  await withTmp(async dir => {
    const file = await subsetFile(dir, ['assess.qualified-all-pass-runtime', 'currency.current-and-reliable']);
    const cases = [
      ['oversize', `process.stdout.write('x'.repeat(${LIMITS.outputBytes + 10}))`, /output exceeds/],
      ['nonjson', "process.stdout.write('this is not json')", /not one strict JSON value/],
      ['array', "process.stdout.write('[1,2]')", /not a JSON object/],
      ['duplicate-members', `process.stdout.write('{"schema":"kya.impl-result/v1","schema":"x"}')`, /strict JSON/],
      ['crash', "throw new Error('boom')", /exit 1/],
      ['exit-code', 'process.exit(5)', /exit 5/],
      ['hang', 'setInterval(()=>{},1000)', /timeout/]
    ];
    for (const [name, body, pattern] of cases) {
      const impl = await script(dir, `${name}.mjs`, 'for await (const _ of process.stdin) {}\n' + body + '\n');
      const r = await run(impl, { vectorsFile: file, timeoutMs: 1500 });
      assert.equal(r.summary.vectors.pass, 0, name);
      assert.equal(r.summary.vectors.fail, 2, name);
      assert.match(r.summary.failures[0].detail, pattern, name);
      assert.equal(r.report.summary.pass, 0, name);
    }
    const missing = await run(q(join(dir, 'does-not-exist')), { vectorsFile: file });
    assert.equal(missing.summary.vectors.fail, 2);
    assert.match(missing.summary.failures[0].detail, /cannot start/);
  });
});

test('an extra field, a missing field and a wrong schema in the result are all failures', async () => {
  await withTmp(async dir => {
    const file = await subsetFile(dir, ['assess.qualified-all-pass-runtime']);
    const wrap = body => script(dir, `wrap-${Math.random().toString(36).slice(2)}.mjs`, `import { spawnSync } from 'node:child_process';\nimport { readFileSync } from 'node:fs';\nconst r = spawnSync(process.execPath, [${JSON.stringify(REFERENCE)}], { input: readFileSync(0), encoding: 'utf8' });\nconst o = JSON.parse(r.stdout);\n${body}\nprocess.stdout.write(JSON.stringify(o));\n`);
    const extra = await run(await wrap("o.bonus = 1;"), { vectorsFile: file });
    assert.match(extra.summary.failures[0].detail, /^\$\.bonus: unexpected field/);
    const missing = await run(await wrap("delete o.coverage;"), { vectorsFile: file });
    assert.match(missing.summary.failures[0].detail, /^\$\.coverage: missing/);
    const schema = await run(await wrap("o.schema = 'other';"), { vectorsFile: file });
    assert.match(schema.summary.failures[0].detail, /^\$\.schema/);
    const decision = await run(await wrap("o.decision = 'qualified'; o.score.earned = 999;"), { vectorsFile: file });
    assert.match(decision.summary.failures[0].detail, /^\$\.score\.earned/);
  });
});

test('a refusal vector fails when the implementation answers with output and exit code zero', async () => {
  await withTmp(async dir => {
    const file = await subsetFile(dir, ['assess.refuse-policy-binds-other-profile', 'currency.refuse-tampered-assessment']);
    const lax = await script(dir, 'lax.mjs', "for await (const _ of process.stdin) {}\nprocess.stdout.write(JSON.stringify({schema:'kya.impl-result/v1',decision:'qualified'}));\n");
    const r = await run(lax, { vectorsFile: file });
    assert.equal(r.summary.vectors.fail, 2);
    assert.match(r.summary.failures[0].detail, /expected a refusal/);
    assert.equal(r.report.results.find(x => x.id === 'KYA-BND-001').result, 'fail');
    const good = await run(refImpl, { vectorsFile: file });
    assert.equal(good.summary.vectors.pass, 2);
  });
});

test('unsupported operations are not-run and never pass', async () => {
  await withTmp(async dir => {
    // The reply echoes the operation, so a refusal vector of a version 2 operation is also not-run (interop/impl-contract/README.md, Unsupported).
    const none = await script(dir, 'none.mjs', "let s = '';\nfor await (const c of process.stdin) s += c;\nprocess.stdout.write(JSON.stringify({schema:'kya.impl-result/v1',operation:JSON.parse(s).operation,unsupported:true}));\n");
    const r = await run(none);
    const v1 = v => ['assess', 'currency'].includes(v.operation);
    // A raw input that is not even JSON crashes this stub's own JSON.parse, which any implementation does for it, so such a vector counts as refused.
    const notJson = v => typeof v.rawInput === 'string' && (() => { try { JSON.parse(v.rawInput); return false; } catch { return true; } })();
    assert.equal(r.summary.vectors.unsupported, FILE.vectors.filter(v => (!v.expected.refused || !v1(v)) && !notJson(v)).length);
    // A version 1 refusal vector still fails when the implementation answers unsupported with exit 0 (a few raw inputs crash this stub's own JSON.parse and so count as refused).
    const v1Refusals = FILE.vectors.filter(v => v.expected.refused && v1(v)).length;
    assert.ok(r.summary.vectors.fail > 0 && r.summary.vectors.fail <= v1Refusals, String(r.summary.vectors.fail));
    assert.equal(r.summary.vectors.fail + r.summary.vectors.unsupported + r.summary.vectors.pass, FILE.vectors.length);
    assert.equal(r.report.summary.pass, 0);
    assert.ok(r.report.results.every(x => x.result !== 'pass'));
    // A refusal vector is satisfied by any non-zero exit, so a requirement that cites only refusals could pass; that is stated in the guide.
    const partial = await script(dir, 'partial.mjs', `import { spawnSync } from 'node:child_process';\nimport { readFileSync } from 'node:fs';\nconst input = readFileSync(0);\nif (JSON.parse(input).operation === 'currency') { process.stdout.write(JSON.stringify({schema:'kya.impl-result/v1',operation:'currency',unsupported:true})); process.exit(0); }\nconst r = spawnSync(process.execPath, [${JSON.stringify(REFERENCE)}], { input, encoding: 'utf8' });\nprocess.stdout.write(r.stdout); process.exit(r.status);\n`);
    const p = await run(partial);
    const byId = Object.fromEntries(p.report.results.map(x => [x.id, x.result]));
    assert.equal(byId['KYA-SCO-001'], 'pass');
    assert.equal(byId['KYA-MON-001'], 'not-run');
    assert.equal(byId['KYA-INC-004'], 'not-run');
  });
});

test('a requirement passes only if every vector citing it passes', async () => {
  await withTmp(async dir => {
    const flaky = await script(dir, 'flaky.mjs', `import { spawnSync } from 'node:child_process';\nimport { readFileSync } from 'node:fs';\nconst input = readFileSync(0);\nconst parsed = JSON.parse(input);\nconst r = spawnSync(process.execPath, [${JSON.stringify(REFERENCE)}], { input, encoding: 'utf8' });\nif (parsed.operation === 'currency') { const o = JSON.parse(r.stdout); o.reliable = !o.reliable; process.stdout.write(JSON.stringify(o)); } else process.stdout.write(r.stdout);\nprocess.exit(r.status);\n`);
    const { report, summary } = await run(flaky);
    const byId = Object.fromEntries(report.results.map(x => [x.id, x.result]));
    assert.equal(byId['KYA-MON-001'], 'fail');
    assert.equal(byId['KYA-INC-004'], 'fail');
    assert.equal(byId['KYA-SCO-001'], 'pass');
    assert.ok(summary.vectors.fail >= 20 && summary.vectors.pass >= 60);
  });
});

test('semantic-only mode ignores digests but can never record a requirement as pass', async () => {
  await withTmp(async dir => {
    const file = await subsetFile(dir, ['assess.qualified-all-pass-runtime']);
    const nodigest = await script(dir, 'nodigest.mjs', `import { spawnSync } from 'node:child_process';\nimport { readFileSync } from 'node:fs';\nconst r = spawnSync(process.execPath, [${JSON.stringify(REFERENCE)}], { input: readFileSync(0), encoding: 'utf8' });\nconst o = JSON.parse(r.stdout); o.reportDigest = 'f'.repeat(64); process.stdout.write(JSON.stringify(o));\n`);
    const strict = await run(nodigest, { vectorsFile: file });
    assert.match(strict.summary.failures[0].detail, /^\$\.reportDigest/);
    const loose = await run(nodigest, { vectorsFile: file, semanticOnly: true });
    assert.equal(loose.summary.vectors.fail, 0);
    assert.equal(loose.summary.vectors.semanticPass, 1);
    assert.equal(loose.report.summary.pass, 0);
  });
});

test('firstDifference and splitCommand behave exactly as the contract states', () => {
  assert.equal(firstDifference({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] }), null);
  assert.equal(firstDifference({ a: [1, { b: 2 }] }, { a: [1, { b: 3 }] }), '$.a[1].b: expected 2, got 3');
  assert.equal(firstDifference({ a: 1 }, { a: 1, b: 2 }), '$.b: unexpected field');
  assert.equal(firstDifference({ a: 1, b: 2 }, { a: 1 }), '$.b: missing');
  assert.equal(firstDifference([1, 2], [1]), '$: expected 2 items, got 1');
  assert.equal(firstDifference({ index: 0, reasonContains: 'sig' }, { index: 0, reason: 'Bad SIGnature' }), null);
  assert.match(firstDifference({ index: 0, reasonContains: 'sig' }, { index: 0, reason: 'other' }), /reason: expected text containing/);
  assert.equal(firstDifference({ x: null }, { x: 0 }), '$.x: expected null, got 0');
  assert.deepEqual(splitCommand('node "a b/c.mjs" --flag \'x y\''), ['node', 'a b/c.mjs', '--flag', 'x y']);
  assert.throws(() => splitCommand('node "unterminated'));
  assert.throws(() => splitCommand('   '));
});

test('the harness rejects a vectors file with an unknown requirement or a duplicate vector ID', async () => {
  await withTmp(async dir => {
    const bad = join(dir, 'bad.json');
    await writeFile(bad, JSON.stringify({ ...FILE, vectors: [{ ...FILE.vectors[0], requirements: ['KYA-ZZZ-999'] }] }));
    await assert.rejects(run(refImpl, { vectorsFile: bad }), /not in the registry/);
    await writeFile(bad, JSON.stringify({ ...FILE, vectors: [FILE.vectors[0], FILE.vectors[0]] }));
    await assert.rejects(run(refImpl, { vectorsFile: bad }), /Duplicate/);
    await writeFile(bad, JSON.stringify({ schema: 'other', vectors: [] }));
    await assert.rejects(run(refImpl, { vectorsFile: bad }), /Not a kya.assessment-vectors/);
  });
});

test('the JS reference adapter refuses malformed input with a non-zero exit and no output', () => {
  for (const input of ['', 'not json', '{"schema":"other"}', '{"schema":"kya.impl-input/v1","operation":"assess","inputs":{}}']) {
    const p = spawnSync(process.execPath, [REFERENCE], { input, encoding: 'utf8' });
    assert.notEqual(p.status, 0, input);
    assert.equal(p.stdout, '', input);
  }
  const unsupported = spawnSync(process.execPath, [REFERENCE], { input: '{"schema":"kya.impl-input/v1","operation":"verify","inputs":{}}', encoding: 'utf8' });
  assert.equal(unsupported.status, 0);
  assert.equal(JSON.parse(unsupported.stdout).unsupported, true);
});

test('vectors that restate the same input in another spelling expect exactly the same result and the spelling really differs', () => {
  const byId = id => FILE.vectors.find(v => v.id === id);
  const base = byId('assess.qualified-all-pass-runtime');
  const flipped = byId('assess.canonical-member-order-does-not-matter');
  assert.deepEqual(flipped.expected, base.expected);
  assert.notEqual(JSON.stringify(flipped.inputs), JSON.stringify(base.inputs));
  assert.deepEqual(Object.keys(flipped.inputs.manifest), Object.keys(base.inputs.manifest).reverse());
  const numbers = byId('assess.raw-number-spellings-equal-by-value-are-accepted');
  assert.deepEqual(numbers.expected, base.expected);
  for (const spelling of ['"minScore":7e2', '"minCoverage":8E-1', '"maxEvidenceAgeSeconds":86400.0', '"minIndependentCoverage":0.0']) assert.ok(numbers.rawInput.includes(spelling), spelling);
  const unicode = byId('assess.canonical-unicode-and-escapes-preserved');
  const escaped = byId('assess.raw-pretty-printed-input-with-escaped-text-is-accepted');
  assert.deepEqual(escaped.expected, unicode.expected);
  assert.ok(escaped.rawInput.includes('\\u00e9') && escaped.rawInput.includes('\\ud83e\\udded') && !/[^\x00-\x7f]/.test(escaped.rawInput));
  assert.ok(escaped.rawInput.includes('\n  '), 'the escaped input is indented');
  assert.equal(escaped.inputs, undefined);
  for (const v of FILE.vectors.filter(x => x.rawInput !== undefined)) assert.equal(v.inputs, undefined, v.id);
});

test('an empty reasonContains accepts any non-empty reason text and refuses a missing or empty reason', () => {
  assert.equal(firstDifference({ index: 0, reasonContains: '' }, { index: 0, reason: 'any text at all' }), null);
  assert.match(firstDifference({ index: 0, reasonContains: '' }, { index: 0, reason: '' }), /reason: expected a non-empty reason/);
  assert.match(firstDifference({ index: 0, reasonContains: '' }, { index: 0 }), /reason: expected a non-empty reason/);
  assert.match(firstDifference({ index: 0, reasonContains: '' }, { index: 0, reason: 7 }), /reason: expected a non-empty reason/);
});

test('a vector with rawInput sends exactly that text on stdin and a vector needs exactly one of inputs and rawInput', async () => {
  await withTmp(async dir => {
    const RAW = '{"schema":"kya.impl-input/v1","operation":"assess","inputs":{"a":1,"a":2}}';
    const base = FILE.vectors.find(v => v.expected.refused === true);
    const { inputs, ...rest } = structuredClone(base);
    const file = join(dir, 'raw.json');
    await writeFile(file, JSON.stringify({ ...FILE, vectors: [{ ...rest, rawInput: RAW }] }));
    const refuseIfExact = await script(dir, 'exact.mjs', 'let s = "";\nfor await (const c of process.stdin) s += c;\nprocess.exit(s === ' + JSON.stringify(RAW) + ' ? 3 : 0);\n');
    const r = await run(refuseIfExact, { vectorsFile: file });
    assert.equal(r.summary.vectors.pass, 1, JSON.stringify(r.summary.failures));
    const answers = await script(dir, 'ok.mjs', 'for await (const _ of process.stdin) {}\nprocess.stdout.write("{}");\n');
    const bad = await run(answers, { vectorsFile: file });
    assert.equal(bad.summary.vectors.fail, 1);
    await writeFile(file, JSON.stringify({ ...FILE, vectors: [{ ...rest, rawInput: RAW, inputs }] }));
    await assert.rejects(run(refuseIfExact, { vectorsFile: file }), /exactly one of inputs and rawInput/);
    await writeFile(file, JSON.stringify({ ...FILE, vectors: [rest] }));
    await assert.rejects(run(refuseIfExact, { vectorsFile: file }), /exactly one of inputs and rawInput/);
  });
});
