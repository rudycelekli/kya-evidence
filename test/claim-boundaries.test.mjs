import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assess, checkCurrency } from '../src/index.mjs';
import { CLAIM_BOUNDARY_CODES, codesForLimitStrings, describe } from '../src/claim-boundaries/index.mjs';
import { inputs } from './helpers.mjs';

const ROOT = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');
const registry = JSON.parse(read('evidence/claim-boundaries.json'));

// Known emitting modules and the array literal that carries their limit text.
const EMITTERS = [
  ['src/assessment/application/assess.mjs', /limitations\s*:\s*\[/g],
  ['src/assessment/application/currency.mjs', /limits\s*:\s*\[/g],
  ['src/reporting/application/dossier.mjs', /limitations\s*:\s*\[/g],
  ['src/benchmarks/application/runner.mjs', /limitations\s*:\s*\[/g],
  ['src/benchmarks/domain/catalog.mjs', /limitations\s*:\s*\[/g],
  ['src/identity/application/import-declarations.mjs', /limitations\s*:\s*\[/g],
  ['src/identity/infrastructure/inspect.mjs', /limitations\s*:\s*\[/g],
  ['src/research/application/universe.mjs', /limitations\s*:\s*\[/g],
  ['src/interop-bridges/gate.mjs', /LIMITS\s*=\s*Object\.freeze\(\[/g],
];
const CONSTANTS = [
  ['src/interop-bridges/oauth.mjs', /SVID_ASSOCIATION_NOTE\s*=\s*'([^']*)'/],
  ['src/vc-bridge/credential.mjs', /const WARNING\s*=\s*'([^']*)'/],
  ['src/vc-bridge/credential.mjs', /const FIXTURE_LIMITATION\s*=\s*'([^']*)'/],
];

// Sentences only: single-quoted literals with a space. This skips mode keywords inside conditional spreads.
function literalsInArray(text, start) {
  let i = start, depth = 1;
  const out = [];
  while (depth > 0) {
    const c = text[i];
    if (c === "'") {
      let j = i + 1, s = '';
      while (text[j] !== "'") { if (text[j] === '\\') j++; s += text[j]; j++; }
      if (s.includes(' ')) out.push(s);
      i = j;
    } else if (c === '[') depth++;
    else if (c === ']') depth--;
    i++;
  }
  return out;
}
function scanSource() {
  const found = new Map();
  const add = (s, file) => { if (!found.has(s)) found.set(s, new Set()); found.get(s).add(file); };
  for (const [file, re] of EMITTERS) {
    const text = read(file);
    const hits = [...text.matchAll(re)];
    assert.ok(hits.length > 0, file + ' no longer has the expected limit array');
    for (const m of hits) for (const s of literalsInArray(text, m.index + m[0].length)) add(s, file);
  }
  for (const [file, re] of CONSTANTS) {
    const m = read(file).match(re);
    assert.ok(m, file + ' no longer has the expected limit constant');
    add(m[1], file);
  }
  return found;
}
// The benchmark verifier recomputes its limitation list inline; those literals must stay equal to the emitted ones.
const registryStrings = () => new Set(registry.codes.flatMap((c) => c.strings));

test('every limit string emitted by src is covered by the claim boundary registry', () => {
  const known = registryStrings();
  const missing = [...scanSource().keys()].filter((s) => !known.has(s));
  assert.deepEqual(missing, [], 'limit strings without a claim boundary code');
});

test('every claim boundary registry string is still present in src', () => {
  const found = scanSource();
  const stale = [...registryStrings()].filter((s) => !found.has(s));
  assert.deepEqual(stale, [], 'registry strings no longer emitted by src');
});

test('benchmark verifier inline limitation list matches the emitted list', () => {
  const text = read('src/benchmarks/application/runner.mjs');
  const m = text.match(/canonical\(run\.limitations\)\s*===\s*canonical\(\[/);
  assert.ok(m, 'verifier comparison not found');
  const inline = literalsInArray(text, m.index + m[0].length);
  const emitted = literalsInArray(text, [...text.matchAll(/limitations\s*:\s*\[/g)][0].index + 'limitations: ['.length);
  assert.deepEqual(inline, emitted);
});

test('claim boundary codes are unique and upper snake case', () => {
  const codes = registry.codes.map((c) => c.code);
  assert.equal(new Set(codes).size, codes.length);
  for (const c of codes) assert.match(c, /^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$/);
  for (const c of registry.codes) {
    assert.ok(c.meaning.length > 0 && c.artifactKinds.length > 0 && c.strings.length > 0, c.code + ' is incomplete');
    assert.deepEqual(c.strings, [...c.strings].sort());
  }
});

test('claim boundary codes are append only against the committed list', () => {
  const codes = new Set(registry.codes.map((c) => c.code));
  const removed = registry.committedCodes.filter((c) => !codes.has(c));
  assert.deepEqual(removed, [], 'a committed code was removed or renamed');
  assert.equal(new Set(registry.committedCodes).size, registry.committedCodes.length);
  assert.deepEqual(registry.committedCodes, [...registry.committedCodes].sort());
  assert.deepEqual(CLAIM_BOUNDARY_CODES, [...codes].sort());
});

test('codesForLimitStrings covers the real assess and checkCurrency outputs', () => {
  const i = inputs();
  const report = assess(i);
  const currency = checkCurrency(report, { manifest: i.manifest, policy: i.policy, now: '2026-10-13T12:10:00.000Z' });
  assert.equal(report.evidenceMode, 'fixture');
  assert.ok(report.limitations.length > 3 && currency.limits.length > 0);
  const codes = codesForLimitStrings([...report.limitations, ...currency.limits]);
  assert.deepEqual(codes, [...new Set(codes)].sort());
  for (const c of codes) assert.equal(describe(c).code, c);
  for (const c of ['NOT_AUTHORIZATION_GRANT', 'SYNTHETIC_FIXTURE_EVIDENCE', 'NO_RUNTIME_OBSERVATION', 'OMITTED_INCIDENT_UNDETECTABLE']) assert.ok(codes.includes(c), c);
  const none = assess({ ...i, evidence: [] });
  assert.ok(codesForLimitStrings(none.limitations).length > 0);
});

test('codesForLimitStrings throws on an unknown string and describe throws on an unknown code', () => {
  assert.throws(() => codesForLimitStrings(['A limit nobody registered']), /Unknown claim boundary string/);
  assert.throws(() => codesForLimitStrings('not an array'), TypeError);
  assert.throws(() => describe('NOT_A_CODE'), /Unknown claim boundary code/);
  assert.deepEqual(codesForLimitStrings([]), []);
});
