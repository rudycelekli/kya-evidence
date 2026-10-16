import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { assess, checkCurrency } from '../src/index.mjs';
import { CLAIM_BOUNDARY_CODES, codesForLimitStrings, describe } from '../src/claim-boundaries/index.mjs';
import { inputs } from './helpers.mjs';
import { literals, arrayBody, scanSentences, sourceFiles, appendOnlyViolations } from './claim-scan.mjs';

const ROOT = new URL('../', import.meta.url);
const ROOT_PATH = fileURLToPath(ROOT);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');
const registry = JSON.parse(read('evidence/claim-boundaries.json'));
const allowlist = JSON.parse(read('evidence/claim-boundary-allowlist.json'));

// Known emitting modules and the array literal that carries their limit text. This list is a second net: the repository-wide
// sentence scan below is the one that cannot miss a new module.
const EMITTERS = [
  ['src/assessment/application/assess.mjs', /limitations\s*:\s*\[/g],
  ['src/assessment/application/currency.mjs', /limits\s*:\s*\[/g],
  ['src/reporting/application/dossier.mjs', /limitations\s*:\s*\[/g],
  ['src/benchmarks/application/runner.mjs', /limitations\s*:\s*\[/g],
  ['src/benchmarks/domain/catalog.mjs', /limitations\s*:\s*\[/g],
  ['src/identity/application/import-declarations.mjs', /limitations\s*:\s*\[/g],
  ['src/identity/application/import-declarations.mjs', /unverified\s*:\s*\[/g],
  ['src/identity/infrastructure/inspect.mjs', /limitations\s*:\s*\[/g],
  ['src/research/application/universe.mjs', /limitations\s*:\s*\[/g],
  ['src/interop-bridges/gate.mjs', /LIMITS\s*=\s*Object\.freeze\(\[/g],
  ['src/interop-bridges/gate.mjs', /NOT_ASSERTED\s*=\s*Object\.freeze\(\[/g],
  ['src/conformance/infrastructure/native-parsers.mjs', /NATIVE_LIMITATIONS\s*=\s*Object\.freeze\(\[/g],
  ['src/conformance/infrastructure/native-adapters.mjs', /limitations\s*:\s*\[/g],
  ['src/conformance/application/runner.mjs', /limitations\s*:\s*\[/g],
];
const CONSTANTS = [
  ['src/interop-bridges/oauth.mjs', /SVID_ASSOCIATION_NOTE\s*=\s*'([^']*)'/],
  ['src/vc-bridge/credential.mjs', /const WARNING\s*=\s*'([^']*)'/],
  ['src/vc-bridge/credential.mjs', /const FIXTURE_LIMITATION\s*=\s*'([^']*)'/],
];

// Sentences only: literals of any quote style with a space. This skips mode keywords inside conditional spreads.
function literalsInArray(text, start) {
  return literals(arrayBody(text, start)).filter((s) => s.includes(' '));
}
function scanEmitters() {
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
const scan = scanSentences(fileURLToPath(ROOT));
/** Sentence-like literals that have neither a claim boundary code nor a reviewed allowlist entry. */
const unreviewed = (sentences, known, allowed) => [...sentences.keys()].filter((s) => !known.has(s) && !allowed.has(s)).sort();

test('every limit string emitted by src is covered by the claim boundary registry', () => {
  const known = registryStrings();
  const missing = [...scanEmitters().keys()].filter((s) => !known.has(s));
  assert.deepEqual(missing, [], 'limit strings without a claim boundary code');
  const unknown = unreviewed(scan.sentences, known, new Set(allowlist.strings));
  assert.deepEqual(unknown, [], 'sentence-like literals under src with neither a claim boundary code nor an allowlist review (add a code to evidence/claim-boundaries.json or review the string into evidence/claim-boundary-allowlist.json)');
});

test('every claim boundary registry string is still present in src', () => {
  const found = scanEmitters();
  const stale = [...registryStrings()].filter((s) => !found.has(s) && !scan.allLiterals.has(s));
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

// Every version of the registry file that git can show: the current commit, the merge base with a main branch, and the recent history of the file.
function gitBaselines() {
  const git = (args) => spawnSync('git', args, { cwd: ROOT_PATH, encoding: 'utf8', timeout: 30_000, maxBuffer: 16_000_000 });
  const inside = git(['rev-parse', '--is-inside-work-tree']);
  if (inside.status !== 0 || inside.stdout.trim() !== 'true') return [];
  const refs = new Set(['HEAD']);
  for (const name of ['origin/main', 'main', 'origin/master', 'master']) {
    const mb = git(['merge-base', 'HEAD', name]);
    if (mb.status === 0 && mb.stdout.trim()) refs.add(mb.stdout.trim());
  }
  const log = git(['log', '-n', '25', '--format=%H', '--', 'evidence/claim-boundaries.json']);
  if (log.status === 0) for (const sha of log.stdout.split('\n').filter(Boolean)) refs.add(sha);
  const out = [];
  for (const ref of refs) {
    const shown = git(['show', `${ref}:./evidence/claim-boundaries.json`]);
    if (shown.status !== 0) continue;
    try { const b = JSON.parse(shown.stdout); out.push({ ref: ref.slice(0, 12), codes: [...new Set([...b.codes.map((c) => c.code), ...b.committedCodes])] }); } catch { /* an unparsable historic version proves nothing */ }
  }
  return out;
}

test('claim boundary codes are append only against the committed list', (t) => {
  const codes = new Set(registry.codes.map((c) => c.code));
  const removed = registry.committedCodes.filter((c) => !codes.has(c));
  assert.deepEqual(removed, [], 'a committed code was removed or renamed');
  assert.equal(new Set(registry.committedCodes).size, registry.committedCodes.length);
  assert.deepEqual(registry.committedCodes, [...registry.committedCodes].sort());
  assert.deepEqual(CLAIM_BOUNDARY_CODES, [...codes].sort());
  // The list inside the file can be edited together with the codes, so compare with what git committed before this change.
  const baselines = gitBaselines();
  if (baselines.length === 0) {
    if (process.env.CI) assert.fail('CI run without a git baseline for evidence/claim-boundaries.json: the append-only check cannot pass silently');
    t.skip('not a git checkout (or the registry is untracked): append-only comparison with the committed baseline did not run');
    return;
  }
  for (const b of baselines) assert.deepEqual(appendOnlyViolations(b.codes, [...codes]), [], `a code present at git ${b.ref} was removed or renamed`);
  const missingFromCommitted = [...codes].filter((c) => !registry.committedCodes.includes(c));
  assert.deepEqual(missingFromCommitted, [], 'every code must be listed in committedCodes');
});

test('append only comparison catches a code renamed in both lists of the registry file', () => {
  const baseline = ['NOT_AUTHORIZATION_GRANT', 'NO_RUNTIME_OBSERVATION'];
  const renamed = { committedCodes: ['NOT_AUTHORIZATION_GRANT', 'NO_RUNTIME_WATCHING'], codes: [{ code: 'NOT_AUTHORIZATION_GRANT' }, { code: 'NO_RUNTIME_WATCHING' }] };
  const codes = new Set(renamed.codes.map((c) => c.code));
  assert.deepEqual(renamed.committedCodes.filter((c) => !codes.has(c)), [], 'the in-file comparison alone passes this rename');
  assert.deepEqual(appendOnlyViolations(baseline, [...codes]), ['NO_RUNTIME_OBSERVATION']);
  assert.deepEqual(appendOnlyViolations(baseline, [...codes, 'NO_RUNTIME_OBSERVATION', 'A_NEW_CODE']), []);
});

test('claim boundary source scan covers every src module and the allowlist is sorted current and disjoint from the registry', () => {
  const files = [...sourceFiles(fileURLToPath(new URL('src', ROOT)))];
  assert.ok(files.length >= 80, 'the scan found only ' + files.length + ' source files');
  const known = registryStrings();
  const strings = allowlist.strings;
  assert.equal(allowlist.schema, 'kya.claim-boundary-allowlist/v1');
  assert.deepEqual(strings, [...strings].sort(), 'allowlist must be sorted');
  assert.equal(new Set(strings).size, strings.length, 'allowlist has duplicates');
  assert.deepEqual(strings.filter((s) => known.has(s)), [], 'a registered limit string must not also be allowlisted');
  assert.deepEqual(strings.filter((s) => !scan.sentences.has(s)), [], 'allowlist entries that no longer exist in src (remove them)');
  assert.ok(scan.sentences.size > 200);
});

test('claim boundary source scan reads every quote style skips comments and regexes and reports a new sentence', () => {
  const sample = [
    "const a = 'It is not a grant of anything'; // 'comment string stays out of the scan'",
    'const b = "Double quoted limit sentence here";',
    'const c = `Template literal sentence without expression`;',
    'const d = `Has ${expr} inside so it is skipped`;',
    "const e = /don't 'quote' me/.test(x) ? 'after regex sentence is read here' : 1;",
    '/* "block comment string stays out" */ const f = a / b / c; const g = "division then string works fine";',
    "const h = ['two', \"strings\", `in one array`];"
  ].join('\n');
  assert.deepEqual(literals(sample), ['It is not a grant of anything', 'Double quoted limit sentence here', 'Template literal sentence without expression', 'after regex sentence is read here', 'division then string works fine', 'two', 'strings', 'in one array']);
  const fake = new Map([['A brand new limit sentence nobody reviewed', new Set(['src/x.mjs'])], ['Listed in the registry already today', new Set(['src/y.mjs'])], ['Reviewed as not a limit statement', new Set(['src/z.mjs'])]]);
  assert.deepEqual(unreviewed(fake, new Set(['Listed in the registry already today']), new Set(['Reviewed as not a limit statement'])), ['A brand new limit sentence nobody reviewed']);
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
