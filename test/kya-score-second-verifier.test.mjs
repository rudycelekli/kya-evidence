import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { verifyScoreCard } from '../src/kya-score/index.mjs';
import { renderVectorFile, VECTOR_FILE } from '../scripts/score-vectors.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const verifier = join(root, 'interop/score-verifier/verify_score_card.py');
const probe = spawnSync('python3', ['--version'], { encoding: 'utf8', timeout: 2000, maxBuffer: 1024, shell: false });
const hasPython = !probe.error && probe.status === 0;
const vectors = JSON.parse(readFileSync(VECTOR_FILE, 'utf8')).vectors;
const pythonEnv = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', LANG: 'C.UTF-8', PYTHONIOENCODING: 'utf-8', PYTHONDONTWRITEBYTECODE: '1' };

function python(file) {
  const result = spawnSync('python3', ['-I', verifier, file], { env: pythonEnv, encoding: 'utf8', timeout: 60000, maxBuffer: 1_048_576, shell: false });
  assert.equal(result.error, undefined, result.error?.message);
  return { status: result.status, value: JSON.parse(result.stdout), stderr: result.stderr };
}

test('score vector file is current and covers valid tamper operator statement and malformed classes', () => {
  assert.equal(readFileSync(VECTOR_FILE, 'utf8'), renderVectorFile());
  const classes = new Set(vectors.map(v => v.class));
  for (const c of ['valid', 'tamper', 'operator-statement', 'malformed']) assert.ok(classes.has(c), c);
  assert.equal(new Set(vectors.map(v => v.id)).size, vectors.length);
  for (const id of ['tamper-headline-score-resealed', 'tamper-outcome-digests-recomputed', 'tamper-manifest-stale-digest', 'tamper-nonclaim-dropped-resealed', 'tamper-nonclaims-reordered-resealed', 'tamper-floor-lowered-resealed', 'tamper-too-few-repeats-resealed', 'tamper-unknown-field-resealed', 'tamper-wrong-schema-resealed', 'valid-all-items-held-out', 'valid-large-resamples']) assert.ok(vectors.some(v => v.id === id), id);
  assert.ok(vectors.filter(v => v.expectValid).length >= 15 && vectors.filter(v => !v.expectValid).length >= 25);
});

test('the javascript verifier agrees with the stated expectation on every shared vector', () => {
  for (const v of vectors) {
    const r = verifyScoreCard(structuredClone(v.card));
    assert.equal(r.valid, v.expectValid, v.id + ': ' + (r.problems ?? []).join(','));
  }
});

test('a re sealed edit of a manifest field that no computation reads is accepted and a re sealed edit of the seed is not', () => {
  const ok = vectors.filter(v => v.class === 'operator-statement');
  assert.ok(ok.length >= 5);
  for (const v of ok) assert.equal(verifyScoreCard(structuredClone(v.card)).valid, true, v.id);
  for (const id of ['tamper-seed-resealed', 'tamper-resamples-resealed', 'tamper-holdout-commitment-removed-resealed']) assert.equal(verifyScoreCard(structuredClone(vectors.find(v => v.id === id).card)).valid, false, id);
});

test('the python verifier agrees with the stated expectation and with the javascript verifier on every shared vector', { skip: !hasPython && 'Python 3 is optional; unavailable on this host, so the second verifier was NOT run' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-score-py-'));
  try {
    for (const v of vectors) {
      const file = join(dir, v.id + '.json');
      writeFileSync(file, JSON.stringify(v.card));
      const py = python(file), js = verifyScoreCard(structuredClone(v.card));
      assert.equal(py.value.valid, v.expectValid, v.id + ': ' + (py.value.problems ?? []).join(','));
      assert.equal(py.status, v.expectValid ? 0 : 1, v.id);
      assert.equal(py.value.valid, js.valid, v.id + ' disagrees with the javascript verifier');
      if (js.valid) { assert.equal(py.value.score, js.score, v.id); assert.equal(py.value.cardDigest, js.cardDigest, v.id); }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the python verifier rejects unreadable input and duplicate members and exits 2 on a usage error', { skip: !hasPython && 'Python 3 is optional; unavailable on this host, so the second verifier was NOT run' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-score-py-'));
  try {
    const dup = join(dir, 'dup.json');
    writeFileSync(dup, '{"schema":"kya.score-card/v1","schema":"kya.score-card/v1"}');
    assert.equal(python(dup).value.valid, false);
    const junk = join(dir, 'junk.json');
    writeFileSync(junk, '{not json');
    assert.equal(python(junk).status, 1);
    const nan = join(dir, 'nan.json');
    writeFileSync(nan, '{"schema":NaN}');
    assert.equal(python(nan).status, 1);
    const usage = spawnSync('python3', ['-I', verifier], { env: pythonEnv, encoding: 'utf8', timeout: 10000, shell: false });
    assert.equal(usage.status, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the python verifier source uses only the standard library with no network process or file writes', () => {
  const text = readFileSync(verifier, 'utf8').replace(/^[^\n]*\n"""[\s\S]*?"""/, '');
  const imports = [...text.matchAll(/^(?:import|from)\s+([a-z_0-9]+)/gm)].map(m => m[1]);
  assert.deepEqual([...new Set(imports)].sort(), ['hashlib', 'json', 'math', 're', 'sys']);
  assert.ok(!/\b(?:socket|subprocess|urllib|http|os\.system|eval|exec|__import__)\b/.test(text));
  assert.ok(!/open\([^)]*["']w/.test(text));
});

test('ADR-0033 states the layout the second verifier needs and the ordering that differs from published sfc32', () => {
  const adr = readFileSync(join(root, 'docs/adr/0033-kya-score-benchmark-profile.md'), 'utf8');
  for (const s of ['### Card layout and algorithms', 'kya.score.seed/v1', 'Twelve outputs are discarded', 'differs from the published sfc32', 'indistinguishable from a card honestly built']) assert.ok(adr.includes(s), s);
  assert.match(adr, /^\*\*Status\*\*: Proposed$/m);
});

test('the benchmarks section tells a reviewer how to reproduce a card and repeats the non claims', () => {
  const doc = readFileSync(join(root, 'docs/BENCHMARKS.md'), 'utf8');
  const section = doc.slice(doc.indexOf('## Reproducing a score card and what it does not show'));
  assert.ok(section.length > 500);
  for (const s of ['kya score verify CARD.json', 'verify_score_card.py', 'kya score build', 'EVIDENCE_FLOOR_NOT_MET', 'score-vectors.mjs --check', 'not independent review', 'NOT_PREDICTIVE_VALIDITY', 'NO_INTER_ASSESSOR_AGREEMENT', 'NOT_SAFETY_CERTIFICATION', 'NOT_ENDORSED_OR_ADOPTED', 'ITEM_SET_MAY_BE_MEMORIZED']) assert.ok(section.includes(s), s);
  assert.match(readFileSync(join(root, 'README.md'), 'utf8'), /docs\/BENCHMARKS\.md#reproducing-a-score-card-and-what-it-does-not-show/);
});

test('the fix lane 10 integration note names only requirement titles and spec headings that exist', () => {
  const note = readFileSync(join(root, 'docs/fixlane10-integration.md'), 'utf8');
  const spec = readFileSync(join(root, 'docs/SPECIFICATION.md'), 'utf8').split('\n');
  const mine = ['kya-score-second-verifier.test.mjs', 'kya-score-wiring.test.mjs'].map(f => readFileSync(join(root, 'test', f), 'utf8')).join('\n');
  const titles = [...note.matchAll(/^- test: `([^`]+)`$/gm)].map(m => m[1]);
  const headings = [...note.matchAll(/^- spec: `(## [^`]+)`$/gm)].map(m => m[1]);
  const ids = [...note.matchAll(/^### (KYA-[A-Z]{3}-\d{3}) /gm)].map(m => m[1]);
  assert.ok(titles.length >= 10 && headings.length >= 5 && ids.length === 5);
  for (const id of ids) assert.match(id, /^KYA-[A-Z]{3}-\d{3}$/);
  for (const t of titles) assert.ok(mine.includes("test('" + t + "'"), 'no such test title: ' + t);
  for (const h of headings) assert.ok(spec.includes(h), 'no such spec heading: ' + h);
});
