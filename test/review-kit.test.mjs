import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkKit, computeActuals, parseNumbers, KIT_FILES } from '../scripts/review-kit-check.mjs';

// The review and pilot kits quote numbers and name commands and files. These tests prove the checker fails when any of
// them drifts. They do not judge whether the prose of the kits is good.
const root = fileURLToPath(new URL('../', import.meta.url));
const REVIEW = KIT_FILES[0], PILOT = KIT_FILES[1], INVITE = KIT_FILES[2];
const doc = p => readFileSync(root + p, 'utf8');
const actuals = await computeActuals(root);

test('the review kit checker passes on this checkout', async () => {
  const r = await checkKit({ root, actuals });
  assert.deepEqual(r.problems, []);
  assert.equal(r.ok, true);
  assert.ok(r.checked.length >= 8);
  assert.ok(r.notChecked.some(s => s.includes('quality')), 'the checker must say what it does not check');
});

test('the quoted number table has a row for every number the checker recomputes for the review', () => {
  const rows = parseNumbers(doc(REVIEW));
  const keys = new Set(rows.map(r => r.key));
  for (const k of ['requirements', 'requirementsRegistryDigest', 'vectorsTotal', 'vectors.assess', 'vectors.currency', 'vectors.canonicalize', 'vectors.digest', 'vectors.verify-envelope', 'vectors.compare', 'mutationControls', 'testFiles', 'testDeclarations', 'adrs', 'coreProfileChecks', 'srcFiles', 'srcLines', 'evaluatorDigestPinned']) {
    assert.ok(keys.has(k), 'table lacks ' + k);
  }
});

test('a drifted requirement count fails the review kit check', async () => {
  const bad = doc(REVIEW).replace(/(\| `requirements` \| `)\d+(`)/, '$1' + (actuals.requirements + 1) + '$2');
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('quoted number requirements')), r.problems.join('; '));
});

test('a drifted vector count fails the review kit check', async () => {
  const bad = doc(REVIEW).replace(/(\| `vectorsTotal` \| `)\d+(`)/, '$1' + (actuals.vectorsTotal - 1) + '$2');
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('vectorsTotal')));
});

test('a drifted mutation control count fails the review kit check', async () => {
  const bad = doc(REVIEW).replace(/(\| `mutationControls` \| `)\d+(`)/, '$1' + (actuals.mutationControls + 3) + '$2');
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('mutationControls')));
});

test('a drifted evaluator digest in the kit fails the review kit check', async () => {
  const flipped = (actuals.evaluatorDigestPinned[0] === '0' ? '1' : '0') + actuals.evaluatorDigestPinned.slice(1);
  const bad = doc(REVIEW).split(actuals.evaluatorDigestPinned).join(flipped);
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('evaluatorDigestPinned')));
});

test('a pinned evaluator digest that differs from the computed digest fails the check', async () => {
  const r = await checkKit({ root, actuals: { ...actuals, evaluatorDigestPinned: '0'.repeat(64) } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('differs from the computed')));
});

test('a quoted number the checker cannot recompute fails the review kit check', async () => {
  const bad = doc(REVIEW).replace('| `adrs` |', '| `invented.number` | `7` | nothing |\n| `adrs` |');
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('invented.number')));
});

test('a reference to a file that does not exist fails the review kit check', async () => {
  const bad = doc(REVIEW) + '\nSee `docs/review/NO-SUCH-FILE.md` for more.\n';
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('NO-SUCH-FILE')));
});

test('a command that names a missing script or npm script fails the pilot kit check', async () => {
  const bad = doc(PILOT) + '\nRun `node scripts/no-such-script.mjs` then `npm run no-such-npm-script`.\n';
  const r = await checkKit({ root, actuals, text: { [PILOT]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('no-such-script')));
  assert.ok(r.problems.some(p => p.includes('no-such-npm-script')));
});

test('a command that names an unknown kya subcommand fails the invitation check', async () => {
  const bad = doc(INVITE) + '\nRun `node bin/kya.mjs frobnicate`.\n';
  const r = await checkKit({ root, actuals, text: { [INVITE]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('frobnicate')));
});

test('removing the statement that no outside review exists fails the check', async () => {
  const bad = doc(REVIEW).split('There is no outside security review today').join('A review is under way');
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('no outside security review')));
});

test('removing the owner approval rule from the pilot kit fails the check', async () => {
  const bad = doc(PILOT).split('without the written approval of the pilot owner').join('whenever convenient');
  const r = await checkKit({ root, actuals, text: { [PILOT]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('written approval')));
});

test('a frozen commit that is not in this history fails the check', async () => {
  const bad = doc(REVIEW).replace(/Frozen commit to review: `[0-9a-f]+`/, 'Frozen commit to review: `0000000`');
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  const gitKnows = r.notChecked.some(s => s.includes('frozen commit ancestry'));
  assert.ok(gitKnows || r.problems.some(p => p.includes('frozen commit')));
});

test('an unmodified override passes and a non ASCII byte fails the check', async () => {
  const same = await checkKit({ root, actuals, text: { [INVITE]: doc(INVITE) } });
  assert.equal(same.ok, true);
  const bad = await checkKit({ root, actuals, text: { [INVITE]: doc(INVITE) + '\ncafé\n' } });
  assert.equal(bad.ok, false);
  assert.ok(bad.problems.some(p => p.includes('not plain ASCII')));
});

test('the checker command line prints usage and rejects an unknown argument', () => {
  const ok = spawnSync(process.execPath, ['scripts/review-kit-check.mjs', '--help'], { cwd: root, encoding: 'utf8' });
  assert.equal(ok.status, 0);
  assert.ok(ok.stdout.includes('usage'));
  const bad = spawnSync(process.execPath, ['scripts/review-kit-check.mjs', '--bogus'], { cwd: root, encoding: 'utf8' });
  assert.equal(bad.status, 2);
});
