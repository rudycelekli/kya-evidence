import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { assess, digest } from '../src/index.mjs';
import { inputs, NOW } from './helpers.mjs';

// Second, independent killers for the reliability gates of kya-check. The first killers read the JSON summary;
// these read the exit code, the GitHub annotations, the step summary and the job outputs.
const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/kya-check.mjs');
const dir = mkdtempSync(join(tmpdir(), 'kya-redundancy-check-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
let counter = 0;
const put = (name, value) => { const p = join(dir, (counter++) + '-' + name); writeFileSync(p, JSON.stringify(value)); return p; };
function actions(args) {
  const out = join(dir, (counter++) + '-output.txt'), summary = join(dir, (counter++) + '-summary.md');
  writeFileSync(out, ''); writeFileSync(summary, '');
  const p = spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', timeout: 20000, env: { PATH: process.env.PATH, GITHUB_ACTIONS: 'true', GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: summary } });
  const outputs = Object.fromEntries(readFileSync(out, 'utf8').split('\n').filter(l => /^[a-z-]+=/.test(l)).map(l => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  return { status: p.status, stdout: p.stdout, stderr: p.stderr, outputs, markdown: readFileSync(summary, 'utf8') };
}
const inputsFile = (x = inputs()) => put('inputs.json', { manifest: x.manifest, profile: x.profile, policy: x.policy, evidence: x.evidence, evaluatorDigest: x.evaluatorDigest });

test('fixture evidence is annotated and withheld in job outputs unless fixtures are explicitly allowed', () => {
  const withheld = actions(['--assessment-inputs', inputsFile(), '--now', NOW]);
  assert.equal(withheld.status, 2, withheld.stderr);
  assert.match(withheld.stdout, /FIXTURE_EVIDENCE_NOT_RELIABLE/);
  assert.equal(withheld.outputs.reliable, 'false');
  assert.equal(withheld.outputs['exit-code'], '2');
  assert.match(withheld.markdown, /FIXTURE.{1,2}EVIDENCE.{1,2}NOT.{1,2}RELIABLE/);
  assert.match(withheld.markdown, /NOT RELIABLE/);
  const allowed = actions(['--assessment-inputs', inputsFile(), '--now', NOW, '--allow-fixture']);
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(allowed.outputs.reliable, 'true');
  assert.doesNotMatch(allowed.stdout, /FIXTURE_EVIDENCE_NOT_RELIABLE/);
});

test('fixture evidence in a stored assessment is withheld by the not qualified fail mode too', () => {
  const x = inputs(), report = assess({ ...x, now: NOW });
  const base = ['--assessment', put('assessment.json', report), '--manifest', put('manifest.json', x.manifest), '--policy', put('policy.json', x.policy), '--now', NOW, '--allow-unpinned-assessment'];
  const strict = actions([...base, '--fail-on', 'not-qualified']);
  assert.equal(strict.status, 2, strict.stderr);
  assert.match(strict.stdout, /FIXTURE_EVIDENCE_NOT_RELIABLE/);
  assert.equal(actions([...base, '--fail-on', 'not-qualified', '--allow-fixture']).status, 0);
});

test('an unpinned stored assessment is withheld with an annotation and a pin makes it reliable', () => {
  const x = inputs(), report = assess({ ...x, now: NOW });
  const base = ['--assessment', put('assessment.json', report), '--manifest', put('manifest.json', x.manifest), '--policy', put('policy.json', x.policy), '--now', NOW, '--allow-fixture'];
  const unpinned = actions(base);
  assert.equal(unpinned.status, 2, unpinned.stderr);
  assert.match(unpinned.stdout, /ASSESSMENT_NOT_PINNED/);
  assert.match(unpinned.markdown, /ASSESSMENT.{1,2}NOT.{1,2}PINNED/);
  assert.equal(unpinned.outputs.reliable, 'false');
  const pinned = actions([...base, '--expect-assessment-digest', report.reportDigest]);
  assert.equal(pinned.status, 0, pinned.stderr);
  assert.equal(pinned.outputs.reliable, 'true');
  assert.doesNotMatch(pinned.markdown, /ASSESSMENT.{1,2}NOT.{1,2}PINNED/);
  const opted = actions([...base, '--allow-unpinned-assessment']);
  assert.equal(opted.status, 0, opted.stderr);
});

test('a wrong assessment pin is a usage error and never reads as reliable', () => {
  const x = inputs(), report = assess({ ...x, now: NOW });
  const wrong = actions(['--assessment', put('assessment.json', report), '--manifest', put('manifest.json', x.manifest), '--policy', put('policy.json', x.policy), '--now', NOW, '--allow-fixture', '--expect-assessment-digest', digest({ other: true })]);
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /ASSESSMENT_DIGEST_MISMATCH/);
});
