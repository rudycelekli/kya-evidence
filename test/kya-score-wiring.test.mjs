import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { hashBytes } from '../src/shared/canonical.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const bin = join(root, 'bin/kya.mjs');
const run = args => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', timeout: 20000 });
const HEX = c => hashBytes('kya-score-wiring-' + c);
const runs = Array.from({ length: 3 }, (_, r) => ({ runId: 'run-' + r, items: Array.from({ length: 40 }, (_, i) => ({ id: 'item-' + String(i).padStart(3, '0'), outcome: i % 5 === 0 ? 'fail' : 'pass', heldOut: i < 12, durationMs: 10, costUsd: 0.01 })) }));
const manifest = { subject: { id: 'subject:wiring', version: '1', digest: HEX('subject') }, suite: { id: 'wiring-suite', version: '1', digest: HEX('suite') }, evaluatorDigest: HEX('evaluator'), judge: null, holdoutCommitment: HEX('holdout'), environment: { runtime: 'node-test', offlineDeclared: true }, bootstrap: { seed: 'wiring', resamples: 2000 } };

test('kya help lists the score subcommand and the delegated help comes from the score script', () => {
  assert.match(run(['--help']).stdout, /kya score build\|verify/);
  const r = run(['score', '--help']);
  assert.equal(r.status, 0, r.stderr);
  assert.ok((r.stdout + r.stderr).includes('kya-score:'));
});

test('kya score build and verify pass arguments and exit codes through the kya command', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kya-score-wire-'));
  try {
    const m = join(dir, 'm.json'), r = join(dir, 'r.json'), out = join(dir, 'card.json');
    await writeFile(m, JSON.stringify(manifest)); await writeFile(r, JSON.stringify(runs));
    const built = run(['score', 'build', '--manifest', m, '--runs', r, '--out', out]);
    assert.equal(built.status, 0, built.stderr);
    assert.equal(JSON.parse(built.stdout).score, 800);
    const ok = run(['score', 'verify', out]);
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(JSON.parse(ok.stdout).valid, true);
    const card = JSON.parse(readFileSync(out, 'utf8')); card.results.headline.score = 999;
    const bad = join(dir, 'bad.json'); await writeFile(bad, JSON.stringify(card));
    assert.equal(run(['score', 'verify', bad]).status, 1);
    await writeFile(r, JSON.stringify(runs.slice(0, 1)));
    const refused = run(['score', 'build', '--manifest', m, '--runs', r, '--out', join(dir, 'never.json')]);
    assert.equal(refused.status, 2);
    assert.ok(refused.stderr.includes('REPEATS_BELOW_FLOOR'));
    assert.equal(existsSync(join(dir, 'never.json')), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('the package exports a kya score subpath that resolves and the root typings name the card types', async () => {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const entry = pkg.exports['./kya-score'];
  assert.ok(entry && entry.import === './src/kya-score/index.mjs' && entry.types === './src/kya-score/index.d.ts');
  assert.ok(existsSync(join(root, entry.types)));
  const mod = await import(new URL('../' + entry.import, import.meta.url));
  for (const name of ['buildScoreCard', 'verifyScoreCard', 'compareScoreCards', 'NON_CLAIM_CODES', 'EVIDENCE_FLOOR']) assert.ok(name in mod, name);
  const dts = readFileSync(join(root, entry.types), 'utf8');
  for (const name of ['buildScoreCard', 'verifyScoreCard', 'compareScoreCards', 'ScoreCard', 'ScoreCardManifest', 'ScoreCardRefusal']) assert.ok(dts.includes(name), name);
  assert.match(readFileSync(join(root, 'src/index.d.ts'), 'utf8'), /from '\.\/kya-score\/index\.js'/);
});
