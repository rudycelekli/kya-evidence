import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { digest, hashBytes } from '../src/shared/canonical.mjs';
import { seededRandom, bootstrapInterval, wilsonInterval, buildScoreCard, verifyScoreCard, compareScoreCards, EVIDENCE_FLOOR, NON_CLAIM_CODES, SCORE_CARD_SCHEMA } from '../src/kya-score/index.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const HEX = c => hashBytes('kya-score-test-' + c);
const ids = n => Array.from({ length: n }, (_, i) => 'item-' + String(i).padStart(3, '0'));

// Deterministic synthetic runs. Item i passes in repeat r unless the rule says otherwise.
function makeRuns({ n = 40, repeats = 3, heldOut = 12, rule = (i, r) => (i % 5 === 0 ? 'fail' : 'pass'), cost = 0.01 } = {}) {
  return Array.from({ length: repeats }, (_, r) => ({
    runId: 'run-' + r,
    items: ids(n).map((id, i) => ({ id, outcome: rule(i, r), heldOut: i < heldOut, durationMs: 10 + i, costUsd: cost })),
  }));
}
function makeManifest(over = {}) {
  return {
    subject: { id: 'subject:synthetic-harness', version: '1', digest: HEX('subject') },
    suite: { id: 'synthetic-suite', version: '1', digest: HEX('suite') },
    evaluatorDigest: HEX('evaluator'),
    judge: null,
    holdoutCommitment: HEX('holdout'),
    environment: { runtime: 'node-test', offlineDeclared: true },
    bootstrap: { seed: 'seed-one', resamples: 2000 },
    ...over,
  };
}
const build = (runs = makeRuns(), manifest = makeManifest(), options) => buildScoreCard({ manifest, runs, ...(options ? { options } : {}) });
const reseal = card => { const { cardDigest, ...body } = card; card.cardDigest = digest(body); return card; };
const clone = v => structuredClone(v);

test('seeded random is deterministic and differs between seeds', () => {
  const a = seededRandom('alpha'), b = seededRandom('alpha'), c = seededRandom('beta');
  const sa = Array.from({ length: 8 }, () => a(1000)), sb = Array.from({ length: 8 }, () => b(1000)), sc = Array.from({ length: 8 }, () => c(1000));
  assert.deepEqual(sa, sb);
  assert.notDeepEqual(sa, sc);
  assert.ok(sa.every(x => Number.isInteger(x) && x >= 0 && x < 1000));
});

test('bootstrap interval is identical for identical seed and data and brackets the point estimate', () => {
  const data = [1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1];
  const one = bootstrapInterval(data, { seed: 's', resamples: 2000 }), two = bootstrapInterval(data, { seed: 's', resamples: 2000 });
  assert.deepEqual(one, two);
  assert.ok(one.low <= one.estimate && one.estimate <= one.high);
  assert.ok(one.low >= 0 && one.high <= 1);
  const other = bootstrapInterval(data, { seed: 'different', resamples: 2000 });
  assert.equal(other.estimate, one.estimate);
});

test('bootstrap interval is wider for a small sample than for a large one with the same mean', () => {
  const small = Array.from({ length: 10 }, (_, i) => (i % 2)), large = Array.from({ length: 200 }, (_, i) => (i % 2));
  const s = bootstrapInterval(small, { seed: 'w', resamples: 2000 }), l = bootstrapInterval(large, { seed: 'w', resamples: 2000 });
  assert.ok(s.high - s.low > l.high - l.low);
});

test('bootstrap rejects empty data non finite values and unsafe resample counts', () => {
  assert.throws(() => bootstrapInterval([], { seed: 's', resamples: 1000 }), /empty/i);
  assert.throws(() => bootstrapInterval([1, NaN], { seed: 's', resamples: 1000 }), /finite/i);
  assert.throws(() => bootstrapInterval([1, 0], { seed: 's', resamples: 5 }), /resamples/i);
  assert.throws(() => bootstrapInterval([1, 0], { seed: '', resamples: 1000 }), /seed/i);
});

test('wilson interval reproduces the published floor arithmetic of ADR-0019', () => {
  const sixteen = wilsonInterval(16, 16), fifteen = wilsonInterval(15, 15);
  assert.ok(Math.abs(sixteen.low - 0.806) < 0.001);
  assert.ok(Math.abs(fifteen.low - 0.796) < 0.001);
  assert.equal(wilsonInterval(0, 10).low, 0);
  assert.throws(() => wilsonInterval(11, 10), /count/i);
});

test('score card carries a headline with interval counts manifest and fixed non claims', () => {
  const card = build();
  assert.equal(card.schema, SCORE_CARD_SCHEMA);
  const h = card.results.headline;
  assert.equal(h.items, 40); assert.equal(h.repeats, 3);
  // 8 of 40 items fail every repeat, so 32 of 40 pass: floor(1000 * 96 / 120) = 800.
  assert.equal(h.score, 800);
  assert.ok(h.ci95.low <= 800 && 800 <= h.ci95.high);
  assert.deepEqual(card.nonClaims, [...NON_CLAIM_CODES]);
  assert.ok(NON_CLAIM_CODES.includes('NOT_PREDICTIVE_VALIDITY') && NON_CLAIM_CODES.includes('NOT_CALIBRATED_TO_INCIDENTS') && NON_CLAIM_CODES.includes('NO_INTER_ASSESSOR_AGREEMENT'));
  assert.equal(card.manifest.subject.digest, HEX('subject'));
  assert.equal(card.runDigest, digest(card.runs));
  assert.equal(verifyScoreCard(card).valid, true);
});

test('fixed denominator counts abstain and error as non passes', () => {
  const runs = makeRuns({ rule: (i, r) => (i === 0 ? 'abstain' : i === 1 ? 'error' : 'pass') });
  const card = build(runs);
  assert.deepEqual(card.results.outcomes, { pass: 114, fail: 0, abstain: 3, error: 3, denominator: 120 });
  assert.equal(card.results.headline.score, Math.floor(1000 * 114 / 120));
});

test('repeat variance reports per run scores spread and the share of unstable items', () => {
  const runs = makeRuns({ rule: (i, r) => (i < 4 && r === 0 ? 'fail' : 'pass') });
  const card = build(runs);
  const v = card.results.repeatVariance;
  assert.deepEqual(v.perRunScores, [900, 1000, 1000]);
  assert.equal(v.min, 900); assert.equal(v.max, 1000);
  assert.ok(v.sd > 57 && v.sd < 58);
  assert.equal(v.unstableItemShare, 0.1);
});

test('held out and public items are scored separately and the gap is descriptive', () => {
  const runs = makeRuns({ n: 40, heldOut: 12, rule: (i, r) => (i < 12 && i % 2 === 0 ? 'fail' : 'pass') });
  const card = build(runs);
  assert.equal(card.results.heldOut.items, 12);
  assert.equal(card.results.public.items, 28);
  assert.equal(card.results.heldOut.score, 500);
  assert.equal(card.results.public.score, 1000);
  assert.equal(card.results.publicMinusHeldOut, 500);
});

test('cost and runtime are reported and cost stays null when any item cost is unknown', () => {
  const known = build();
  assert.equal(known.results.cost.totalUsd, 1.2);
  assert.equal(known.results.cost.knownItems, 120);
  assert.equal(known.results.runtime.totalDurationMs, 3 * (40 * 10 + (39 * 40) / 2));
  const runs = makeRuns(); runs[1].items[3].costUsd = null;
  const partial = build(runs);
  assert.equal(partial.results.cost.totalUsd, null);
  assert.equal(partial.results.cost.knownItems, 119);
});

test('score card build is byte identical for identical inputs', () => {
  assert.equal(JSON.stringify(build()), JSON.stringify(build()));
  const other = build(makeRuns(), makeManifest({ bootstrap: { seed: 'seed-two', resamples: 2000 } }));
  assert.equal(other.results.headline.score, build().results.headline.score);
  assert.notEqual(other.cardDigest, build().cardDigest);
});

test('build refuses below the item floor and names the code', () => {
  assert.throws(() => build(makeRuns({ n: EVIDENCE_FLOOR.minItems - 1, heldOut: 10 })), e => e.code === 'EVIDENCE_FLOOR_NOT_MET' && e.refusals.includes('ITEMS_BELOW_FLOOR'));
});

test('build refuses below the repeat floor and names the code', () => {
  assert.throws(() => build(makeRuns({ repeats: EVIDENCE_FLOOR.minRepeats - 1 })), e => e.code === 'EVIDENCE_FLOOR_NOT_MET' && e.refusals.includes('REPEATS_BELOW_FLOOR'));
});

test('build refuses too few held out items and a missing holdout commitment', () => {
  assert.throws(() => build(makeRuns({ heldOut: EVIDENCE_FLOOR.minHeldOutItems - 1 })), e => e.refusals.includes('HELDOUT_BELOW_FLOOR'));
  assert.throws(() => build(makeRuns(), makeManifest({ holdoutCommitment: null })), e => e.refusals.includes('HOLDOUT_COMMITMENT_MISSING'));
});

test('build reports every unmet floor at once', () => {
  assert.throws(() => build(makeRuns({ n: 12, repeats: 1, heldOut: 1 }), makeManifest({ holdoutCommitment: null })), e => ['ITEMS_BELOW_FLOOR', 'REPEATS_BELOW_FLOOR', 'HELDOUT_BELOW_FLOOR', 'HOLDOUT_COMMITMENT_MISSING'].every(c => e.refusals.includes(c)));
});

test('options can raise the floor but never lower it', () => {
  assert.throws(() => build(makeRuns(), makeManifest(), { floor: { minItems: 5 } }), /floor/i);
  assert.throws(() => build(makeRuns({ n: 40 }), makeManifest(), { floor: { minItems: 50 } }), e => e.refusals.includes('ITEMS_BELOW_FLOOR'));
  const raised = build(makeRuns({ n: 60, heldOut: 20 }), makeManifest(), { floor: { minItems: 50 } });
  assert.equal(raised.floor.minItems, 50);
});

test('build rejects runs that disagree on the item population and duplicate item ids', () => {
  const runs = makeRuns(); runs[2].items.pop();
  assert.throws(() => build(runs), /population/i);
  const dup = makeRuns(); dup[0].items[1].id = dup[0].items[0].id;
  assert.throws(() => build(dup), /duplicate/i);
  const flag = makeRuns(); flag[1].items[0].heldOut = !flag[1].items[0].heldOut;
  assert.throws(() => build(flag), /held out/i);
});

test('build rejects malformed manifests and unknown fields', () => {
  assert.throws(() => build(makeRuns(), makeManifest({ extra: 1 })), /manifest/i);
  assert.throws(() => build(makeRuns(), makeManifest({ subject: { id: 'x', version: '1', digest: 'nothex' } })), /digest/i);
  assert.throws(() => build(makeRuns(), makeManifest({ bootstrap: { seed: 's', resamples: 10 } })), /resamples/i);
  assert.throws(() => build(makeRuns(), makeManifest({ judge: { id: 'j' } })), /judge/i);
});

test('canary exposures are counted from item flags and reported', () => {
  const runs = makeRuns(); runs[0].items[2].canaryExposed = true; runs[1].items[2].canaryExposed = true;
  const card = build(runs);
  assert.equal(card.results.integrity.canaryExposures, 2);
  assert.equal(verifyScoreCard(card).valid, true);
});

test('verify accepts an untouched card and returns the recomputed headline', () => {
  const card = build();
  const r = verifyScoreCard(JSON.parse(JSON.stringify(card)));
  assert.equal(r.valid, true); assert.equal(r.score, card.results.headline.score); assert.equal(r.cardDigest, card.cardDigest);
});

test('verify rejects an edited headline score even when the digest is recomputed', () => {
  const card = clone(build()); card.results.headline.score = 990; reseal(card);
  assert.equal(verifyScoreCard(card).valid, false);
  assert.ok(verifyScoreCard(card).problems.includes('results-differ-from-recomputation'));
});

test('verify rejects an edited item outcome when only the digest is recomputed', () => {
  const card = clone(build()); card.runs[0].items[0].outcome = 'pass'; reseal(card);
  assert.equal(verifyScoreCard(card).valid, false);
});

test('verify rejects a stale digest after any edit', () => {
  const card = clone(build()); card.manifest.subject.version = '2';
  const r = verifyScoreCard(card);
  assert.equal(r.valid, false); assert.ok(r.problems.includes('card-digest-differs'));
});

test('verify rejects dropped or reordered non claims', () => {
  const dropped = clone(build()); dropped.nonClaims.pop(); reseal(dropped);
  assert.equal(verifyScoreCard(dropped).valid, false);
  const reordered = clone(build()); reordered.nonClaims.reverse(); reseal(reordered);
  assert.equal(verifyScoreCard(reordered).valid, false);
});

test('verify rejects a card whose recorded floor was lowered below the hard floor', () => {
  const card = clone(build()); card.floor.minItems = 1; reseal(card);
  const r = verifyScoreCard(card);
  assert.equal(r.valid, false); assert.ok(r.problems.includes('floor-below-hard-minimum'));
});

test('verify rejects a card built from too little evidence even with an honest floor field', () => {
  const small = clone(build()); small.runs = small.runs.slice(0, 2); small.runDigest = digest(small.runs); reseal(small);
  const r = verifyScoreCard(small);
  assert.equal(r.valid, false);
});

test('verify rejects unknown fields and wrong schema without throwing', () => {
  const card = clone(build()); card.extra = true; reseal(card);
  assert.equal(verifyScoreCard(card).valid, false);
  assert.equal(verifyScoreCard({ schema: 'other' }).valid, false);
  assert.equal(verifyScoreCard(null).valid, false);
  assert.equal(verifyScoreCard('text').valid, false);
});

test('compare refuses different suites and flags overlapping intervals as not distinguishable', () => {
  const a = build(), b = build(makeRuns({ rule: (i) => (i % 5 === 0 || i === 1 ? 'fail' : 'pass') }));
  const same = compareScoreCards(a, b);
  assert.equal(same.comparable, true);
  assert.equal(same.distinguishable, a.results.headline.ci95.high < b.results.headline.ci95.low || b.results.headline.ci95.high < a.results.headline.ci95.low);
  const other = build(makeRuns(), makeManifest({ suite: { id: 'synthetic-suite', version: '2', digest: HEX('suite-v2') } }));
  const diff = compareScoreCards(a, other);
  assert.equal(diff.comparable, false); assert.ok(diff.reasons.includes('suite-digest-differs'));
  const evalChange = build(makeRuns(), makeManifest({ evaluatorDigest: HEX('evaluator-2') }));
  assert.ok(compareScoreCards(a, evalChange).reasons.includes('evaluator-digest-differs'));
});

test('compare reports clearly separated scores as distinguishable', () => {
  const high = build(makeRuns({ n: 200, heldOut: 40, rule: () => 'pass' }));
  const low = build(makeRuns({ n: 200, heldOut: 40, rule: (i) => (i % 2 ? 'fail' : 'pass') }));
  const r = compareScoreCards(high, low);
  assert.equal(r.comparable, true); assert.equal(r.distinguishable, true); assert.equal(r.delta, high.results.headline.score - low.results.headline.score);
});

test('the kya score source makes no network or process calls', () => {
  const dir = join(root, 'src/kya-score');
  const files = readdirSync(dir).filter(f => f.endsWith('.mjs'));
  assert.ok(files.length >= 3);
  for (const f of files) {
    const text = readFileSync(join(dir, f), 'utf8');
    assert.ok(!/node:(?:net|http|https|dgram|tls|dns|child_process)|\bfetch\s*\(|XMLHttpRequest|WebSocket/.test(text), f + ' reaches for the network or a process');
  }
});

test('the kya score cli builds a card then verifies it and rejects a tampered copy', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kya-score-'));
  try {
    const m = join(dir, 'manifest.json'), r = join(dir, 'runs.json'), out = join(dir, 'card.json');
    await writeFile(m, JSON.stringify(makeManifest())); await writeFile(r, JSON.stringify(makeRuns()));
    const run = (...a) => spawnSync(process.execPath, [join(root, 'scripts/kya-score.mjs'), ...a], { encoding: 'utf8', timeout: 20000 });
    const built = run('build', '--manifest', m, '--runs', r, '--out', out);
    assert.equal(built.status, 0, built.stderr);
    assert.equal(JSON.parse(built.stdout).score, 800);
    const ok = run('verify', out);
    assert.equal(ok.status, 0, ok.stderr); assert.equal(JSON.parse(ok.stdout).valid, true);
    const card = JSON.parse(await readFile(out, 'utf8')); card.results.headline.score = 999;
    const bad = join(dir, 'bad.json'); await writeFile(bad, JSON.stringify(card));
    assert.equal(run('verify', bad).status, 1);
    await writeFile(r, JSON.stringify(makeRuns({ n: 10, heldOut: 10 })));
    const refused = run('build', '--manifest', m, '--runs', r, '--out', join(dir, 'never.json'));
    assert.equal(refused.status, 2);
    assert.ok(refused.stderr.includes('ITEMS_BELOW_FLOOR'));
    assert.equal(existsSync(join(dir, 'never.json')), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('ADR-0033 is Proposed and names what is unmeasured', () => {
  const adr = readFileSync(join(root, 'docs/adr/0033-kya-score-benchmark-profile.md'), 'utf8');
  assert.match(adr, /^# ADR-0033: /m);
  assert.match(adr, /^\*\*Status\*\*: Proposed$/m);
  for (const s of ['predictive validity', 'inter-assessor agreement', 'calibration against real incidents']) assert.ok(adr.includes(s), s);
  for (const c of NON_CLAIM_CODES) assert.ok(adr.includes(c), c);
});

test('the fix lane 8 integration note names only requirement titles and spec headings that exist', () => {
  const note = readFileSync(join(root, 'docs/fixlane8-integration.md'), 'utf8');
  const spec = readFileSync(join(root, 'docs/SPECIFICATION.md'), 'utf8').split('\n');
  const mine = readFileSync(fileURLToPath(import.meta.url), 'utf8');
  const titles = [...note.matchAll(/^- test: `([^`]+)`$/gm)].map(m => m[1]);
  const headings = [...note.matchAll(/^- spec: `(## [^`]+)`$/gm)].map(m => m[1]);
  assert.ok(titles.length >= 8 && headings.length >= 1);
  for (const t of titles) assert.ok(mine.includes("test('" + t + "'"), 'no such test title: ' + t);
  for (const h of headings) assert.ok(spec.includes(h), 'no such spec heading: ' + h);
});
