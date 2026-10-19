// verify-score-card and compare-score-cards (contract version 2) of the second implementation, written from
// "Score card verification" in docs/SPECIFICATION.md. Team-built, NOT independent.
import { createHash } from 'node:crypto';
import { Refusal, canonical, sha256hex, isObj, HEX64 } from './kya2.mjs';

const refuse = m => { throw new Refusal(m); };
const RESULT = 'kya.impl-result/v1';
const has = (o, k) => Object.hasOwn(o, k);
const keysAre = (o, ks) => isObj(o) && Object.keys(o).length === ks.length && ks.every(k => has(o, k));
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const isHash = s => typeof s === 'string' && HEX64.test(s);
const isIdent = s => typeof s === 'string' && ID.test(s);
const MINIMUMS = { minItems: 30, minRepeats: 3, minHeldOutItems: 10 };
const NON_CLAIMS = ['NOT_PREDICTIVE_VALIDITY', 'NOT_CALIBRATED_TO_INCIDENTS', 'NO_INTER_ASSESSOR_AGREEMENT', 'NOT_SAFETY_CERTIFICATION', 'NOT_ENDORSED_OR_ADOPTED', 'NOT_A_PRODUCT_RANKING', 'INTERVAL_COVERS_ITEM_SAMPLING_ONLY', 'SUBJECT_IDENTITY_AS_DECLARED', 'OFFLINE_EXECUTION_NOT_VERIFIED', 'ITEM_SET_MAY_BE_MEMORIZED'];
const OUTCOMES = ['pass', 'fail', 'abstain', 'error'];

class FloorRefused extends Error {}
const bad = m => { throw new Error('rebuild: ' + m); };

// canonical text bounded by the size limit of the canonical form
const canon = v => { const t = canonical(v); if (Buffer.byteLength(t, 'utf8') > 1048576) refuse('canonical form too long'); return t; };
const dig = v => sha256hex(canon(v));

// ---------------------------------------------------------------- generator
function seededRandom(seed) {
  const h = createHash('sha256').update('kya.score.seed/v1\n' + seed, 'utf8').digest();
  let a = h.readUInt32BE(0), b = h.readUInt32BE(4), c = h.readUInt32BE(8), d = h.readUInt32BE(12);
  const step = () => {
    let t = (a + b) >>> 0;
    a = (b ^ (b >>> 9)) >>> 0;
    b = (c + (c << 3)) >>> 0;
    c = ((c << 21) | (c >>> 11)) >>> 0;
    d = (d + 1) >>> 0;
    t = (t + d) >>> 0;
    c = (c + t) >>> 0;
    return t;
  };
  for (let i = 0; i < 12; i++) step();
  return bound => {
    const limit = Math.floor(4294967296 / bound) * bound;
    let x = step();
    while (x >= limit) x = step();
    return x % bound;
  };
}

// ---------------------------------------------------------------- computation
const roundTo = (x, f) => Math.round(x * f) / f;
const scoreOf = (sum, m, R) => Math.floor(1000 * sum / (m * R));

function aggregate(ps, R, seed, B, label) {
  const m = ps.length, next = seededRandom(seed + '|' + label);
  let total = 0; for (const p of ps) total += p;
  const sums = new Array(B);
  for (let r = 0; r < B; r++) { let s = 0; for (let j = 0; j < m; j++) s += ps[next(m)]; sums[r] = s; }
  sums.sort((x, y) => x - y);
  const k = Math.floor(B * 25 / 1000);
  return { items: m, repeats: R, score: scoreOf(total, m, R), ci95: { low: scoreOf(sums[k], m, R), high: scoreOf(sums[B - 1 - k], m, R) }, resamples: B };
}

function compute(manifest, runs) {
  const R = runs.length, n = runs[0].items.length, B = manifest.bootstrap.resamples, seed = manifest.bootstrap.seed;
  const p = new Array(n).fill(0), counts = { pass: 0, fail: 0, abstain: 0, error: 0 };
  const perRun = [];
  let unstable = 0, known = 0, costSum = 0, dur = 0, maxDur = 0, canary = 0;
  for (const run of runs) {
    let passes = 0;
    run.items.forEach((it, i) => {
      counts[it.outcome]++;
      if (it.outcome === 'pass') { passes++; p[i]++; }
      if (it.costUsd !== null) { known++; costSum += Math.round(it.costUsd * 1e6); }
      dur += it.durationMs; if (it.durationMs > maxDur) maxDur = it.durationMs;
      if (it.canaryExposed) canary++;
    });
    perRun.push(Math.floor(1000 * passes / n));
  }
  for (let i = 0; i < n; i++) if (!runs.every(r => r.items[i].outcome === runs[0].items[i].outcome)) unstable++;
  const held = runs[0].items.map(x => x.heldOut);
  const all = p, heldP = p.filter((_, i) => held[i]), pubP = p.filter((_, i) => !held[i]);
  const headline = aggregate(all, R, seed, B, 'all');
  const heldOut = aggregate(heldP, R, seed, B, 'heldout');
  const pub = pubP.length ? aggregate(pubP, R, seed, B, 'public') : null;
  const mean = perRun.reduce((a, b) => a + b, 0) / R;
  let sq = 0; for (const s of perRun) sq += (s - mean) * (s - mean);
  return {
    headline, heldOut, public: pub, publicMinusHeldOut: pub ? pub.score - heldOut.score : null,
    outcomes: { ...counts, denominator: n * R },
    repeatVariance: { perRunScores: perRun, mean: roundTo(mean, 1e6), sd: roundTo(Math.sqrt(sq / (R - 1)), 1e6), min: Math.min(...perRun), max: Math.max(...perRun), unstableItemShare: roundTo(unstable / n, 1e6) },
    cost: { totalUsd: known === n * R ? costSum / 1e6 : null, knownItems: known, items: n * R },
    runtime: { totalDurationMs: roundTo(dur, 1e3), meanPerRunDurationMs: roundTo(dur / R, 1e3), maxItemDurationMs: maxDur },
    integrity: { canaryExposures: canary }
  };
}

// ---------------------------------------------------------------- build / rebuild
function checkManifest(m) {
  if (!keysAre(m, ['subject', 'suite', 'evaluatorDigest', 'judge', 'holdoutCommitment', 'environment', 'bootstrap'])) bad('manifest members');
  for (const k of ['subject', 'suite']) {
    const x = m[k];
    if (!keysAre(x, ['id', 'version', 'digest']) || !isIdent(x.id) || !isIdent(x.version) || !isHash(x.digest)) bad(k);
  }
  if (!isHash(m.evaluatorDigest)) bad('evaluatorDigest');
  if (m.judge !== null && (!keysAre(m.judge, ['id', 'digest']) || !isIdent(m.judge.id) || !isHash(m.judge.digest))) bad('judge');
  if (m.holdoutCommitment !== null && !isHash(m.holdoutCommitment)) bad('holdoutCommitment');
  const e = m.environment;
  if (!keysAre(e, ['runtime', 'offlineDeclared']) || typeof e.runtime !== 'string' || e.runtime.length < 1 || e.runtime.length > 128 || typeof e.offlineDeclared !== 'boolean') bad('environment');
  const b = m.bootstrap;
  if (!keysAre(b, ['seed', 'resamples']) || typeof b.seed !== 'string' || b.seed.length < 1 || b.seed.length > 128 || !Number.isInteger(b.resamples) || b.resamples < 100 || b.resamples > 20000) bad('bootstrap');
}

const cmpUnits = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
// returns runs with canaryExposed filled in (absent means false)
function checkRuns(runs) {
  if (!Array.isArray(runs) || runs.length < 1 || runs.length > 32) bad('runs');
  const runIds = new Set();
  const out = runs.map(run => {
    if (!isObj(run) || !has(run, 'runId') || !has(run, 'items') || Object.keys(run).length !== 2 || !isIdent(run.runId) || runIds.has(run.runId)) bad('run');
    runIds.add(run.runId);
    if (!Array.isArray(run.items) || run.items.length < 1 || run.items.length > 2000) bad('items');
    const ids = new Set();
    const items = run.items.map((it, i) => {
      if (!isObj(it) || !['id', 'outcome', 'heldOut', 'durationMs', 'costUsd'].every(k => has(it, k)) || !Object.keys(it).every(k => ['id', 'outcome', 'heldOut', 'durationMs', 'costUsd', 'canaryExposed'].includes(k))) bad('item members');
      if (!isIdent(it.id) || ids.has(it.id)) bad('item id');
      ids.add(it.id);
      if (!OUTCOMES.includes(it.outcome) || typeof it.heldOut !== 'boolean') bad('item outcome');
      if (typeof it.durationMs !== 'number' || !(it.durationMs >= 0 && it.durationMs <= 1e9)) bad('durationMs');
      if (it.costUsd !== null && (typeof it.costUsd !== 'number' || !(it.costUsd >= 0 && it.costUsd <= 1e6))) bad('costUsd');
      if (has(it, 'canaryExposed') && typeof it.canaryExposed !== 'boolean') bad('canaryExposed');
      return { id: it.id, outcome: it.outcome, heldOut: it.heldOut, durationMs: it.durationMs, costUsd: it.costUsd, canaryExposed: it.canaryExposed === true };
    });
    // the builder puts items in ascending id order (UTF-16 code units), so a card with another order differs from its rebuild
    return { runId: run.runId, items: items.sort((x, y) => cmpUnits(x.id, y.id)) };
  });
  for (const r of out) {
    if (r.items.length !== out[0].items.length || r.items.some((it, i) => it.id !== out[0].items[i].id || it.heldOut !== out[0].items[i].heldOut)) bad('runs differ in items');
  }
  return out;
}

function build(manifest, runsIn, floor) {
  checkManifest(manifest);
  const runs = checkRuns(runsIn);
  const n = runs[0].items.length, held = runs[0].items.filter(x => x.heldOut).length;
  if (n < floor.minItems || runs.length < floor.minRepeats || held < floor.minHeldOutItems || manifest.holdoutCommitment === null) throw new FloorRefused('floor');
  const body = { schema: 'kya.score-card/v1', label: 'KYA-SCR-EXPERIMENTAL', manifest, floor, runs, runDigest: dig(runs), results: compute(manifest, runs), nonClaims: NON_CLAIMS };
  return { ...body, cardDigest: dig(body) };
}

// ---------------------------------------------------------------- verification
const floorOk = f => keysAre(f, Object.keys(MINIMUMS)) && Object.entries(MINIMUMS).every(([k, min]) => Number.isSafeInteger(f[k]) && f[k] >= min);

export function verifyCard(card) {
  if (!isObj(card) || card.schema !== 'kya.score-card/v1') return ['wrong-schema'];
  const top = ['schema', 'label', 'manifest', 'floor', 'runs', 'runDigest', 'results', 'nonClaims', 'cardDigest'];
  if (!keysAre(card, top)) return ['unexpected-or-missing-fields'];
  const problems = [];
  try {
    const { cardDigest, ...rest } = card;
    if (dig(rest) !== cardDigest) problems.push('card-digest-differs');
    if (dig(card.runs) !== card.runDigest) problems.push('run-digest-differs');
    const ok = floorOk(card.floor);
    if (!ok) problems.push('floor-below-hard-minimum');
    let rebuilt = null;
    try { rebuilt = build(card.manifest, card.runs, ok ? card.floor : MINIMUMS); } catch (e) {
      if (e instanceof FloorRefused) problems.push('evidence-floor-not-met');
      else if (e instanceof Refusal) throw e;
      else problems.push('rebuild-failed');
    }
    if (rebuilt) {
      if (canon(rebuilt.results) !== canon(card.results)) problems.push('results-differ-from-recomputation');
      if (canon(rebuilt) !== canon(card)) problems.push('card-differs-from-recomputation');
    }
  } catch { problems.push('unverifiable'); }
  return problems;
}

export function verifyScoreCardOp(inputs) {
  if (!keysAre(inputs, ['card'])) refuse('inputs must hold exactly card');
  const problems = verifyCard(inputs.card);
  const base = { schema: RESULT, operation: 'verify-score-card', valid: problems.length === 0, problems };
  return problems.length ? { ...base, score: null, cardDigest: null } : { ...base, score: inputs.card.results.headline.score, cardDigest: inputs.card.cardDigest };
}

export function compareScoreCardsOp(inputs) {
  if (!keysAre(inputs, ['left', 'right'])) refuse('inputs must hold exactly left, right');
  const { left, right } = inputs;
  const base = { schema: RESULT, operation: 'compare-score-cards' };
  if (verifyCard(left).length || verifyCard(right).length) return { ...base, comparable: false, reasons: ['card-invalid'], delta: null, distinguishable: null };
  const reasons = [];
  if (left.manifest.suite.digest !== right.manifest.suite.digest) reasons.push('suite-digest-differs');
  if (left.manifest.evaluatorDigest !== right.manifest.evaluatorDigest) reasons.push('evaluator-digest-differs');
  if (reasons.length) return { ...base, comparable: false, reasons, delta: null, distinguishable: null };
  const l = left.results.headline, r = right.results.headline;
  return { ...base, comparable: true, reasons: [], delta: l.score - r.score, distinguishable: l.ci95.high < r.ci95.low || r.ci95.high < l.ci95.low };
}
