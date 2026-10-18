import { canonical, digest, insist } from '../shared/canonical.mjs';
import { bootstrapSumQuantiles } from './stats.mjs';

export const SCORE_CARD_SCHEMA = 'kya.score-card/v1';
export const SCORE_LABEL = 'KYA-SCORE-EXPERIMENTAL';
/** Lower bounds on evidence. A caller may raise any of them; none can be lowered, and a verifier re-applies them. */
export const EVIDENCE_FLOOR = Object.freeze({ minItems: 30, minRepeats: 3, minHeldOutItems: 10 });
/** Fixed, ordered list of things the headline number does not establish. Prose for each code lives in ADR-0033. */
export const NON_CLAIM_CODES = Object.freeze([
  'NOT_PREDICTIVE_VALIDITY', 'NOT_CALIBRATED_TO_INCIDENTS', 'NO_INTER_ASSESSOR_AGREEMENT', 'NOT_SAFETY_CERTIFICATION',
  'NOT_ENDORSED_OR_ADOPTED', 'NOT_A_PRODUCT_RANKING', 'INTERVAL_COVERS_ITEM_SAMPLING_ONLY', 'SUBJECT_IDENTITY_AS_DECLARED',
  'OFFLINE_EXECUTION_NOT_VERIFIED', 'ITEM_SET_MAY_BE_MEMORIZED',
]);
const OUTCOMES = Object.freeze(['pass', 'fail', 'abstain', 'error']);
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const TOP_KEYS = ['schema', 'label', 'manifest', 'floor', 'runs', 'runDigest', 'results', 'nonClaims', 'cardDigest'];

export class ScoreCardRefusal extends Error {
  constructor(refusals) {
    super(refusals.join(','));
    this.name = 'ScoreCardRefusal'; this.code = 'EVIDENCE_FLOOR_NOT_MET'; this.refusals = refusals;
  }
}

const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
function exact(value, keys, label, optional = []) {
  insist(plain(value), `Invalid ${label}`);
  for (const k of Object.keys(value)) insist(keys.includes(k) || optional.includes(k), `Invalid ${label}: unexpected field ${k}`);
  for (const k of keys) insist(Object.hasOwn(value, k), `Invalid ${label}: missing field ${k}`);
}
const round6 = x => Math.round(x * 1e6) / 1e6;
const round3 = x => Math.round(x * 1e3) / 1e3;
const idOk = (v, label) => insist(typeof v === 'string' && ID.test(v), `Invalid ${label}`);
const hexOk = (v, label) => insist(typeof v === 'string' && HEX64.test(v), `Invalid ${label} digest`);

function checkManifest(m) {
  exact(m, ['subject', 'suite', 'evaluatorDigest', 'judge', 'holdoutCommitment', 'environment', 'bootstrap'], 'manifest');
  exact(m.subject, ['id', 'version', 'digest'], 'manifest subject'); idOk(m.subject.id, 'subject id'); idOk(m.subject.version, 'subject version'); hexOk(m.subject.digest, 'subject');
  exact(m.suite, ['id', 'version', 'digest'], 'manifest suite'); idOk(m.suite.id, 'suite id'); idOk(m.suite.version, 'suite version'); hexOk(m.suite.digest, 'suite');
  hexOk(m.evaluatorDigest, 'evaluator');
  if (m.judge !== null) { exact(m.judge, ['id', 'digest'], 'judge'); idOk(m.judge.id, 'judge id'); hexOk(m.judge.digest, 'judge'); }
  if (m.holdoutCommitment !== null) hexOk(m.holdoutCommitment, 'holdout commitment');
  exact(m.environment, ['runtime', 'offlineDeclared'], 'manifest environment');
  insist(typeof m.environment.runtime === 'string' && m.environment.runtime.length > 0 && m.environment.runtime.length <= 128 && typeof m.environment.offlineDeclared === 'boolean', 'Invalid environment');
  exact(m.bootstrap, ['seed', 'resamples'], 'manifest bootstrap');
  insist(typeof m.bootstrap.seed === 'string' && m.bootstrap.seed.length > 0 && m.bootstrap.seed.length <= 128, 'Invalid bootstrap seed');
  insist(Number.isSafeInteger(m.bootstrap.resamples) && m.bootstrap.resamples >= 100 && m.bootstrap.resamples <= 20000, 'Invalid bootstrap resamples');
}

function normaliseRuns(input) {
  insist(Array.isArray(input) && input.length >= 1 && input.length <= 32, 'Invalid runs list');
  const runIds = new Set(); let population = null, flags = null;
  return input.map(run => {
    exact(run, ['runId', 'items'], 'run'); idOk(run.runId, 'run id'); insist(!runIds.has(run.runId), 'Duplicate run id'); runIds.add(run.runId);
    insist(Array.isArray(run.items) && run.items.length >= 1 && run.items.length <= 2000, 'Invalid item list');
    const seen = new Set();
    const items = run.items.map(item => {
      exact(item, ['id', 'outcome', 'heldOut', 'durationMs', 'costUsd'], 'item', ['canaryExposed']);
      idOk(item.id, 'item id'); insist(!seen.has(item.id), 'Duplicate item id'); seen.add(item.id);
      insist(OUTCOMES.includes(item.outcome), 'Invalid item outcome');
      insist(typeof item.heldOut === 'boolean' && (item.canaryExposed === undefined || typeof item.canaryExposed === 'boolean'), 'Invalid item flag');
      insist(typeof item.durationMs === 'number' && Number.isFinite(item.durationMs) && item.durationMs >= 0 && item.durationMs <= 1e9, 'Invalid item duration');
      insist(item.costUsd === null || (typeof item.costUsd === 'number' && Number.isFinite(item.costUsd) && item.costUsd >= 0 && item.costUsd <= 1e6), 'Invalid item cost');
      return { id: item.id, outcome: item.outcome, heldOut: item.heldOut, durationMs: item.durationMs, costUsd: item.costUsd, canaryExposed: item.canaryExposed === true };
    }).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const pop = items.map(i => i.id).join('\n'), fl = items.map(i => (i.heldOut ? 'h' : 'p')).join('');
    if (population === null) { population = pop; flags = fl; }
    else { insist(pop === population, 'Runs disagree on the item population'); insist(fl === flags, 'Runs disagree on the held out flags'); }
    return { runId: run.runId, items };
  });
}

function resolveFloor(options) {
  if (options === undefined) return { ...EVIDENCE_FLOOR };
  exact(options, [], 'options', ['floor']);
  const floor = { ...EVIDENCE_FLOOR };
  if (options.floor !== undefined) {
    exact(options.floor, [], 'floor', Object.keys(EVIDENCE_FLOOR));
    for (const [k, v] of Object.entries(options.floor)) {
      insist(Number.isSafeInteger(v) && v >= EVIDENCE_FLOOR[k], 'Floor cannot be lowered below the hard minimum');
      floor[k] = v;
    }
  }
  return floor;
}

function aggregate(passesPerItem, repeats, manifest, label) {
  const n = passesPerItem.length, sum = passesPerItem.reduce((a, b) => a + b, 0), denom = n * repeats;
  const q = bootstrapSumQuantiles(passesPerItem, { seed: manifest.bootstrap.seed + '|' + label, resamples: manifest.bootstrap.resamples });
  const score = s => Math.floor(1000 * s / denom);
  return { items: n, repeats, score: score(sum), ci95: { low: score(q.lowSum), high: score(q.highSum) }, resamples: q.resamples };
}

/**
 * Build a kya.score-card/v1 from repeated runs of one fixed item set. Pure and deterministic: no clock, no network,
 * no randomness beyond the seed in the manifest. Throws ScoreCardRefusal (code EVIDENCE_FLOOR_NOT_MET) below the floor.
 */
export function buildScoreCard({ manifest, runs: rawRuns, options } = {}) {
  const m = JSON.parse(canonical(manifest ?? null));
  checkManifest(m);
  const runs = normaliseRuns(JSON.parse(canonical(rawRuns ?? null)));
  const floor = resolveFloor(options === undefined ? undefined : JSON.parse(canonical(options)));
  const R = runs.length, items = runs[0].items, n = items.length;
  const heldCount = items.filter(i => i.heldOut).length;
  const refusals = [];
  if (n < floor.minItems) refusals.push('ITEMS_BELOW_FLOOR');
  if (R < floor.minRepeats) refusals.push('REPEATS_BELOW_FLOOR');
  if (heldCount < floor.minHeldOutItems) refusals.push('HELDOUT_BELOW_FLOOR');
  if (m.holdoutCommitment === null) refusals.push('HOLDOUT_COMMITMENT_MISSING');
  if (refusals.length) throw new ScoreCardRefusal(refusals);

  const passesPerItem = items.map((_, i) => runs.reduce((s, run) => s + (run.items[i].outcome === 'pass' ? 1 : 0), 0));
  const subset = flag => passesPerItem.filter((_, i) => items[i].heldOut === flag);
  const headline = aggregate(passesPerItem, R, m, 'all');
  const heldOut = aggregate(subset(true), R, m, 'heldout');
  const publicPart = subset(false).length ? aggregate(subset(false), R, m, 'public') : null;
  const outcomes = { pass: 0, fail: 0, abstain: 0, error: 0, denominator: n * R };
  let canaryExposures = 0, durationSum = 0, maxItem = 0, microUsd = 0, known = 0;
  for (const run of runs) for (const it of run.items) {
    outcomes[it.outcome]++; if (it.canaryExposed) canaryExposures++;
    durationSum += it.durationMs; maxItem = Math.max(maxItem, it.durationMs);
    if (it.costUsd !== null) { known++; microUsd += Math.round(it.costUsd * 1e6); }
  }
  const perRunScores = runs.map(run => Math.floor(1000 * run.items.filter(i => i.outcome === 'pass').length / n));
  const mean = perRunScores.reduce((a, b) => a + b, 0) / R;
  const sd = Math.sqrt(perRunScores.reduce((a, b) => a + (b - mean) * (b - mean), 0) / (R - 1));
  const unstable = items.filter((_, i) => new Set(runs.map(run => run.items[i].outcome)).size > 1).length;
  const results = {
    headline, heldOut, public: publicPart, publicMinusHeldOut: publicPart === null ? null : publicPart.score - heldOut.score, outcomes,
    repeatVariance: { perRunScores, mean: round6(mean), sd: round6(sd), min: Math.min(...perRunScores), max: Math.max(...perRunScores), unstableItemShare: round6(unstable / n) },
    cost: { totalUsd: known === n * R ? microUsd / 1e6 : null, knownItems: known, items: n * R },
    runtime: { totalDurationMs: round3(durationSum), meanPerRunDurationMs: round3(durationSum / R), maxItemDurationMs: maxItem },
    integrity: { canaryExposures },
  };
  const body = { schema: SCORE_CARD_SCHEMA, label: SCORE_LABEL, manifest: m, floor, runs, runDigest: digest(runs), results, nonClaims: [...NON_CLAIM_CODES] };
  return { ...body, cardDigest: digest(body) };
}

/** Recompute a card from its embedded runs and manifest. Never throws; returns {valid, problems, ...}. */
export function verifyScoreCard(card) {
  const problems = [];
  try {
    if (!plain(card) || card.schema !== SCORE_CARD_SCHEMA) return { valid: false, problems: ['wrong-schema'] };
    const extra = Object.keys(card).filter(k => !TOP_KEYS.includes(k)), missing = TOP_KEYS.filter(k => !Object.hasOwn(card, k));
    if (extra.length || missing.length) return { valid: false, problems: ['unexpected-or-missing-fields'] };
    const { cardDigest, ...body } = card;
    if (digest(body) !== cardDigest) problems.push('card-digest-differs');
    if (digest(card.runs) !== card.runDigest) problems.push('run-digest-differs');
    const floorOk = plain(card.floor) && Object.keys(card.floor).length === 3 && Object.keys(EVIDENCE_FLOOR).every(k => Number.isSafeInteger(card.floor[k]) && card.floor[k] >= EVIDENCE_FLOOR[k]);
    if (!floorOk) problems.push('floor-below-hard-minimum');
    let rebuilt = null;
    try { rebuilt = buildScoreCard({ manifest: card.manifest, runs: card.runs, options: { floor: floorOk ? card.floor : {} } }); }
    catch (error) { problems.push(error instanceof ScoreCardRefusal ? 'evidence-floor-not-met' : 'rebuild-failed'); }
    if (rebuilt) {
      if (canonical(rebuilt.results) !== canonical(card.results)) problems.push('results-differ-from-recomputation');
      if (canonical(rebuilt) !== canonical(card)) problems.push('card-differs-from-recomputation');
    }
    const valid = problems.length === 0;
    return { valid, problems, ...(valid ? { score: rebuilt.results.headline.score, cardDigest } : {}) };
  } catch { return { valid: false, problems: [...problems, 'unverifiable'] }; }
}

/**
 * Two cards are comparable only when they ran the same suite and evaluator. Distinguishable means the two 95 percent
 * item-sampling intervals do not overlap; it says nothing about validity or about repeat variance.
 */
export function compareScoreCards(a, b) {
  const va = verifyScoreCard(a), vb = verifyScoreCard(b), reasons = [];
  if (!va.valid || !vb.valid) return { comparable: false, reasons: ['card-invalid'], delta: null, distinguishable: null };
  if (a.manifest.suite.digest !== b.manifest.suite.digest) reasons.push('suite-digest-differs');
  if (a.manifest.evaluatorDigest !== b.manifest.evaluatorDigest) reasons.push('evaluator-digest-differs');
  if (reasons.length) return { comparable: false, reasons, delta: null, distinguishable: null };
  const x = a.results.headline, y = b.results.headline;
  return { comparable: true, reasons, delta: x.score - y.score, distinguishable: x.ci95.high < y.ci95.low || y.ci95.high < x.ci95.low };
}
