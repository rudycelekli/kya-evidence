#!/usr/bin/env node
// Shared vector set for the two kya.score-card/v1 verifiers (ADR-0033). Valid cards are built by the JavaScript builder;
// tamper vectors edit a valid card and, where the class says so, recompute digests so that only recomputation can catch them.
// `expectValid` is stated here from the intent of each vector, not read from either verifier.
//   node scripts/score-vectors.mjs          write interop/score-verifier/vectors.json
//   node scripts/score-vectors.mjs --check  fail if the file differs from what this script generates
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { digest, hashBytes } from '../src/shared/canonical.mjs';
import { buildScoreCard } from '../src/kya-score/index.mjs';
import { isMain } from './lib/is-main.mjs';

export const VECTOR_FILE = fileURLToPath(new URL('../interop/score-verifier/vectors.json', import.meta.url));
const HEX = c => hashBytes('kya-score-vector-' + c);
const clone = v => structuredClone(v);
const reseal = card => { const { cardDigest, ...body } = card; card.cardDigest = digest(body); return card; };
const resealAll = card => { card.runDigest = digest(card.runs); return reseal(card); };

function runsOf({ n = 40, repeats = 3, heldOut = 12, rule = i => (i % 5 === 0 ? 'fail' : 'pass'), idOf = i => 'item-' + String(i).padStart(3, '0'), cost = i => 0.01, dur = i => 10 + i } = {}) {
  return Array.from({ length: repeats }, (_, r) => ({ runId: 'run-' + r, items: Array.from({ length: n }, (_, i) => ({ id: idOf(i), outcome: rule(i, r), heldOut: i < heldOut, durationMs: dur(i), costUsd: cost(i, r) })) }));
}
function manifestOf(over = {}) {
  return { subject: { id: 'subject:vector', version: '1', digest: HEX('subject') }, suite: { id: 'vector-suite', version: '1', digest: HEX('suite') }, evaluatorDigest: HEX('evaluator'), judge: null, holdoutCommitment: HEX('holdout'), environment: { runtime: 'vector-runtime', offlineDeclared: true }, bootstrap: { seed: 'vector-seed', resamples: 1000 }, ...over };
}
const card = (runs = runsOf(), manifest = manifestOf(), options) => buildScoreCard({ manifest, runs, ...(options ? { options } : {}) });
// A pass rate that varies per item and per repeat, so the interval is not on a coarse grid.
const mixed = (i, r) => ((i * 7 + r * 3) % 11 < 3 ? 'fail' : (i * 5 + r) % 13 === 0 ? 'abstain' : (i + r * 2) % 17 === 0 ? 'error' : 'pass');

export function buildVectors() {
  const v = [];
  const add = (id, cls, expectValid, value) => v.push({ id, class: cls, expectValid, card: value });
  const base = () => clone(card());

  add('valid-baseline', 'valid', true, card());
  add('valid-minimum-floor', 'valid', true, card(runsOf({ n: 30, heldOut: 10 })));
  add('valid-mixed-outcomes-and-items', 'valid', true, card(runsOf({ n: 53, heldOut: 17, repeats: 5, rule: mixed })));
  add('valid-all-items-held-out', 'valid', true, card(runsOf({ n: 30, heldOut: 30, rule: mixed })));
  add('valid-fractional-cost-and-duration', 'valid', true, card(runsOf({ n: 36, heldOut: 11, rule: mixed, cost: (i, r) => 0.001234567 * (i + 1) + r / 7, dur: i => 12.34567 + i / 3 })));
  add('valid-cost-unknown-for-one-item', 'valid', true, card(runsOf({ n: 33, heldOut: 10, rule: mixed, cost: (i, r) => (i === 4 && r === 1 ? null : 0.02) })));
  add('valid-judge-recorded', 'valid', true, card(runsOf({ rule: mixed }), manifestOf({ judge: { id: 'judge:panel', digest: HEX('judge') } })));
  add('valid-non-ascii-seed', 'valid', true, card(runsOf({ rule: mixed }), manifestOf({ bootstrap: { seed: 'seed-é世', resamples: 500 } })));
  add('valid-minimum-resamples', 'valid', true, card(runsOf({ rule: mixed }), manifestOf({ bootstrap: { seed: 'low', resamples: 100 } })));
  add('valid-large-resamples', 'valid', true, card(runsOf({ n: 30, heldOut: 10, rule: mixed }), manifestOf({ bootstrap: { seed: 'big', resamples: 20000 } })));
  add('valid-odd-resamples', 'valid', true, card(runsOf({ rule: mixed }), manifestOf({ bootstrap: { seed: 'odd', resamples: 1001 } })));
  add('valid-ids-sort-by-code-unit', 'valid', true, card(runsOf({ n: 32, heldOut: 10, rule: mixed, idOf: i => (i % 2 ? 'b' : 'B') + '.' + i + (i % 3 ? '_x' : '-y') })));
  add('valid-raised-floor', 'valid', true, card(runsOf({ n: 60, heldOut: 20, repeats: 4 }), manifestOf(), { floor: { minItems: 50, minRepeats: 4 } }));
  add('valid-canary-exposures', 'valid', true, (() => { const r = runsOf({ rule: mixed }); r[0].items[2].canaryExposed = true; r[1].items[2].canaryExposed = true; return card(r); })());
  add('valid-unstable-items', 'valid', true, card(runsOf({ rule: (i, r) => ((i + r) % 4 === 0 ? 'fail' : 'pass') })));
  add('valid-items-given-out-of-order', 'valid', true, (() => { const r = runsOf({ rule: mixed }); r[1].items.reverse(); return card(r); })());

  let c = base(); c.results.headline.score = 990; add('tamper-headline-score-resealed', 'tamper', false, resealAll(c));
  c = base(); c.results.headline.ci95.high = 1000; add('tamper-interval-resealed', 'tamper', false, resealAll(c));
  c = base(); c.results.heldOut.score = 999; add('tamper-heldout-score-resealed', 'tamper', false, resealAll(c));
  c = base(); c.results.cost.totalUsd = 0; add('tamper-cost-resealed', 'tamper', false, resealAll(c));
  c = base(); c.results.repeatVariance.sd = 1; add('tamper-variance-resealed', 'tamper', false, resealAll(c));
  c = base(); c.runs[0].items[0].outcome = 'pass'; add('tamper-outcome-stale-run-digest', 'tamper', false, reseal(c));
  c = base(); c.runs[0].items[0].outcome = 'pass'; add('tamper-outcome-digests-recomputed', 'tamper', false, resealAll(c));
  c = base(); c.runs[0].items[0].heldOut = !c.runs[0].items[0].heldOut; add('tamper-heldout-flag-one-run-resealed', 'tamper', false, resealAll(c));
  c = base(); c.runs[0].items[3].durationMs += 1; add('tamper-duration-resealed', 'tamper', false, resealAll(c));
  c = base(); c.runs[1].items.reverse(); add('tamper-item-order-resealed', 'tamper', false, resealAll(c));
  c = base(); delete c.runs[0].items[0].canaryExposed; add('tamper-missing-canary-flag-resealed', 'tamper', false, resealAll(c));
  c = base(); c.manifest.subject.version = '2'; add('tamper-manifest-stale-digest', 'tamper', false, c);
  c = base(); c.manifest.bootstrap.seed = 'other-seed'; add('tamper-seed-resealed', 'tamper', false, resealAll(c));
  c = base(); c.manifest.bootstrap.resamples = 1001; add('tamper-resamples-resealed', 'tamper', false, resealAll(c));
  c = base(); c.manifest.holdoutCommitment = null; add('tamper-holdout-commitment-removed-resealed', 'tamper', false, resealAll(c));
  // Operator statements: no computation reads these, so a re-sealed edit is indistinguishable from an honest build (ADR-0033 item 8).
  c = base(); c.manifest.subject.version = '2'; add('operator-statement-subject-version-resealed', 'operator-statement', true, resealAll(c));
  c = base(); c.manifest.judge = { id: 'judge:added', digest: HEX('judge-added') }; add('operator-statement-judge-added-resealed', 'operator-statement', true, resealAll(c));
  c = base(); c.manifest.environment.offlineDeclared = false; add('operator-statement-offline-flag-resealed', 'operator-statement', true, resealAll(c));
  c = base(); c.manifest.evaluatorDigest = HEX('other-evaluator'); add('operator-statement-evaluator-digest-resealed', 'operator-statement', true, resealAll(c));
  c = base(); c.manifest.holdoutCommitment = HEX('other-holdout'); add('operator-statement-holdout-value-resealed', 'operator-statement', true, resealAll(c));
  c = base(); c.nonClaims.pop(); add('tamper-nonclaim-dropped-resealed', 'tamper', false, resealAll(c));
  c = base(); c.nonClaims.reverse(); add('tamper-nonclaims-reordered-resealed', 'tamper', false, resealAll(c));
  c = base(); c.nonClaims.push('NOT_PREDICTIVE_VALIDITY'); add('tamper-nonclaim-added-resealed', 'tamper', false, resealAll(c));
  c = base(); c.floor.minItems = 1; add('tamper-floor-lowered-resealed', 'tamper', false, resealAll(c));
  c = base(); c.floor.minItems = 500; add('tamper-floor-raised-above-evidence-resealed', 'tamper', false, resealAll(c));
  c = base(); c.floor.extra = 1; add('tamper-floor-extra-field-resealed', 'tamper', false, resealAll(c));
  c = base(); c.runs = c.runs.slice(0, 2); add('tamper-too-few-repeats-resealed', 'tamper', false, resealAll(c));
  c = base(); c.runs.forEach(r => { r.items = r.items.slice(0, 20); }); add('tamper-too-few-items-resealed', 'tamper', false, resealAll(c));
  c = base(); c.label = 'KYA-SCR-CERTIFIED'; add('tamper-label-resealed', 'tamper', false, resealAll(c));
  c = base(); c.extra = true; add('tamper-unknown-field-resealed', 'tamper', false, resealAll(c));
  c = base(); delete c.floor; add('tamper-missing-field-resealed', 'tamper', false, resealAll(c));
  c = base(); c.schema = 'kya.score-card/v2'; add('tamper-wrong-schema-resealed', 'tamper', false, resealAll(c));
  c = base(); c.runs[2].runId = 'run-0'; add('tamper-duplicate-run-id-resealed', 'tamper', false, resealAll(c));
  c = base(); c.runs[0].items[1].id = c.runs[0].items[0].id; add('tamper-duplicate-item-id-resealed', 'tamper', false, resealAll(c));
  c = base(); c.runs[0].items[0].outcome = 'maybe'; add('tamper-unknown-outcome-resealed', 'tamper', false, resealAll(c));
  c = base(); c.results.publicMinusHeldOut += 1; add('tamper-gap-resealed', 'tamper', false, resealAll(c));
  add('malformed-null', 'malformed', false, null);
  add('malformed-text', 'malformed', false, 'text');
  add('malformed-array', 'malformed', false, []);
  add('malformed-empty-object', 'malformed', false, {});
  return v;
}

export function renderVectorFile() {
  const head = JSON.stringify({ schema: 'kya.score-vectors/v1', note: 'Expected validity is stated by intent. Built with the JavaScript builder; both verifiers must agree with it. Same-team vectors, not external review.' });
  return head.slice(0, -1) + ',"vectors":[\n' + buildVectors().map(x => JSON.stringify(x)).join(',\n') + '\n]}\n';
}

if (isMain(import.meta.url)) {
  const text = renderVectorFile();
  if (process.argv[2] === '--check') {
    if ((await readFile(VECTOR_FILE, 'utf8').catch(() => '')) !== text) { console.error('score vectors are out of date; run node scripts/score-vectors.mjs'); process.exitCode = 1; }
  } else await writeFile(VECTOR_FILE, text);
}
