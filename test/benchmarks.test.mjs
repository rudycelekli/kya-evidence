import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, readFile, writeFile, rm, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { BENCHMARK_CATALOG, CATALOG_DIGEST, runOfflineBenchmarks, verifyBenchmarkRun } from '../src/benchmarks/index.mjs';
import { CORE_PROFILE, EVALUATOR_DIGEST } from '../src/conformance/index.mjs';
import { canonical, digest, hashBytes } from '../src/shared/canonical.mjs';
import { assess } from '../src/assessment/index.mjs';

const NOW = '2026-10-14T02:00:00.000Z';
const run = await runOfflineBenchmarks({ now: NOW });
const clone = value => structuredClone(value);
function reseal(value) { const { runDigest, ...body } = value; value.runDigest = digest(body); return value; }

test('catalog is deeply frozen and covers four full behavioral suites and twelve admission controls', () => {
  assert.equal(BENCHMARK_CATALOG.schema, 'kya.benchmark-catalog/v1');
  assert.equal(BENCHMARK_CATALOG.version, 1);
  assert.equal(BENCHMARK_CATALOG.evaluatorDigest, EVALUATOR_DIGEST);
  assert.equal(CATALOG_DIGEST, digest(BENCHMARK_CATALOG));
  assert.equal(BENCHMARK_CATALOG.cases.length, 16);
  assert.equal(BENCHMARK_CATALOG.suites[0].caseIds.length, 4);
  for (const suite of BENCHMARK_CATALOG.suites) assert.deepEqual(suite.checkPopulation, CORE_PROFILE.checks.map(c => c.id));
  assert.throws(() => BENCHMARK_CATALOG.cases.pop());
  assert.throws(() => { BENCHMARK_CATALOG.cases[0].expected.checkStatuses[0].status = 'unknown'; });
});

test('complete offline controls execute with unknown cost, measured duration and no commercial claims', () => {
  assert.deepEqual(run.summary, { total: 16, possible: 16, passed: 16, failed: 0, errors: 0, allPassed: true });
  assert.equal(run.fixtureOnly, true); assert.equal(run.commercialRuntimesMeasured, false); assert.equal(run.newProviderCalls, 0);
  assert.equal(run.evidenceInputDigest, digest(run.cases.map(c => c.inputDigest)));
  for (const item of run.cases) {
    assert.equal(item.source, 'fixture'); assert.equal(item.costUsd, null); assert(item.durationMs >= 0);
    assert.equal(item.inputDigest, digest(item.inputs)); assert.equal(item.artifactDigest, item.assessment.reportDigest);
    assert.equal(item.inputs.profile.checks.length, 18); assert.equal(item.assessment.score.possible, 1000);
  }
  const critical = run.cases.find(c => c.id === 'integrity.critical-failure');
  assert.equal(critical.assessment.score.earned, 944); assert.equal(critical.actual.decision, 'blocked');
  const revoked = run.cases.find(c => c.id === 'integrity.revoked-newer-failure');
  assert.equal(revoked.actual.coverage, 0); assert.equal(revoked.assessment.selectedRunId, 'fixture:newer-run');
  assert(Object.isFrozen(run.cases[0].inputs.evidence[0].payload));
  assert.deepEqual(verifyBenchmarkRun(run), { integrity: true, replayMatched: true, passed: true, runDigest: run.runDigest, catalogDigest: CATALOG_DIGEST, assessorSourceDigest: run.assessorSourceDigest, authenticated: false });
});

test('options require explicit canonical time and refuse arbitrary subsets or authority overrides', async () => {
  for (const options of [undefined, {}, { now: NOW, cases: [] }, { now: NOW, assessor: 'other' }, { now: '2026-10-14' }, { now: '0000-01-01T00:00:00.000Z' }]) await assert.rejects(runOfflineBenchmarks(options));
  const getter = {}; Object.defineProperty(getter, 'now', { enumerable: true, get() { throw Error('must not execute'); } });
  await assert.rejects(runOfflineBenchmarks(getter), /accessor/i);
});

test('verifier rejects hash tampering and resealed expected-contract, ordering, population and implementation edits', () => {
  const attacks = [
    [value => { value.cases[0].actual.coverage = 0; }, false],
    [value => { value.cases[0].expected.decision = 'blocked'; }, true],
    [value => { value.cases.pop(); }, true],
    [value => { value.cases.reverse(); }, true],
    [value => { value.cases[0].id = value.cases[1].id; }, true],
    [value => { value.catalogDigest = hashBytes('other'); }, true],
    [value => { value.assessorSourceDigest = hashBytes('other'); }, true],
    [value => { value.evaluatorDigest = hashBytes('other'); }, true],
    [value => { value.summary.possible = 15; }, true],
    [value => { value.summary.passed = 99; }, true],
    [value => { value.cases[0].costUsd = 0; }, true],
    [value => { value.cases[0].durationMs = -1; }, true],
    [value => { value.newProviderCalls = 1; }, true],
    [value => { value.limitations = []; }, true],
    [value => { value.extra = 'ignored'; }, true],
  ];
  for (const [attack, rehash] of attacks) { const value = clone(run); attack(value); if (rehash) reseal(value); assert.throws(() => verifyBenchmarkRun(value)); }
});

test('forged passing report cannot survive input-bound assessment replay', () => {
  const value = clone(run), item = value.cases.find(c => c.id === 'integrity.critical-failure');
  item.assessment.decision = 'qualified';
  const { reportDigest, ...body } = item.assessment;
  item.assessment.reportDigest = digest(body); item.artifactDigest = item.assessment.reportDigest;
  item.actual.decision = 'qualified'; item.outcome = 'pass'; reseal(value);
  assert.throws(() => verifyBenchmarkRun(value), /replay/);
});

test('even a replayable matching outcome cannot substitute a different policy for the frozen challenge', () => {
  const value = clone(run), item = value.cases.find(c => c.id === 'integrity.positive');
  item.inputs.policy.minScore = 0;
  item.inputDigest = digest(item.inputs); item.assessment = assess(item.inputs); item.artifactDigest = item.assessment.reportDigest;
  assert.equal(item.actual.decision, item.assessment.decision); assert.equal(item.actual.coverage, item.assessment.coverage);
  value.evidenceInputDigest = digest(value.cases.map(c => c.inputDigest)); reseal(value);
  assert.throws(() => verifyBenchmarkRun(value), /challenge inputs/);
});

test('error remains in population and never passes; relabeling or summary laundering is rejected', () => {
  const value = clone(run), item = value.cases[0];
  Object.assign(item, { outcome: 'error', actual: null, inputs: null, inputDigest: null, assessment: null, artifactDigest: null, error: 'BENCHMARK_EXECUTION_ERROR' });
  value.evidenceInputDigest = digest(value.cases.map(c => c.inputDigest));
  value.summary = { total: 16, possible: 16, passed: 15, failed: 0, errors: 1, allPassed: false }; reseal(value);
  const verification = verifyBenchmarkRun(value); assert.equal(verification.passed, false); assert.equal(verification.replayMatched, false);
  const laundered = clone(value); laundered.cases[0].outcome = 'pass'; laundered.summary = clone(run.summary); reseal(laundered);
  assert.throws(() => verifyBenchmarkRun(laundered));
  const summaryOnly = clone(value); summaryOnly.summary = clone(run.summary); reseal(summaryOnly); assert.throws(() => verifyBenchmarkRun(summaryOnly));
});

test('repeated runs preserve catalog/expected population while ephemeral keys and run IDs change', async () => {
  const next = await runOfflineBenchmarks({ now: NOW });
  assert.equal(next.catalogDigest, run.catalogDigest); assert.deepEqual(next.cases.map(c => c.expected), run.cases.map(c => c.expected));
  assert.deepEqual(next.summary, run.summary); assert.notEqual(next.evidenceInputDigest, run.evidenceInputDigest);
  assert.equal(verifyBenchmarkRun(next).passed, true);
});

test('frozen controls detect six actual assessor gate mutations, with identical complete populations', { timeout: 120_000 }, async () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const sourcePath = 'src/assessment/application/assess.mjs', original = await readFile(join(root, sourcePath), 'utf8');
  const mutations = [
    ['trust-anchor bypass', "const k = trusted.get(e.keyId);", "const k = trusted.get(e.keyId) ?? {role:'self'};", 'integrity.untrusted-key'],
    ['signature bypass', 'const e = verifyEvidence(capturedEvidence[index].data); p = e.payload;', 'const raw = capturedEvidence[index].data; const e = {payload:raw.payload,keyId:raw.proof.keyId,envelopeDigest:digest(raw)}; p = e.payload;', 'integrity.signature-tamper'],
    ['revoked key bypass', "insist(!policy.revokedKeyIds.includes(e.keyId),'Signing key is revoked');", '/* owned mutation skips key revocation */', 'integrity.revoked-key'],
    ['declaration promotion', "insist(p.source !== 'declaration','A declaration cannot satisfy an observed check');", '/* owned mutation permits declarations */', 'integrity.declaration-laundering'],
    ['critical gate removal', "const criticalFailures = checks.filter(c=>c.critical && c.status==='fail');", 'const criticalFailures = [];', 'integrity.critical-failure'],
    ['revoked failure fallback', 'for (const e of bound) {\n    const id = e.payload.runId;', 'for (const e of unique) {\n    const id = e.payload.runId;', 'integrity.revoked-newer-failure'],
  ];
  const privateRoot = join(root, '.private', 'benchmark-mutation-tests'); await mkdir(privateRoot, { recursive: true });
  function execute(dir) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', `import {runOfflineBenchmarks} from './src/benchmarks/index.mjs'; const run=await runOfflineBenchmarks({now:'${NOW}'}); console.log(JSON.stringify({summary:run.summary,cases:run.cases.map(c=>({id:c.id,outcome:c.outcome,error:c.error}))}));`], { cwd: dir, shell: false, encoding: 'utf8', timeout: 10_000, maxBuffer: 100_000, env: { PATH: '/usr/bin:/bin' } });
    assert.ifError(result.error); assert.equal(result.signal, null); assert.equal(result.status, 0, 'child must execute; crashes are not defect detection');
    return JSON.parse(result.stdout);
  }
  const receipts = [];
  for (const [name, from, to, caseId] of mutations) {
    assert(original.includes(from), `mutation anchor exists: ${name}`);
    const dir = await mkdtemp(join(privateRoot, 'owned-copy-'));
    try {
      await cp(join(root, 'src'), join(dir, 'src'), { recursive: true }); await cp(join(root, 'profiles'), join(dir, 'profiles'), { recursive: true }); await cp(join(root, 'package.json'), join(dir, 'package.json'));
      const baseline = execute(dir); assert.equal(baseline.summary.allPassed, true); assert.equal(baseline.summary.total, 16);
      const mutated = original.replace(from, to); await writeFile(join(dir, sourcePath), mutated);
      const candidate = execute(dir); assert.equal(candidate.summary.total, baseline.summary.total); assert.equal(candidate.summary.errors, 0); assert.equal(candidate.cases.length, 16);
      assert.equal(candidate.cases.find(c => c.id === 'integrity.positive').outcome, 'pass', 'positive control must remain executable');
      assert.equal(candidate.cases.find(c => c.id === caseId).outcome, 'fail', `frozen case must detect ${name}`);
      assert.equal(candidate.summary.allPassed, false);
      receipts.push({ name, caseId, baselinePassed: 16, candidateFailed: candidate.summary.failed, candidateErrors: candidate.summary.errors, mutantSourceDigest: hashBytes(mutated), detected: true });
    } finally { await rm(dir, { recursive: true, force: true }); }
  }
  console.log(JSON.stringify({ schema: 'kya.benchmark-mutation-controls/v1', baselineSourceDigest: hashBytes(original), controls: receipts, allDetected: true, limitation: 'Six targeted owned source mutations; not exhaustive safety validation.' }));
});
