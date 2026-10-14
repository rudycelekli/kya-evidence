import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, readdir, rm, stat, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { digest, verifyDossier, verifyBenchmarkRun, BENCHMARK_CATALOG } from '../src/index.mjs';

const bin = fileURLToPath(new URL('../bin/kya.mjs', import.meta.url));
const NOW = '2026-10-14T02:00:00.000Z';
let directory, fixtureDirectory, benchDirectory, inputs, observations, dossier, benchmark;
const cli = args => spawnSync(process.execPath, [bin, ...args], {
  cwd: directory, shell: false, encoding: 'utf8', timeout: 15_000, maxBuffer: 2_097_152,
  env: { PATH: '/usr/bin:/bin' },
});
function succeeds(result) { assert.ifError(result.error); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr); return JSON.parse(result.stdout); }
function rejects(result, reason) { assert.ifError(result.error); assert.equal(result.signal, null); assert.equal(result.status, 1); assert.match(result.stderr, reason); }
const json = async path => JSON.parse(await readFile(path, 'utf8'));
async function save(name, value) { const path = join(directory, name); await writeFile(path, JSON.stringify(value), { mode: 0o600 }); return path; }
function reseal(value, field) { const body = { ...value }; delete body[field]; value[field] = digest(body); return value; }
const dossierArgs = out => ['dossier', '--inputs', join(fixtureDirectory, 'inputs.json'), '--observations', join(fixtureDirectory, 'observations.json'), '--out', out];
const verifyArgs = file => ['dossier-verify', '--dossier', file, '--inputs', join(fixtureDirectory, 'inputs.json'), '--observations', join(fixtureDirectory, 'observations.json')];

before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kya-alpha3-cli-'));
  // One benchmark execution supplies every command test; no protected/private
  // workspace or Git checkout is needed for this test's temporary output.
  fixtureDirectory = join(directory, 'diagnose'); benchDirectory = join(directory, 'bench');
  succeeds(cli(['diagnose', '--mode', 'careful', '--out', fixtureDirectory]));
  succeeds(cli(['bench', '--now', NOW, '--out', benchDirectory]));
  inputs = await json(join(fixtureDirectory, 'inputs.json'));
  observations = await json(join(fixtureDirectory, 'observations.json'));
  dossier = await json(join(fixtureDirectory, 'dossier.json'));
  benchmark = await json(join(benchDirectory, 'benchmark-run.json'));
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

test('diagnose exports fixed receipt-bound originals and dossier-verify replays them from a different cwd', () => {
  assert.equal(dossier.assessment.decision, 'qualified'); assert.equal(dossier.assessment.evidenceMode, 'fixture');
  assert.equal(observations.length, 18); assert.equal(dossier.strengths.length, 18);
  assert.equal(dossier.observations.verifiedOriginals, 18); assert.equal(dossier.observations.structuredReplays, 18);
  assert.equal(dossier.assurance.actualEffectsVerified, false); assert.equal(dossier.assurance.captureComplete, false);
  assert.equal(dossier.measurements.cost.reportedTotalUsd, null);
  const result = succeeds(cli(verifyArgs(join(fixtureDirectory, 'dossier.json'))));
  assert.deepEqual(result, verifyDossier(dossier, { inputs, observations }));
  assert.equal(result.authenticated, false); assert.equal(result.replayMatched, true);
});

test('dossier command reproduces the exact diagnosis from saved inputs/originals and refuses overwrite', async () => {
  const out = join(directory, 'replayed-dossier'); const result = succeeds(cli(dossierArgs(out)));
  assert.equal(result.dossierDigest, dossier.dossierDigest);
  assert.deepEqual(await json(join(out, 'dossier.json')), dossier);
  assert.equal(await readFile(join(out, 'dossier.md'), 'utf8'), await readFile(join(fixtureDirectory, 'dossier.md'), 'utf8'));
  rejects(cli(dossierArgs(out)), /EEXIST/);
});

test('bench exports the full frozen catalog and bench-verify checks exact inputs with unknown costs', async () => {
  assert.deepEqual(await json(join(benchDirectory, 'benchmark-catalog.json')), BENCHMARK_CATALOG);
  assert.equal(benchmark.now, NOW); assert.equal(benchmark.fixtureOnly, true); assert.equal(benchmark.commercialRuntimesMeasured, false);
  assert.equal(benchmark.summary.total, BENCHMARK_CATALOG.cases.length); assert.equal(benchmark.summary.allPassed, true);
  assert(benchmark.cases.every(item => item.costUsd === null && item.source === 'fixture'));
  const result = succeeds(cli(['bench-verify', join(benchDirectory, 'benchmark-run.json')]));
  assert.deepEqual(result, verifyBenchmarkRun(benchmark)); assert.equal(result.authenticated, false); assert.equal(result.passed, true);
});

test('a verified benchmark can be attached without becoming agent quality or runtime coverage', async () => {
  const out = join(directory, 'attached-dossier'), file = join(benchDirectory, 'benchmark-run.json');
  succeeds(cli([...dossierArgs(out), '--benchmarks', file]));
  const attached = await json(join(out, 'dossier.json'));
  assert.deepEqual(attached.assessment, dossier.assessment); assert.deepEqual(attached.strengths, dossier.strengths);
  assert.equal(attached.benchmarks.length, 1); assert.equal(attached.benchmarks[0].executionAuthenticated, false);
  assert.equal(attached.benchmarks[0].commercialRuntimesMeasured, false);
  assert.equal(succeeds(cli([...verifyArgs(join(out, 'dossier.json')), '--benchmarks', file])).replayMatched, true);
  rejects(cli(verifyArgs(join(out, 'dossier.json'))), /does not replay/);
});

test('tampered originals and resealed narrative cannot survive CLI dossier replay', async () => {
  const modified = structuredClone(observations); modified[0].requestDigest = '0'.repeat(64);
  const originalFile = await save('tampered-originals.json', modified);
  const args = verifyArgs(join(fixtureDirectory, 'dossier.json')); args[args.indexOf('--observations') + 1] = originalFile;
  rejects(cli(args), /does not replay/);
  const forged = structuredClone(dossier); forged.assurance.actualEffectsVerified = true; reseal(forged, 'dossierDigest');
  rejects(cli(verifyArgs(await save('forged-dossier.json', forged))), /Unsupported assurance claim/);
  const hashOnly = structuredClone(dossier); hashOnly.inputsDigest = 'a'.repeat(64);
  rejects(cli(verifyArgs(await save('unsealed-dossier.json', hashOnly))), /Dossier digest differs/);
});

test('malformed, duplicate-member and oversized JSON are rejected before dossier rendering', async () => {
  const path = join(directory, 'bad-inputs.json');
  for (const [text, reason] of [['{broken', /Expected JSON member/], ['{"inputs":1,"inputs":2}', /Duplicate/], [' '.repeat(1_048_577), /bounded regular JSON file/]]) {
    await writeFile(path, text);
    rejects(cli(['dossier', '--inputs', path, '--out', join(directory, 'bad-output')]), reason);
  }
  const nullFile = await save('null-observations.json', null);
  const args = dossierArgs(join(directory, 'null-output')); args[args.indexOf('--observations') + 1] = nullFile;
  rejects(cli(args), /Observation population limit/);
});

test('a resealed omitted-case or altered-expectation benchmark is rejected both directly and as an attachment', async () => {
  for (const [name, mutate, reason] of [
    ['omission', value => { value.cases.pop(); }, /population differs/],
    ['expected', value => { value.cases[0].expected.coverage = 0; }, /expected contract differs/],
    ['status', value => { value.cases[0].actual.decision = 'blocked'; }, /actual contract differs/],
  ]) {
    const value = structuredClone(benchmark); mutate(value); reseal(value, 'runDigest');
    const file = await save(`bad-benchmark-${name}.json`, value);
    rejects(cli(['bench-verify', file]), reason);
    rejects(cli([...dossierArgs(join(directory, `bad-attachment-${name}`)), '--benchmarks', file]), reason);
  }
});

test('bench-verify reports a retained execution error with CI exit 2 instead of accepting a pass', async () => {
  const value = structuredClone(benchmark);
  Object.assign(value.cases[0], { outcome: 'error', actual: null, inputs: null, inputDigest: null, assessment: null, artifactDigest: null, error: 'BENCHMARK_EXECUTION_ERROR' });
  value.evidenceInputDigest = digest(value.cases.map(item => item.inputDigest));
  value.summary = { total: 16, possible: 16, passed: 15, failed: 0, errors: 1, allPassed: false }; reseal(value, 'runDigest');
  const result = cli(['bench-verify', await save('error-benchmark.json', value)]);
  assert.ifError(result.error); assert.equal(result.status, 2); assert.equal(result.stderr, '');
  const verified = JSON.parse(result.stdout); assert.equal(verified.passed, false); assert.equal(verified.replayMatched, false); assert.equal(verified.authenticated, false);
});

test('input symlinks and unrecognized execution options are refused', async () => {
  const link = join(directory, 'linked-inputs.json'); await symlink(join(fixtureDirectory, 'inputs.json'), link);
  rejects(cli(['dossier', '--inputs', link, '--out', join(directory, 'symlink-output')]), /bounded regular JSON file/);
  rejects(cli(['diagnose', '--mode', 'live', '--out', join(directory, 'live-output')]), /Unsupported fixture/);
  rejects(cli(['diagnose', '--with-benchmarks', 'yes', '--out', join(directory, 'option-output')]), /Unsupported fixture/);
  rejects(cli(['bench', '--cases', 'positive', '--out', join(directory, 'subset-output')]), /Unknown flag/);
  rejects(cli(['bench-verify', join(benchDirectory, 'benchmark-run.json'), '--skip-gates', 'true']), /Unknown flag/);
});

test('dossier and benchmark exports contain public proofs but no signing private key or provider token', async () => {
  for (const out of [fixtureDirectory, benchDirectory]) {
    const files = await readdir(out); assert(!files.some(name => /private|secret|\.pem$/i.test(name)));
    for (const name of files) {
      const path = join(out, name), bytes = await readFile(path, 'utf8');
      assert.doesNotMatch(bytes, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"privateKey"\s*:|"privatePem"\s*:|"(?:OPENAI_API_KEY|ANTHROPIC_API_KEY)"\s*:|sk-(?:proj-)?[A-Za-z0-9]{24,}/);
      if (process.platform !== 'win32') assert.equal((await stat(path)).mode & 0o777, 0o600);
    }
  }
  assert(inputs.evidence.every(envelope => envelope.proof.publicKey.includes('BEGIN PUBLIC KEY')));
});
