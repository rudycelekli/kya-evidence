import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mapTapToRequirements } from '../src/conformance-report/index.mjs';

const registry = { requirements: [
  { id: 'KYA-AAA-001', tests: [{ file: 'f', title: 'good' }] },
  { id: 'KYA-AAA-002', tests: [{ file: 'f', title: 'bad' }] }
] };
const mixed = [{ title: 'good', status: 'pass' }, { title: 'bad', status: 'fail' }];
const mapped = run => mapTapToRequirements(registry, { f: run });
function unknownWithFailure(run) {
  const r = mapped(run);
  assert.deepEqual(r['KYA-AAA-001'], { result: 'not-run', evidence: null, executed: [] });
  assert.deepEqual(r['KYA-AAA-002'], { result: 'fail', evidence: 'executed-test', executed: ['f :: bad'] });
}

test('a visible failing sibling cannot launder an invalid process outcome into pass', () => {
  for (const exitCode of [null, undefined, '1', NaN, Infinity, -1, 1.5]) unknownWithFailure({ exitCode, tests: mixed });
});

test('signal and runner errors withhold pass while preserving observed failures', () => {
  for (const run of [
    { exitCode: null, signal: 'SIGKILL', tests: mixed },
    { exitCode: 0, signal: 'SIGTERM', tests: mixed },
    { exitCode: 1, signal: 'SIGKILL', tests: mixed },
    { exitCode: 1, error: 'ETIMEDOUT', tests: mixed },
    { exitCode: 1, error: 'ENOBUFS', tests: mixed }
  ]) unknownWithFailure(run);
});

test('only an exact pass status can support a conformance pass', () => {
  for (const status of [undefined, null, '', 'unknown', 'PASS', true, 1]) {
    const r = mapped({ exitCode: 0, tests: [{ title: 'good', status }, mixed[1]] });
    assert.deepEqual(r['KYA-AAA-001'], { result: 'not-run', evidence: null, executed: [] });
    assert.equal(r['KYA-AAA-002'].result, 'fail');
  }
});

test('normal mixed runs retain failures and require exit zero for sibling pass credit', () => {
  for (const exitCode of [0]) {
    const r = mapped({ exitCode, tests: mixed });
    assert.deepEqual(r['KYA-AAA-001'], { result: 'pass', evidence: 'executed-test', executed: ['f :: good'] });
    assert.equal(r['KYA-AAA-002'].result, 'fail');
  }
  unknownWithFailure({ exitCode: 1, tests: mixed });
  assert.equal(mapped({ exitCode: 1, tests: [mixed[0]] })['KYA-AAA-001'].result, 'not-run');
  assert.equal(mapped({ exitCode: 0, tests: [{ title: 'good', status: 'skip' }] })['KYA-AAA-001'].result, 'not-run');
});

test('conformance CLI withholds pass after a real signal termination with a visible failed test', async () => {
  const root = await mkdtemp(join(tmpdir(), 'kya-tap-signal-'));
  try {
    for (const dir of ['evidence', 'docs', 'test']) await mkdir(join(root, dir));
    const tests = "import test from 'node:test';\ntest('good', () => {});\ntest('bad', () => { throw Error('fixture failure'); });\ntest('crash', async () => { await new Promise(resolve => setTimeout(resolve, 100)); process.kill(process.pid, 'SIGKILL'); });\n";
    await writeFile(join(root, 'test/f.test.mjs'), tests);
    await writeFile(join(root, 'docs/spec.md'), '## s\n');
    await writeFile(join(root, 'evidence/requirements.json'), JSON.stringify({ schema: 'kya.requirements/v1', specification: 'docs/spec.md', requirements: registry.requirements.map(r => ({ ...r, level: 'MUST', statement: 'A test MUST complete', area: 'conformance', section: 's', tests: r.tests.map(t => ({ ...t, file: 'test/f.test.mjs' })) })) }));
    const cli = fileURLToPath(new URL('../scripts/conformance-report.mjs', import.meta.url));
    const r = spawnSync(process.execPath, [cli, '--root', root, '--now', '2026-11-03T12:00:00.000Z'], { encoding: 'utf8', timeout: 15000 });
    assert.equal(r.status, 0, r.stderr);
    const report = JSON.parse(r.stdout);
    assert.equal(report.results.find(r => r.id === 'KYA-AAA-001').result, 'not-run');
    assert.equal(report.results.find(r => r.id === 'KYA-AAA-002').result, 'fail');
  } finally { await rm(root, { recursive: true, force: true }); }
});
