import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { runVectors } from '../scripts/run-vectors.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const vectors = JSON.parse(await readFile(join(root, 'evidence/assessment-vectors.json'), 'utf8'));
const refusal = vectors.vectors.find(v => v.operation === 'assess' && v.expected.refused);
const positive = vectors.vectors.find(v => v.operation === 'assess' && !v.expected.refused);
async function fixture(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'kya-runner-gates-'));
  try {
    const file = join(dir, 'vectors.json'), impl = join(dir, 'impl.mjs');
    const run = async (body, cases = [refusal, positive], options = {}) => {
      await writeFile(file, JSON.stringify({ ...vectors, vectors: cases }));
      await writeFile(impl, 'for await (const _ of process.stdin) {}\n' + body);
      return runVectors({ impl: `"${process.execPath}" "${impl}"`, vectorsFile: file, root, timeoutMs: 10000, ...options });
    };
    await fn(run);
  } finally { await rm(dir, { recursive: true, force: true }); }
}

test('signal termination never earns refusal or requirement credit', async () => {
  await fixture(async run => {
    const r = await run("process.kill(process.pid, 'SIGKILL');");
    assert.equal(r.summary.vectors.pass, 0);
    assert.equal(r.summary.vectors.fail, 2);
    assert.ok(r.outcomes.every(o => /signal SIGKILL/.test(o.detail)));
    for (const id of refusal.requirements) assert.equal(r.report.results.find(r => r.id === id).result, 'fail');
  });
});

test('ordinary nonzero refusal stays a pass only for an expected refusal', async () => {
  await fixture(async run => {
    const r = await run('process.exit(3);');
    assert.deepEqual(r.outcomes.map(o => o.status), ['pass', 'fail']);
    const semantic = await run('process.exit(3);', [refusal], { semanticOnly: true });
    assert.equal(semantic.outcomes[0].status, 'semantic-pass');
    assert.equal(semantic.report.summary.pass, 0);
  });
});

test('unsupported replies require exactly three members and the requested operation', async () => {
  await fixture(async run => {
    const reply = { schema: 'kya.impl-result/v1', operation: 'assess', unsupported: true };
    for (const value of [
      { ...reply, operation: 'currency' },
      { schema: reply.schema, unsupported: true },
      { ...reply, decision: 'qualified' },
      { ...reply, unsupported: 'true' }
    ]) {
      const r = await run(`process.stdout.write(${JSON.stringify(JSON.stringify(value))});`, [positive]);
      assert.equal(r.outcomes[0].status, 'fail', JSON.stringify(value));
      assert.equal(r.summary.vectors.unsupported, 0);
    }
    const valid = await run(`process.stdout.write(${JSON.stringify(JSON.stringify(reply))});`, [positive]);
    assert.equal(valid.outcomes[0].status, 'unsupported');
    assert.equal(valid.report.summary.pass, 0);
    const newer = vectors.vectors.find(v => v.operation === 'canonicalize' && v.expected.refused);
    const exact = { ...reply, operation: newer.operation };
    const notRun = await run(`process.stdout.write(${JSON.stringify(JSON.stringify(exact))});`, [newer]);
    assert.equal(notRun.outcomes[0].status, 'unsupported');
  });
});

test('invalid execution budgets are rejected before starting an implementation', async () => {
  // Invalid vectorsFile proves option validation happens before reading inputs or spawning.
  for (const jobs of [0, -1, 1.5, NaN, Infinity, 17, '4']) {
    await assert.rejects(runVectors({ impl: 'unused', vectorsFile: 'missing', root, jobs }), /jobs must be an integer/);
  }
  for (const timeoutMs of [0, -1, 1.5, NaN, Infinity, 2147483648, '100']) {
    await assert.rejects(runVectors({ impl: 'unused', vectorsFile: 'missing', root, timeoutMs }), /timeoutMs must be an integer/);
  }
});

test('CLI refuses empty and invalid budgets with exit 2 and no conformance report', () => {
  for (const [flag, value] of [['--jobs', ''], ['--jobs', 'NaN'], ['--jobs', '0'], ['--timeout-ms', ''], ['--timeout-ms', 'Infinity'], ['--timeout-ms', '2147483648']]) {
    const r = spawnSync(process.execPath, [join(root, 'scripts/run-vectors.mjs'), '--impl', 'unused', flag, value], { encoding: 'utf8', timeout: 10000 });
    assert.equal(r.status, 2, `${flag} ${value}: ${r.stderr}`);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /must be an integer/);
  }
});
