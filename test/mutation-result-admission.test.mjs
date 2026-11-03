import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const target = process.env.KYA_MUTATION_RESULT_MODULE
  ? pathToFileURL(process.env.KYA_MUTATION_RESULT_MODULE).href
  : new URL('../scripts/lib/mutation-result.mjs', import.meta.url).href;
const { admitMutationBaseline, admitMutationCandidate } = await import(target);
const footer = ({ tests = 2, suites = 0, pass = tests, fail = 0, cancelled = 0, skipped = 0, todo = 0 } = {}) =>
  `TAP version 13\nok 1 - synthetic assertion\n1..1\n# tests ${tests}\n# suites ${suites}\n# pass ${pass}\n# fail ${fail}\n# cancelled ${cancelled}\n# skipped ${skipped}\n# todo ${todo}\n# duration_ms 1.25\n`;
const processResult = (counts = {}, status = 0, stdout = footer(counts)) => ({ status, signal: null, stdout });
const base = () => admitMutationBaseline(processResult());

test('complete mutation runs accept all-pass baselines and distinguish observed kills from survivors', () => {
  const baseline = base();
  assert.equal(baseline.tests, 2);
  const killed = admitMutationCandidate(processResult({ pass: 1, fail: 1 }, 1), baseline);
  assert.equal(killed.killed, true);
  assert.equal(killed.counts.fail, 1);
  assert.equal(admitMutationCandidate(processResult(), baseline).killed, false);
});

test('mutation count admission refuses missing duplicate malformed and unsafe footer values', () => {
  const good = footer();
  for (const name of ['tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const line = good.split('\n').find(s => s.startsWith(`# ${name} `));
    for (const text of [good.replace(line + '\n', ''), good.replace(line, line + '\n' + line),
      ...['-1', '1.5', '01', '9007199254740992', 'NaN', '2 extra'].map(n => good.replace(line, `# ${name} ${n}`))]) {
      assert.throws(() => admitMutationBaseline(processResult({}, 0, text)), name);
      assert.throws(() => admitMutationCandidate(processResult({}, 1, text), base()), name);
    }
  }
});

test('mutation footer populations must reconcile tests with pass and fail counts', () => {
  for (const counts of [{ tests: 2, pass: 1 }, { tests: 2, pass: 3 }, { tests: 0, pass: 0 }])
    assert.throws(() => admitMutationBaseline(processResult(counts)));
  for (const counts of [{ tests: 2, pass: 0, fail: 1 }, { tests: 2, pass: 2, fail: 1 }])
    assert.throws(() => admitMutationCandidate(processResult(counts, 1), base()));
});

test('TODO skipped and cancelled cases cannot count as complete baselines or killed mutants', () => {
  for (const key of ['todo', 'skipped', 'cancelled']) {
    assert.throws(() => admitMutationBaseline(processResult({ pass: 1, [key]: 1 })));
    assert.throws(() => admitMutationCandidate(processResult({ pass: 0, fail: 1, [key]: 1 }, 1), base()));
  }
});

test('mutation process admission rejects errors signals and nonnumeric or unsafe exit statuses', () => {
  for (const extra of [{ error: new Error('synthetic failure') }, { signal: 'SIGTERM' }, { status: null },
    { status: '1' }, { status: true }, { status: -1 }, { status: 1.5 }, { status: Number.MAX_SAFE_INTEGER + 1 }]) {
    assert.throws(() => admitMutationBaseline({ ...processResult(), ...extra }));
    assert.throws(() => admitMutationCandidate({ ...processResult({ pass: 1, fail: 1 }, 1), ...extra }, base()));
  }
});

test('exit outcomes must agree with baseline and candidate assertion aggregates', () => {
  assert.throws(() => admitMutationBaseline(processResult({}, 1)));
  assert.throws(() => admitMutationBaseline(processResult({ pass: 1, fail: 1 }, 1)));
  assert.throws(() => admitMutationCandidate(processResult({ pass: 1, fail: 1 }, 0), base()));
  assert.throws(() => admitMutationCandidate(processResult({}, 1), base()));
});

test('aggregate counts must form one complete terminal Node TAP footer', () => {
  const good = footer();
  for (const text of [good.replace('# suites 0\n# pass 2', '# pass 2\n# suites 0'),
    good.replace('# duration_ms 1.25\n', ''), good + '# tests 2\n', good + 'ok 2 - late result\n',
    good.replace('# fail 0\n', '# fail 0\n\n')])
    assert.throws(() => admitMutationBaseline(processResult({}, 0, text)));
  const crlf = good.replaceAll('\n', '\r\n');
  assert.equal(admitMutationBaseline(processResult({}, 0, crlf)).tests, 2);
});

test('mutant aggregate population must match its admitted baseline without changing tests or suites', () => {
  assert.throws(() => admitMutationCandidate(processResult({ tests: 3, pass: 2, fail: 1 }, 1), base()));
  assert.throws(() => admitMutationCandidate(processResult({ suites: 1, pass: 1, fail: 1 }, 1), base()));
});

test('ordinary Node TAP diagnostic comments before the terminal counts remain admissible', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-mutation-diagnostic-'));
  try {
    const file = join(dir, 'diagnostic.test.mjs');
    writeFileSync(file, "import test from 'node:test';test('synthetic diagnostic',()=>console.log('tests are all ready'));\n");
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
    const p = spawnSync(process.execPath, ['--test', '--test-reporter=tap', file], { encoding: 'utf8', env, timeout: 10000 });
    assert.equal(p.status, 0, p.stderr);
    assert.match(p.stdout, /^# tests are all ready$/m);
    const result = admitMutationBaseline(p);
    assert.equal(result.tests, 1);
    assert.equal(result.pass, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
