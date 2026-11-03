import { mkdtemp, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const root = fileURLToPath(new URL('../', import.meta.url));
const target = 'scripts/run-vectors.mjs';
const original = await readFile(join(root, target), 'utf8');
const signalGate = "  if (r.signal) return { status: 'fail', detail: `implementation terminated by signal ${r.signal}` };\n";
const refusalGate = 'Number.isInteger(r.code) && r.code !== 0 && !r.signal';
const jobsGate = "  if (!Number.isSafeInteger(jobs) || jobs < 1 || jobs > 16) throw Error('jobs must be an integer from 1 to 16');\n";
const timeoutGate = "  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) throw Error('timeoutMs must be an integer from 1 to 2147483647');\n";
const controls = [
  { name: 'signal termination earns refusal credit', edits: [[signalGate, ''], [refusalGate, 'r.code !== 0 || r.signal']] },
  { name: 'unsupported reply admits wrong operation and extra members', edits: [["    Object.keys(reply).length === 3 && reply.schema === 'kya.impl-result/v1' &&\n    reply.operation === operation && reply.unsupported === true;", "    reply.schema === 'kya.impl-result/v1' && reply.unsupported === true;"]] },
  { name: 'invalid worker budget accepted', edits: [[jobsGate, '']] },
  { name: 'invalid timeout budget accepted', edits: [[timeoutGate, '']] }
];
const hash = s => createHash('sha256').update(s).digest('hex');
const dir = await mkdtemp(join(tmpdir(), 'kya-runner-mutations-'));
function run() {
  const p = spawnSync(process.execPath, ['--test', '--test-reporter=tap', 'test/vector-runner-gates.test.mjs'], { cwd: dir, encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  const count = k => Number(new RegExp(`^# ${k} (\\d+)$`, 'm').exec(p.stdout)?.[1] ?? NaN);
  if (p.error || p.signal || count('tests') !== 5 || count('cancelled') !== 0 || count('skipped') !== 0 || count('todo') !== 0) throw Error('Incomplete gate test execution: ' + p.stdout.slice(-5000) + p.stderr.slice(-1000));
  return { exitCode: p.status, tests: count('tests'), pass: count('pass'), fail: count('fail'), failedTests: [...p.stdout.matchAll(/^not ok \d+ - (.+)$/gm)].map(m => m[1]) };
}
try {
  for (const path of ['src', 'scripts', 'evidence', 'test', 'profiles', 'policies', 'suites', 'schemas', 'docs', 'package.json']) await cp(join(root, path), join(dir, path), { recursive: true });
  const baseline = run();
  if (baseline.exitCode !== 0 || baseline.fail !== 0) throw Error('Candidate baseline did not pass');
  let previous = null;
  if (process.argv.length > 2) {
    if (process.argv.length !== 4 || process.argv[2] !== '--previous') throw Error('usage: vector-runner-mutations.mjs [--previous FILE]');
    const source = await readFile(process.argv[3], 'utf8');
    await writeFile(join(dir, target), source);
    previous = { sourceDigest: hash(source), ...run() };
    if (previous.exitCode === 0 || previous.fail < 1) throw Error('Previous runner did not reproduce a gate failure');
  }
  const results = [];
  for (const control of controls) {
    let candidate = original;
    for (const [from, to] of control.edits) {
      if (candidate.split(from).length !== 2) throw Error('Mutation anchor must match exactly once: ' + control.name);
      candidate = candidate.replace(from, to);
    }
    await writeFile(join(dir, target), candidate);
    const syntax = spawnSync(process.execPath, ['--check', join(dir, target)], { encoding: 'utf8' });
    if (syntax.status !== 0) throw Error('Invalid mutant syntax: ' + control.name);
    const result = run();
    if (result.exitCode === 0 || result.fail < 1) throw Error('Surviving mutation: ' + control.name);
    results.push({ name: control.name, sourceDigest: hash(candidate), killed: true, ...result });
  }
  const report = { schema: 'kya.vector-runner-controls/v1', sourceDigest: hash(original), node: process.version, previous, baseline, controls: results, allKilled: true, limitations: 'Targeted local controls, same-team authorship; not independent review or exhaustive verification.' };
  console.log(JSON.stringify(report, null, 2));
} finally { await rm(dir, { recursive: true, force: true }); }
