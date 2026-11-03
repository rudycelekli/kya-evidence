import { mkdtemp, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const root = fileURLToPath(new URL('../', import.meta.url));
const target = 'src/interop-bridges/verify.mjs';
const original = await readFile(join(root, target), 'utf8');
const controls = [
  { name: 'omit checked reliability consistency', from: "      insist(!currency.checked || currency.reliable === (currency.current && r.decision === 'qualified'), 'Currency block reliable contradicts its current result or report decision');\n", to: '' },
  { name: 'omit nonqualified override requirement', from: "      insist(r.decision === 'qualified' || currency.overrides.includes('allowNonQualified'), 'A nonqualified report must record the allowNonQualified override');\n", to: '' }
];
const hash = s => createHash('sha256').update(s).digest('hex');
const dir = await mkdtemp(join(tmpdir(), 'kya-bridge-currency-'));
function run() {
  const p = spawnSync(process.execPath, ['--test', '--test-reporter=tap', 'test/bridge-currency-consistency.test.mjs'], { cwd: dir, encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  const count = k => Number(new RegExp(`^# ${k} (\\d+)$`, 'm').exec(p.stdout)?.[1] ?? NaN);
  const tests = count('tests'), pass = count('pass'), fail = count('fail');
  if (p.error || p.signal || tests !== 3 || !Number.isInteger(pass) || !Number.isInteger(fail) || pass + fail !== tests || count('cancelled') !== 0 || count('skipped') !== 0 || count('todo') !== 0)
    throw Error('Incomplete gate test execution: ' + p.stdout.slice(-5000) + p.stderr.slice(-1000));
  return { exitCode: p.status, tests, pass, fail, failedTests: [...p.stdout.matchAll(/^not ok \d+ - (.+)$/gm)].map(m => m[1]) };
}
try {
  for (const path of ['src', 'scripts', 'evidence', 'test', 'profiles', 'policies', 'suites', 'schemas', 'docs', 'package.json'])
    await cp(join(root, path), join(dir, path), { recursive: true });
  const baseline = run();
  if (baseline.exitCode !== 0 || baseline.fail !== 0) throw Error('Candidate baseline did not pass');
  let previous = null;
  if (process.argv.length > 2) {
    if (process.argv.length !== 4 || process.argv[2] !== '--previous') throw Error('usage: bridge-currency-mutations.mjs [--previous FILE]');
    const source = await readFile(process.argv[3], 'utf8');
    await writeFile(join(dir, target), source);
    previous = { sourceDigest: hash(source), ...run() };
    if (previous.exitCode === 0 || previous.fail < 1) throw Error('Previous verifier did not reproduce a gate failure');
  }
  const results = [];
  for (const control of controls) {
    if (original.split(control.from).length !== 2) throw Error('Mutation anchor must match exactly once: ' + control.name);
    const candidate = original.replace(control.from, control.to);
    await writeFile(join(dir, target), candidate);
    const syntax = spawnSync(process.execPath, ['--check', join(dir, target)], { encoding: 'utf8' });
    if (syntax.error || syntax.signal || syntax.status !== 0) throw Error('Invalid mutant syntax: ' + control.name);
    const result = run();
    if (result.exitCode === 0 || result.fail < 1) throw Error('Surviving mutation: ' + control.name);
    results.push({ name: control.name, sourceDigest: hash(candidate), killed: true, ...result });
  }
  console.log(JSON.stringify({ schema: 'kya.bridge-currency-controls/v1', sourceDigest: hash(original), node: process.version,
    previous, baseline, controls: results, allKilled: true,
    limitations: 'Targeted same-team controls; not independent review, currency authenticity or exhaustive verification.' }, null, 2));
} finally { await rm(dir, { recursive: true, force: true }); }
