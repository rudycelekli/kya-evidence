import { mkdtemp, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const root = fileURLToPath(new URL('../', import.meta.url));
const targets = ['src/vc-bridge/open.mjs', 'src/vc-bridge/credential.mjs'];
const original = Object.fromEntries(await Promise.all(targets.map(async path => [path, await readFile(join(root, path), 'utf8')])));
const target = targets[0];
const controls = [
  { name: 'expected issuer membership read from live array', from: "captureArrayItems(expectedIssuerKeys, 256, 'Expected issuer keys')", to: 'expectedIssuerKeys' },
  { name: 'trust anchor fingerprint consistency omitted', from: "    insist(keyId(anchor.publicKey) === anchor.id, 'Trust anchor fingerprint differs');\n", to: '' },
  { name: 'policy trust projection remains live after root field capture', from: 'const projection = JSON.parse(canonical(raw));', to: 'const projection = raw;' }
];
const hash = s => createHash('sha256').update(s).digest('hex');
const sourceDigests = source => Object.fromEntries(Object.entries(source).map(([path, text]) => [path, hash(text)]));
const dir = await mkdtemp(join(tmpdir(), 'kya-vc-trust-'));
function run() {
  const p = spawnSync(process.execPath, ['--test', '--test-reporter=tap', 'test/vc-trust-inputs.test.mjs'], { cwd: dir, encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  const count = k => Number(new RegExp(`^# ${k} (\\d+)$`, 'm').exec(p.stdout)?.[1] ?? NaN);
  const tests = count('tests'), pass = count('pass'), fail = count('fail');
  if (p.error || p.signal || tests !== 6 || !Number.isInteger(pass) || !Number.isInteger(fail) || pass + fail !== tests || count('cancelled') !== 0 || count('skipped') !== 0 || count('todo') !== 0)
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
    if (process.argv.length !== 4 || process.argv[2] !== '--previous') throw Error('usage: vc-trust-mutations.mjs [--previous DIR]');
    const source = {};
    for (const path of targets) {
      source[path] = await readFile(join(process.argv[3], basename(path)), 'utf8');
      await writeFile(join(dir, path), source[path]);
    }
    previous = { sourceDigests: sourceDigests(source), ...run() };
    if (previous.exitCode === 0 || previous.fail < 1) throw Error('Previous VC trust admission did not reproduce a gate failure');
  }
  const results = [];
  for (const control of controls) {
    for (const path of targets) await writeFile(join(dir, path), original[path]);
    if (original[target].split(control.from).length !== 2) throw Error('Mutation anchor must match exactly once: ' + control.name);
    const candidate = original[target].replace(control.from, control.to);
    await writeFile(join(dir, target), candidate);
    const syntax = spawnSync(process.execPath, ['--check', join(dir, target)], { encoding: 'utf8' });
    if (syntax.error || syntax.signal || syntax.status !== 0) throw Error('Invalid mutant syntax: ' + control.name);
    const result = run();
    if (result.exitCode === 0 || result.fail < 1) throw Error('Surviving mutation: ' + control.name);
    results.push({ name: control.name, sourceDigest: hash(candidate), killed: true, ...result });
  }
  console.log(JSON.stringify({ schema: 'kya.vc-trust-controls/v1', sourceDigests: sourceDigests(original), node: process.version,
    previous, baseline, controls: results, allKilled: true,
    limitations: 'Targeted same-team controls; not outside independent assessment, issuer honesty or authorization.' }, null, 2));
} finally { await rm(dir, { recursive: true, force: true }); }
