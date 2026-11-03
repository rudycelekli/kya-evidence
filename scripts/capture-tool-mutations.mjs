import { mkdtemp, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const root = fileURLToPath(new URL('../', import.meta.url));
const bundle = 'src/capture-cell/bundle.mjs', proxy = 'src/capture-cell/proxy.mjs';
const original = Object.fromEntries(await Promise.all([bundle, proxy].map(async p => [p, await readFile(join(root, p), 'utf8')])));
const guard = 'insist(new Set(list.map(t => t.name)).size === list.length, `${label}: duplicate tool name`);';
const controls = [
  { name: 'duplicate exposed tool names accepted', target: bundle, from: guard, to: 'insist(withEffect || new Set(list.map(t => t.name)).size === list.length, `${label}: duplicate tool name`);' },
  { name: 'duplicate declared tool names accepted', target: bundle, from: guard, to: 'insist(!withEffect || new Set(list.map(t => t.name)).size === list.length, `${label}: duplicate tool name`);' },
  { name: 'duplicate cell declarations allowed until after agent invocation', target: proxy,
    from: "insist(new Set(declaredTools.map(t => t.id)).size === declaredTools.length, 'Duplicate declared tool ID');",
    to: "insist(true, 'Duplicate declared tool ID');" }
];
const hash = s => createHash('sha256').update(s).digest('hex');
const digests = sources => Object.fromEntries(Object.entries(sources).map(([p, text]) => [p, hash(text)]));
const dir = await mkdtemp(join(tmpdir(), 'kya-capture-tool-mutations-'));
async function install(sources) {
  for (const [path, text] of Object.entries(sources)) await writeFile(join(dir, path), text);
}
function run() {
  const p = spawnSync(process.execPath, ['--test', '--test-reporter=tap', 'test/capture-tool-uniqueness.test.mjs'], { cwd: dir, encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  const count = k => Number(new RegExp(`^# ${k} (\\d+)$`, 'm').exec(p.stdout)?.[1] ?? NaN);
  if (p.error || p.signal || ![0, 1].includes(p.status) || count('tests') !== 4 ||
      count('pass') + count('fail') !== 4 || count('cancelled') !== 0 || count('skipped') !== 0 || count('todo') !== 0)
    throw Error('Incomplete gate test execution: ' + p.stdout.slice(-5000) + p.stderr.slice(-1000));
  return { exitCode: p.status, tests: count('tests'), pass: count('pass'), fail: count('fail'),
    failedTests: [...p.stdout.matchAll(/^not ok \d+ - (.+)$/gm)].map(m => m[1]) };
}
try {
  for (const path of ['src', 'scripts', 'evidence', 'test', 'profiles', 'policies', 'suites', 'schemas', 'docs', 'package.json'])
    await cp(join(root, path), join(dir, path), { recursive: true });
  const baseline = run();
  if (baseline.exitCode !== 0 || baseline.fail !== 0) throw Error('Candidate baseline did not pass');
  let previous = null;
  if (process.argv.length > 2) {
    if (process.argv.length !== 4 || process.argv[2] !== '--previous') throw Error('usage: capture-tool-mutations.mjs [--previous DIRECTORY]');
    const sources = { [bundle]: await readFile(join(process.argv[3], 'previous-bundle.mjs'), 'utf8'),
      [proxy]: await readFile(join(process.argv[3], 'previous-proxy.mjs'), 'utf8') };
    await install(sources);
    previous = { sourceDigests: digests(sources), ...run() };
    if (previous.exitCode !== 1 || previous.fail < 1) throw Error('Previous implementation did not reproduce a gate failure');
  }
  const results = [];
  for (const control of controls) {
    const sources = { ...original };
    if (sources[control.target].split(control.from).length !== 2) throw Error('Mutation anchor must match exactly once: ' + control.name);
    sources[control.target] = sources[control.target].replace(control.from, control.to);
    await install(sources);
    const syntax = spawnSync(process.execPath, ['--check', join(dir, control.target)], { encoding: 'utf8', timeout: 60000 });
    if (syntax.error || syntax.signal || syntax.status !== 0) throw Error('Invalid mutant syntax: ' + control.name);
    const result = run();
    if (result.exitCode !== 1 || result.fail < 1) throw Error('Surviving mutation: ' + control.name);
    results.push({ name: control.name, sourceDigests: digests(sources), killed: true, ...result });
  }
  console.log(JSON.stringify({ schema: 'kya.capture-tool-controls/v1', sourceDigests: digests(original), node: process.version,
    previous, baseline, controls: results, allKilled: true,
    limitations: 'Targeted local same-team controls; not independent review, real-agent validation or sandbox isolation.' }, null, 2));
} finally { await rm(dir, { recursive: true, force: true }); }
