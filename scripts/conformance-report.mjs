import { readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { parseJson } from '../src/shared/canonical.mjs';
import { buildReport, validateReport, verifyReport, parseTap, mapTapToRequirements } from '../src/conformance-report/index.mjs';
import { loadRequirements } from './requirements.mjs';

// Builds a kya.conformance-report/v1 for the JS reference by actually running each cited test file under
// `node --test --test-reporter=tap` and mapping top-level results to requirement IDs. No clock is read:
// --now is mandatory. The output is unsigned; signing is a separate act with a key the caller controls.
const usage = 'usage: conformance-report.mjs --now ISO [--out FILE] [--root DIR] [--source-digest SHA256] | --verify FILE [--root DIR]';
function args(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (!['--now', '--out', '--root', '--verify', '--source-digest'].includes(k) || i + 1 >= argv.length) throw Error(`Unknown or incomplete option ${k}. ${usage}`);
    o[k.slice(2)] = argv[++i];
  }
  return o;
}

function runFile(root, file) {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, ['--test', '--test-reporter=tap', file], { cwd: root, encoding: 'utf8', env, maxBuffer: 64 * 1024 * 1024, timeout: 600000 });
  return { exitCode: p.status, error: p.error ? String(p.error.code ?? p.error.message) : undefined, tests: parseTap(p.stdout ?? '') };
}

async function main() {
  const o = args(process.argv.slice(2)), root = resolve(o.root ?? fileURLToPath(new URL('../', import.meta.url)));
  const { reg } = await loadRequirements(root);
  if (o.verify) {
    const parsed = parseJson(await readFile(o.verify, 'utf8'));
    const signed = Object.hasOwn(parsed, 'proof');
    const v = signed ? verifyReport(parsed, { registry: reg }) : { payload: validateReport(parsed, { registry: reg }), keyId: null, authenticated: false, truthfulnessVerified: false };
    console.log(JSON.stringify({ valid: true, signed, keyId: v.keyId, authenticated: false, truthfulnessVerified: false, registryDigest: v.payload.registryDigest, summary: v.payload.summary }));
    return;
  }
  if (!o.now) throw Error('--now ISO-8601 UTC time is required (this tool never reads the clock). ' + usage);
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8').catch(() => '{"name":"kya-evidence","version":"unknown"}'));
  const runs = {};
  for (const file of [...new Set(reg.requirements.flatMap(r => r.tests.map(t => t.file)))].sort()) runs[file] = runFile(root, file);
  const report = buildReport({
    registry: reg, runAt: o.now,
    implementation: { name: (pkg.name ?? 'kya-evidence') + ' (JavaScript reference)', version: String(pkg.version ?? 'unknown'), language: 'javascript', sourceDigest: o['source-digest'] ?? null, declaredSubset: null },
    results: mapTapToRequirements(reg, runs)
  });
  if (o.out) { await writeFile(o.out, JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify(report.summary)); }
  else console.log(JSON.stringify(report, null, 2));
}
main().catch(e => { console.error(e.message); process.exit(1); });
