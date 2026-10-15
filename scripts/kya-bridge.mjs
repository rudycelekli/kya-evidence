#!/usr/bin/env node
// kya-bridge: offline exports of a KYA assessment for other ecosystems. No network, no signing, no default clock.
// Exit codes: 0 ok, 1 cross-check found a problem, 2 refused or usage error (fail closed).
import { readFile, writeFile, lstat, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';
import { parseJson } from '../src/shared/canonical.mjs';
import { exportInTotoStatement, exportOtelAttributes, exportOAuthClaims, exportSpiffeBinding, exportA2aExtension, exportMcpMeta, verifyBridgeExport, serialize, BridgeError, BRIDGE_KINDS } from '../src/interop-bridges/index.mjs';

const HELP = `kya-bridge: export a KYA assessment as ${BRIDGE_KINDS.join(', ')}. Offline, unsigned, not an authorization grant.

  kya-bridge export KIND --assessment FILE --manifest FILE --policy FILE --now ISO [--incidents FILE]
                    [--spiffe-id ID] [--assessment-url URL] [--allow-non-qualified] [--allow-not-current] [--out FILE [--force]]
  kya-bridge verify KIND --export FILE --assessment FILE [--manifest FILE --policy FILE --now ISO [--incidents FILE]]

Exports refuse (exit 2) a non-qualified or non-current assessment unless the matching --allow flag is given; overrides used are
recorded inside the output. --now is always explicit. verify rebuilds the export from the report and compares it; without
--manifest/--policy/--now the currency block is not re-derived. Unknown flags, empty values, and --incidents without
--manifest/--policy/--now exit 2. --out refuses an existing file unless --force, and always refuses a symlink or an input file.
No third-party tool has consumed these formats.
`;

// Per command flag allowlists: a misspelt flag must stop the run, never silently drop a check.
const VALUE_FLAGS = {
  export: ['assessment', 'manifest', 'policy', 'now', 'incidents', 'spiffe-id', 'assessment-url', 'out'],
  verify: ['export', 'assessment', 'manifest', 'policy', 'now', 'incidents']
};
const BOOL_FLAGS = { export: ['allow-non-qualified', 'allow-not-current', 'force'], verify: [] };

function parseArgs(argv, cmd) {
  const flags = Object.create(null), bool = new Set(BOOL_FLAGS[cmd]), val = new Set(VALUE_FLAGS[cmd]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; if (!a.startsWith('--')) throw Error(`Unexpected argument ${a}`);
    const k = a.slice(2);
    if (!bool.has(k) && !val.has(k)) throw Error(`Unknown flag --${k} for ${cmd}`);
    if (k in flags) throw Error(`Duplicate --${k}`);
    if (bool.has(k)) { flags[k] = true; continue; }
    const v = argv[++i]; if (v === undefined || v.startsWith('--')) throw Error(`Missing value for --${k}`);
    flags[k] = v;
  }
  return flags;
}
const need = (f, ...ks) => { for (const k of ks) if (f[k] === undefined) throw Error(`--${k} is required`); };
const readJson = async p => parseJson(await readFile(p, 'utf8'));
const INPUT_FLAGS = ['assessment', 'manifest', 'policy', 'incidents', 'export'];

async function emit(f, text) {
  if (f.out === undefined) { process.stdout.write(text); return; }
  if (f.out === '') throw Error('--out must not be empty');
  const out = resolve(f.out), paths = INPUT_FLAGS.filter(k => f[k] !== undefined).map(k => f[k]);
  if (paths.some(p => resolve(p) === out)) throw Error('--out must not be an input file');
  const st = await lstat(out).catch(() => null);
  if (st) {
    if (st.isSymbolicLink()) throw Error('--out must not be a symbolic link');
    for (const p of paths) { const s = await stat(p); if (s.ino === st.ino && s.dev === st.dev) throw Error('--out must not be an input file'); }
    if (f.force !== true) throw Error('--out already exists; pass --force to overwrite it');
  }
  const flag = f.force === true ? constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0) : constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;
  await writeFile(out, text, { flag });
}

// A flag counts as present whenever it was given, even with an empty value, so an empty value fails instead of being skipped.
async function inputs(f) {
  const o = {};
  if (f.manifest !== undefined) o.manifest = await readJson(f.manifest);
  if (f.policy !== undefined) o.policy = await readJson(f.policy);
  if (f.now !== undefined) o.now = f.now;
  if (f.incidents !== undefined) o.incidents = await readJson(f.incidents);
  return o;
}
const recheckFlags = f => ['manifest', 'policy', 'now'].map(k => f[k] !== undefined);

async function main() {
  const [cmd, kind, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === '--help' || cmd === 'help') { process.stdout.write(HELP); return 0; }
  if (!BRIDGE_KINDS.includes(kind)) throw Error(`KIND must be one of ${BRIDGE_KINDS.join(', ')}`);
  if (cmd !== 'export' && cmd !== 'verify') throw Error(`Unknown command ${cmd}`);
  const f = parseArgs(rest, cmd);
  if (cmd === 'export') {
    need(f, 'assessment');
    const options = { ...await inputs(f), ...(f['allow-non-qualified'] ? { allowNonQualified: true } : {}), ...(f['allow-not-current'] ? { allowNotCurrent: true } : {}) };
    if (f['assessment-url'] !== undefined) options.assessmentUrl = f['assessment-url'];
    const a = await readJson(f.assessment);
    if (kind === 'spiffe') { need(f, 'spiffe-id'); await emit(f, serialize(exportSpiffeBinding(a, f['spiffe-id'], options))); return 0; }
    if (f['spiffe-id'] !== undefined) throw Error('--spiffe-id applies only to KIND spiffe');
    const fn = { intoto: exportInTotoStatement, otel: exportOtelAttributes, oauth: exportOAuthClaims, a2a: exportA2aExtension, mcp: exportMcpMeta }[kind];
    if (f['assessment-url'] !== undefined && kind !== 'a2a' && kind !== 'mcp') throw Error('--assessment-url applies only to KIND a2a or mcp');
    await emit(f, serialize(fn(a, options)));
    return 0;
  }
  if (cmd === 'verify') {
    need(f, 'export', 'assessment');
    const have = recheckFlags(f);
    if (have.some(Boolean) && !have.every(Boolean)) throw Error('--manifest, --policy and --now must be given together, or none of them');
    if (f.incidents !== undefined && !have.every(Boolean)) throw Error('--incidents needs --manifest, --policy and --now');
    const result = verifyBridgeExport(kind, await readJson(f.export), { report: await readJson(f.assessment), ...await inputs(f) });
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return result.valid ? 0 : 1;
  }
  throw Error(`Unknown command ${cmd}`);
}

main().then(code => { process.exitCode = code; }, e => {
  process.stderr.write(JSON.stringify({ error: e.message, code: e instanceof BridgeError ? e.code : undefined }) + '\n');
  process.exitCode = 2;
});
