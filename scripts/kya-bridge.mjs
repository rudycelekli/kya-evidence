#!/usr/bin/env node
// kya-bridge: offline exports of a KYA assessment for other ecosystems. No network, no signing, no default clock.
// Exit codes: 0 ok, 1 cross-check found a problem, 2 refused or usage error (fail closed).
import { readFile, writeFile } from 'node:fs/promises';
import { parseJson } from '../src/shared/canonical.mjs';
import { exportInTotoStatement, exportOtelAttributes, exportOAuthClaims, exportSpiffeBinding, exportA2aExtension, exportMcpMeta, verifyBridgeExport, serialize, BridgeError, BRIDGE_KINDS } from '../src/interop-bridges/index.mjs';

const HELP = `kya-bridge: export a KYA assessment as ${BRIDGE_KINDS.join(', ')}. Offline, unsigned, not an authorization grant.

  kya-bridge export KIND --assessment FILE --manifest FILE --policy FILE --now ISO [--incidents FILE]
                    [--spiffe-id ID] [--assessment-url URL] [--allow-non-qualified] [--allow-not-current] [--out FILE]
  kya-bridge verify KIND --export FILE --assessment FILE [--manifest FILE --policy FILE --now ISO [--incidents FILE]]

Exports refuse (exit 2) a non-qualified or non-current assessment unless the matching --allow flag is given; overrides used are
recorded inside the output. --now is always explicit. verify rebuilds the export from the report and compares it; without
--manifest/--policy/--now the currency block is not re-derived. No third-party tool has consumed these formats.
`;

function parseArgs(argv) {
  const flags = {}, bool = new Set(['allow-non-qualified', 'allow-not-current']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; if (!a.startsWith('--')) throw Error(`Unexpected argument ${a}`);
    const k = a.slice(2);
    if (bool.has(k)) { flags[k] = true; continue; }
    const v = argv[++i]; if (v === undefined || v.startsWith('--')) throw Error(`Missing value for --${k}`);
    if (k in flags) throw Error(`Duplicate --${k}`); flags[k] = v;
  }
  return flags;
}
const need = (f, ...ks) => { for (const k of ks) if (f[k] === undefined) throw Error(`--${k} is required`); };
const readJson = async p => parseJson(await readFile(p, 'utf8'));
const emit = async (f, text) => { if (f.out) await writeFile(f.out, text); else process.stdout.write(text); };

async function inputs(f) {
  const o = {};
  if (f.manifest) o.manifest = await readJson(f.manifest);
  if (f.policy) o.policy = await readJson(f.policy);
  if (f.now) o.now = f.now;
  if (f.incidents) o.incidents = await readJson(f.incidents);
  return o;
}

async function main() {
  const [cmd, kind, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === '--help' || cmd === 'help') { process.stdout.write(HELP); return 0; }
  if (!BRIDGE_KINDS.includes(kind)) throw Error(`KIND must be one of ${BRIDGE_KINDS.join(', ')}`);
  const f = parseArgs(rest);
  if (cmd === 'export') {
    need(f, 'assessment');
    const options = { ...await inputs(f), ...(f['allow-non-qualified'] ? { allowNonQualified: true } : {}), ...(f['allow-not-current'] ? { allowNotCurrent: true } : {}) };
    if (f['assessment-url']) options.assessmentUrl = f['assessment-url'];
    const a = await readJson(f.assessment);
    if (kind === 'spiffe') { need(f, 'spiffe-id'); await emit(f, serialize(exportSpiffeBinding(a, f['spiffe-id'], options))); return 0; }
    if (f['spiffe-id']) throw Error('--spiffe-id applies only to KIND spiffe');
    const fn = { intoto: exportInTotoStatement, otel: exportOtelAttributes, oauth: exportOAuthClaims, a2a: exportA2aExtension, mcp: exportMcpMeta }[kind];
    if (f['assessment-url'] && kind !== 'a2a' && kind !== 'mcp') throw Error('--assessment-url applies only to KIND a2a or mcp');
    await emit(f, serialize(fn(a, options)));
    return 0;
  }
  if (cmd === 'verify') {
    need(f, 'export', 'assessment');
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
