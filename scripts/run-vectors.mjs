import { readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';
import { parseJson } from '../src/shared/canonical.mjs';
import { buildReport, validateReport } from '../src/conformance-report/index.mjs';
import { loadRequirements } from './requirements.mjs';
import { isMain } from "./lib/is-main.mjs";

// Language-neutral harness: runs ANY implementation command against evidence/assessment-vectors.json.
// An implementation reads one kya.impl-input/v1 JSON object on stdin and writes one kya.impl-result/v1 object on stdout
// (interop/impl-contract/README.md). Nothing the implementation says about itself is trusted: only its result for each
// vector counts. The harness reads no clock; the report time comes from --now or the vectors file.
const usage = 'usage: run-vectors.mjs --impl "<command and args>" [--vectors FILE] [--now ISO] [--out FILE] [--name NAME] [--impl-version V] [--language L] [--timeout-ms N] [--jobs N] [--semantic-only]';
export const LIMITS = Object.freeze({ outputBytes: 1_048_576, inputBytes: 4_194_304, timeoutMs: 15_000, failuresShown: 25 });
const DIGEST_FIELDS = ['reportDigest', 'resultDigest'];

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--semantic-only') { o.semanticOnly = true; continue; }
    if (!['--impl', '--vectors', '--now', '--out', '--name', '--impl-version', '--language', '--timeout-ms', '--jobs', '--root'].includes(k) || i + 1 >= argv.length) throw Error(`Unknown or incomplete option ${k}. ${usage}`);
    o[k.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = argv[++i];
  }
  return o;
}
// No shell: whitespace separated, with single or double quotes for arguments that contain spaces.
export function splitCommand(s) {
  const out = []; let cur = '', quote = null, any = false;
  for (const ch of s) {
    if (quote) { if (ch === quote) quote = null; else cur += ch; }
    else if (ch === '"' || ch === "'") { quote = ch; any = true; }
    else if (/\s/.test(ch)) { if (cur || any) out.push(cur); cur = ''; any = false; }
    else cur += ch;
  }
  if (quote) throw Error('Unterminated quote in --impl');
  if (cur || any) out.push(cur);
  if (!out.length) throw Error('--impl is empty');
  return out;
}

// Exact comparison, reporting the first differing path. In an expected object, reasonContains is a lowercase keyword that must
// appear case-insensitively in the actual reason; any other key must match exactly and no extra keys are allowed.
export function firstDifference(expected, actual, path = '$') {
  const show = v => { const t = JSON.stringify(v); return t === undefined ? 'undefined' : t.length > 80 ? t.slice(0, 77) + '...' : t; };
  if (expected === null || typeof expected !== 'object') return Object.is(expected, actual) ? null : `${path}: expected ${show(expected)}, got ${show(actual)}`;
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return `${path}: expected an array, got ${show(actual)}`;
    if (actual.length !== expected.length) return `${path}: expected ${expected.length} items, got ${actual.length}`;
    for (let i = 0; i < expected.length; i++) { const d = firstDifference(expected[i], actual[i], `${path}[${i}]`); if (d) return d; }
    return null;
  }
  if (actual === null || typeof actual !== 'object' || Array.isArray(actual)) return `${path}: expected an object, got ${show(actual)}`;
  const contains = Object.hasOwn(expected, 'reasonContains');
  const ek = Object.keys(expected).filter(k => k !== 'reasonContains'), ak = Object.keys(actual).filter(k => !(contains && k === 'reason'));
  for (const k of ek.sort()) { if (!Object.hasOwn(actual, k)) return `${path}.${k}: missing`; const d = firstDifference(expected[k], actual[k], `${path}.${k}`); if (d) return d; }
  for (const k of ak.sort()) if (!Object.hasOwn(expected, k)) return `${path}.${k}: unexpected field`;
  // An empty reasonContains means the reason text is free (the specification gives no wording): any non-empty string is accepted.
  if (contains && expected.reasonContains === '' && (typeof actual.reason !== 'string' || actual.reason.length === 0)) return `${path}.reason: expected a non-empty reason, got ${show(actual.reason)}`;
  if (contains && (typeof actual.reason !== 'string' || !actual.reason.toLowerCase().includes(expected.reasonContains.toLowerCase()))) return `${path}.reason: expected text containing ${show(expected.reasonContains)}, got ${show(actual.reason)}`;
  return null;
}

function runOne(cmd, args, input, timeoutMs) {
  return new Promise(res => {
    let done = false, out = Buffer.alloc(0), err = '', timedOut = false, oversize = false;
    const finish = r => { if (!done) { done = true; clearTimeout(timer); res(r); } };
    let child;
    try { child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'], env: process.env }); } catch (e) { return finish({ kind: 'spawn-error', message: e.message }); }
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    child.on('error', e => finish({ kind: 'spawn-error', message: e.code ?? e.message }));
    child.stdout.on('data', d => { if (oversize) return; out = Buffer.concat([out, d]); if (out.length > LIMITS.outputBytes) { oversize = true; child.kill('SIGKILL'); } });
    child.stderr.on('data', d => { if (err.length < 2000) err += d.toString('utf8').slice(0, 2000 - err.length); });
    child.stdin.on('error', () => {});
    child.on('close', (code, signal) => finish({ kind: timedOut ? 'timeout' : oversize ? 'oversize' : 'exit', code, signal, stdout: out, stderr: err }));
    child.stdin.end(input);
  });
}

// Returns {status: pass|fail|unsupported|semantic-pass, detail}
async function evaluate(vector, impl, o) {
  // rawInput, when present, is the exact stdin text (used for input that JSON.parse of a vectors file cannot hold, such as duplicate members).
  const input = typeof vector.rawInput === 'string' ? vector.rawInput : JSON.stringify({ schema: 'kya.impl-input/v1', operation: vector.operation, inputs: vector.inputs });
  if (Buffer.byteLength(input) > LIMITS.inputBytes) return { status: 'fail', detail: 'vector input exceeds the harness size bound' };
  const r = await runOne(impl.cmd, impl.args, input, o.timeoutMs);
  if (r.kind === 'spawn-error') return { status: 'fail', detail: `cannot start implementation: ${r.message}` };
  if (r.kind === 'timeout') return { status: 'fail', detail: `timeout after ${o.timeoutMs} ms` };
  if (r.kind === 'oversize') return { status: 'fail', detail: `output exceeds ${LIMITS.outputBytes} bytes` };
  const refusedExpected = vector.expected?.refused === true;
  if (refusedExpected) {
    if (r.code !== 0 || r.signal) return { status: o.semanticOnly ? 'semantic-pass' : 'pass', detail: 'refused as required' };
    return { status: 'fail', detail: 'expected a refusal (non-zero exit), implementation exited 0' };
  }
  if (r.code !== 0) return { status: 'fail', detail: `exit ${r.code ?? r.signal}: refused or crashed${r.stderr ? ' (' + r.stderr.trim().split('\n')[0].slice(0, 120) + ')' : ''}` };
  let actual;
  try { actual = parseJson(r.stdout.toString('utf8')); } catch (e) { return { status: 'fail', detail: 'stdout is not one strict JSON value: ' + String(e.message).slice(0, 100) }; }
  if (actual === null || typeof actual !== 'object' || Array.isArray(actual)) return { status: 'fail', detail: 'stdout is not a JSON object' };
  if (actual.unsupported === true && actual.schema === 'kya.impl-result/v1') return { status: 'unsupported', detail: `operation ${vector.operation} declared unsupported` };
  const expected = JSON.parse(JSON.stringify(vector.expected)), got = JSON.parse(JSON.stringify(actual));
  if (o.semanticOnly || vector.digestReproducible === false) for (const f of DIGEST_FIELDS) { delete expected[f]; delete got[f]; }
  const d = firstDifference(expected, got);
  return d ? { status: 'fail', detail: d } : { status: o.semanticOnly ? 'semantic-pass' : 'pass', detail: null };
}

function validateVectors(file, registryIds) {
  if (file?.schema !== 'kya.assessment-vectors/v1' || !Array.isArray(file.vectors) || !file.vectors.length) throw Error('Not a kya.assessment-vectors/v1 file');
  const ids = new Set();
  for (const v of file.vectors) {
    if (typeof v.id !== 'string' || ids.has(v.id)) throw Error('Duplicate or missing vector ID ' + v.id); ids.add(v.id);
    if (!['assess', 'currency'].includes(v.operation)) throw Error(`Vector ${v.id}: unknown operation`);
    if (!Array.isArray(v.requirements) || !v.requirements.length || v.requirements.some(r => !registryIds.has(r))) throw Error(`Vector ${v.id}: cites a requirement that is not in the registry`);
    const hasInputs = typeof v.inputs === 'object' && v.inputs !== null, hasRaw = typeof v.rawInput === 'string';
    if (hasInputs === hasRaw) throw Error(`Vector ${v.id}: exactly one of inputs and rawInput is required`);
    if (typeof v.expected !== 'object' || v.expected === null) throw Error(`Vector ${v.id}: expected is required`);
  }
}

export async function runVectors({ impl, vectorsFile, now, name, implVersion, language, timeoutMs = LIMITS.timeoutMs, jobs = 4, semanticOnly = false, root }) {
  const { reg } = await loadRequirements(root);
  const file = JSON.parse(await readFile(vectorsFile, 'utf8'));
  const registryIds = new Set(reg.requirements.map(r => r.id));
  validateVectors(file, registryIds);
  const parts = splitCommand(impl), cmd = { cmd: parts[0], args: parts.slice(1) };
  const outcomes = new Array(file.vectors.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.max(1, Math.min(jobs, 16)) }, async () => {
    while (next < file.vectors.length) { const i = next++; outcomes[i] = await evaluate(file.vectors[i], cmd, { timeoutMs, semanticOnly }); }
  }));
  const byReq = new Map();
  file.vectors.forEach((v, i) => { for (const r of v.requirements) byReq.set(r, [...(byReq.get(r) ?? []), { id: v.id, status: outcomes[i].status }]); });
  const results = {};
  for (const id of registryIds) {
    const cited = byReq.get(id) ?? [];
    const executed = cited.map(c => c.id).slice(0, 256);
    if (cited.some(c => c.status === 'fail')) results[id] = { result: 'fail', evidence: 'portable-vector', executed };
    else if (cited.length && cited.every(c => c.status === 'pass')) results[id] = { result: 'pass', evidence: 'portable-vector', executed };
    else results[id] = { result: 'not-run', evidence: null, executed: [] };
  }
  const report = buildReport({ registry: reg, runAt: now ?? file.runAtDefault, implementation: { name: name ?? 'unnamed implementation', version: implVersion ?? 'unknown', language: language ?? 'unknown', sourceDigest: null, declaredSubset: null }, results });
  const count = s => outcomes.filter(x => x.status === s).length;
  const failures = file.vectors.map((v, i) => ({ id: v.id, detail: outcomes[i].detail, status: outcomes[i].status })).filter(x => x.status === 'fail').map(({ id, detail }) => ({ id, detail }));
  const summary = { vectors: { total: outcomes.length, pass: count('pass'), semanticPass: count('semantic-pass'), fail: count('fail'), unsupported: count('unsupported') }, requirements: report.summary, semanticOnly, failures: failures.slice(0, LIMITS.failuresShown), failuresOmitted: Math.max(0, failures.length - LIMITS.failuresShown) };
  return { report, summary, outcomes: file.vectors.map((v, i) => ({ id: v.id, ...outcomes[i] })) };
}

async function main() {
  const o = parseArgs(process.argv.slice(2)), root = resolve(o.root ?? fileURLToPath(new URL('../', import.meta.url)));
  if (!o.impl) throw Error('--impl is required. ' + usage);
  const now = o.now;
  const { report, summary } = await runVectors({ impl: o.impl, vectorsFile: o.vectors ?? join(root, 'evidence/assessment-vectors.json'), now, name: o.name, implVersion: o.implVersion, language: o.language, timeoutMs: o.timeoutMs ? Number(o.timeoutMs) : LIMITS.timeoutMs, jobs: o.jobs ? Number(o.jobs) : 4, semanticOnly: !!o.semanticOnly, root });
  validateReport(report);
  if (o.out) await writeFile(o.out, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(summary));
  process.exit(summary.vectors.fail || summary.vectors.unsupported ? 1 : 0);
}
if (isMain(import.meta.url)) main().catch(e => { console.error(e.message); process.exit(2); });
