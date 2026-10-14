#!/usr/bin/env node
// kya-check: a CI gate over assess and checkCurrency. Standalone; it does not touch bin/kya.mjs.
// Exit codes: 0 reliable and current, 2 not qualified or reassess required, 1 usage or input error.
import { readFileSync, lstatSync, appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assess, checkCurrency, parseJson, BLOCKER_CODES } from '../src/index.mjs';

const HELP = `kya-check: gate a pipeline on a KYA policy

  kya-check --assessment-inputs FILE [--incidents FILE] [--now ISO] [--fail-on MODE]
  kya-check --manifest FILE --profile FILE --policy FILE --evidence FILE --evaluator DIGEST [--incidents FILE] [--now ISO] [--fail-on MODE]
  kya-check --assessment FILE --manifest FILE --policy FILE [--incidents FILE] [--now ISO] [--fail-on MODE]

FILE for --assessment-inputs holds {manifest, profile, policy, evidence, evaluatorDigest[, now]}.
--fail-on unreliable (default) | not-qualified | never
Exit: 0 reliable and current, 2 not qualified or reassess required, 1 usage or input error.
Without --now the system clock is read and the summary says so.
A result is a local policy check, not an authorization grant.
`;
const VALUE_FLAGS = ['assessment-inputs', 'assessment', 'manifest', 'profile', 'policy', 'evidence', 'evaluator', 'incidents', 'now', 'fail-on'];
const FAIL_ON = ['unreliable', 'not-qualified', 'never'];
const INPUT_KEYS = ['manifest', 'profile', 'policy', 'evidence', 'evaluatorDigest', 'now'];
const MAX_FILE = 4_194_304;

const CONTROL = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]', 'g');
class UsageError extends Error {}
const usage = message => { throw new UsageError(message); };

function parseArgs(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { flags.help = true; continue; }
    if (!a.startsWith('--')) usage('Unexpected positional argument');
    const name = a.slice(2);
    if (!VALUE_FLAGS.includes(name)) usage(`Unknown flag --${name}`);
    if (Object.hasOwn(flags, name)) usage(`Duplicate flag --${name}`);
    const next = argv[++i];
    if (next === undefined || next.startsWith('--')) usage(`Flag --${name} requires a value`);
    flags[name] = next;
  }
  return flags;
}

function readJson(path, label) {
  let st;
  try { st = lstatSync(path); } catch { usage(`Cannot read ${label}`); }
  if (!st.isFile() || st.isSymbolicLink() || st.size > MAX_FILE) usage(`${label} must be a bounded regular JSON file`);
  try { return parseJson(readFileSync(path, 'utf8')); } catch (e) { usage(`${label} is not valid JSON: ${clean(e.message, 120)}`); }
}

// Untrusted text (agent names, blocker text, ids) is reduced to one printable line and bounded.
export function clean(value, max = 200) {
  return String(value ?? '').replace(CONTROL, ' ').slice(0, max);
}
// GitHub workflow command escaping: data escapes % CR LF; properties also escape colon and comma.
export const escapeData = s => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
export const escapeProperty = s => escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
// Markdown: no raw HTML, link, image, heading, table or autolink syntax can survive.
export function escapeMarkdown(value, max = 200) {
  return clean(value, max).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/:\/\//g, ':&#47;&#47;').replace(/[\\`*_{}\[\]()#|~!]/g, c => '\\' + c);
}
const num = v => (typeof v === 'number' && Number.isFinite(v) ? v : null);

function summarize({ report, currency, mode, now, clockSource, failOn }) {
  const reliable = currency.reliable === true;
  const failed = failOn === 'never' ? false : failOn === 'not-qualified' ? report.decision !== 'qualified' : !reliable;
  const blockers = (Array.isArray(report.blockers) ? report.blockers : []).slice(0, 20).map(b => clean(b));
  const codes = (Array.isArray(report.blockerCodes) ? report.blockerCodes : []).filter(c => BLOCKER_CODES.includes(c));
  const summary = {
    schema: 'kya.check-summary/v1', mode,
    agent: { id: clean(report.agentId, 128), name: clean(report.agentName, 128), scopeId: clean(report.scopeId, 128) },
    decision: clean(report.decision, 40), evidenceMode: clean(report.evidenceMode, 20),
    score: { earned: num(report.score?.earned), possible: num(report.score?.possible), upperBound: num(report.score?.upperBound) },
    coverage: num(report.coverage), independentCoverage: num(report.independentCoverage),
    blockerCodes: codes, blockers,
    currency: {
      current: currency.current === true, action: clean(currency.action, 20),
      triggers: currency.triggers.map(t => ({ id: clean(t.id, 60), code: clean(t.code, 60), detail: clean(t.detail) })),
      incidentsOpen: currency.incidents.open.map(i => clean(i, 128)),
    },
    reliable, failOn, exitCode: failed ? 2 : 0,
    clock: { now, source: clockSource, note: clockSource === 'system-clock' ? 'No --now given: the system clock was read, so this result is not reproducible' : clockSource === 'inputs-file' ? 'now taken from the inputs file' : 'now supplied explicitly; output is deterministic' },
    reportDigest: clean(report.reportDigest, 64), authenticated: false,
    notes: ['Local policy result; not an authorization grant', 'Report checksum is unauthenticated; the gate trusts only the inputs it was given'],
  };
  return summary;
}

function annotations(s, onActions) {
  if (!onActions) return [];
  const err = (title, msg) => `::error title=${escapeProperty(title)}::${escapeData(clean(msg, 400))}`;
  const warn = (title, msg) => `::warning title=${escapeProperty(title)}::${escapeData(clean(msg, 400))}`;
  const out = [];
  if (!s.reliable) out.push(err(`KYA decision: ${s.decision}`, `${s.agent.name} (${s.agent.scopeId}) is not reliable and current under the supplied policy`));
  s.blockers.forEach((b, i) => out.push(err(`KYA blocker ${s.blockerCodes[i] ?? 'UNCODED'}`, b)));
  s.currency.triggers.forEach(t => out.push(err('KYA reassess required', `${t.code}: ${t.detail}`)));
  if (s.clock.source === 'system-clock') out.push(warn('KYA clock', s.clock.note));
  if (s.evidenceMode === 'fixture' || s.evidenceMode === 'mixed') out.push(warn('KYA evidence', 'Result includes synthetic fixture evidence; it is not a real product assessment'));
  return out.length > 10 ? [...out.slice(0, 9), warn('KYA annotations', `${out.length - 9} further annotations omitted; see the JSON summary`)] : out;
}

function markdown(s) {
  const e = escapeMarkdown, verdict = s.reliable ? 'RELIABLE AND CURRENT' : 'NOT RELIABLE';
  const lines = [`## KYA check: ${verdict}`, '', '| Field | Value |', '| :--- | :--- |',
    `| Agent | ${e(s.agent.name)} (${e(s.agent.id)}) |`, `| Scope | ${e(s.agent.scopeId)} |`, `| Decision | ${e(s.decision)} |`,
    `| Score | ${s.score.earned ?? 'n/a'} of ${s.score.possible ?? 'n/a'} (upper bound ${s.score.upperBound ?? 'n/a'}) |`,
    `| Coverage | ${s.coverage ?? 'n/a'} (independent ${s.independentCoverage ?? 'n/a'}) |`, `| Evidence mode | ${e(s.evidenceMode)} |`,
    `| Current | ${s.currency.current} (action: ${e(s.currency.action)}) |`, `| Clock | ${e(s.clock.now)} from ${e(s.clock.source)} |`, `| Exit code | ${s.exitCode} |`, ''];
  if (s.blockers.length) { lines.push('Blockers:', ''); s.blockers.forEach((b, i) => lines.push(`- ${e(s.blockerCodes[i] ?? 'UNCODED')}: ${e(b)}`)); lines.push(''); }
  if (s.currency.triggers.length) { lines.push('Reassessment triggers:', ''); s.currency.triggers.forEach(t => lines.push(`- ${e(t.code)}: ${e(t.detail)}`)); lines.push(''); }
  if (s.clock.source === 'system-clock') lines.push(`Note: ${e(s.clock.note)}.`, '');
  lines.push('This is a local policy check, not an authorization grant. It does not prove truthful execution, human identity or independent review.', '');
  return lines.join('\n');
}

function githubOutputs(s) {
  const one = v => clean(String(v), 4000);
  return [['decision', s.decision], ['reliable', s.reliable], ['current', s.currency.current], ['score', s.score.earned ?? ''], ['coverage', s.coverage ?? ''],
    ['independent-coverage', s.independentCoverage ?? ''], ['blocker-codes', s.blockerCodes.join(',')], ['trigger-codes', s.currency.triggers.map(t => t.code).join(',')],
    ['exit-code', s.exitCode], ['clock-source', s.clock.source], ['summary-json', JSON.stringify(s)]]
    .map(([k, v]) => `${k}=${one(v)}\n`).join('');
}

function loadInputs(flags) {
  const individual = ['manifest', 'profile', 'policy', 'evidence', 'evaluator'].filter(k => flags[k] !== undefined);
  if (flags['assessment-inputs'] !== undefined) {
    if (flags.assessment !== undefined || individual.length) usage('--assessment-inputs cannot be combined with other input flags');
    const f = readJson(flags['assessment-inputs'], 'assessment inputs');
    if (f === null || typeof f !== 'object' || Array.isArray(f)) usage('assessment inputs must be an object');
    for (const k of Object.keys(f)) if (!INPUT_KEYS.includes(k)) usage(`Unknown member in assessment inputs: ${clean(k, 40)}`);
    for (const k of ['manifest', 'profile', 'policy', 'evidence', 'evaluatorDigest']) if (!Object.hasOwn(f, k)) usage(`assessment inputs lack ${k}`);
    return { mode: 'assess-and-currency', manifest: f.manifest, profile: f.profile, policy: f.policy, evidence: f.evidence, evaluatorDigest: f.evaluatorDigest, fileNow: f.now };
  }
  if (flags.assessment !== undefined) {
    for (const k of ['profile', 'evidence', 'evaluator']) if (flags[k] !== undefined) usage(`--${k} is not used with --assessment`);
    for (const k of ['manifest', 'policy']) if (flags[k] === undefined) usage(`--assessment requires --${k}`);
    return { mode: 'currency-only', assessment: readJson(flags.assessment, 'assessment'), manifest: readJson(flags.manifest, 'manifest'), policy: readJson(flags.policy, 'policy') };
  }
  for (const k of ['manifest', 'profile', 'policy', 'evidence', 'evaluator']) if (flags[k] === undefined) usage(`Missing --${k} (or use --assessment-inputs or --assessment)`);
  return { mode: 'assess-and-currency', manifest: readJson(flags.manifest, 'manifest'), profile: readJson(flags.profile, 'profile'), policy: readJson(flags.policy, 'policy'), evidence: readJson(flags.evidence, 'evidence'), evaluatorDigest: flags.evaluator };
}

export function main(argv = process.argv.slice(2), env = process.env, write = s => process.stdout.write(s)) {
  const onActions = env.GITHUB_ACTIONS === 'true';
  try {
    const flags = parseArgs(argv);
    if (flags.help) { write(HELP); return 0; }
    const failOn = flags['fail-on'] ?? 'unreliable';
    if (!FAIL_ON.includes(failOn)) usage('--fail-on must be unreliable, not-qualified or never');
    const input = loadInputs(flags);
    const incidents = flags.incidents !== undefined ? readJson(flags.incidents, 'incidents') : [];
    const clockSource = flags.now !== undefined ? 'flag' : input.fileNow !== undefined ? 'inputs-file' : 'system-clock';
    const now = flags.now ?? input.fileNow ?? new Date().toISOString();
    if (typeof now !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(now) || Number.isNaN(Date.parse(now))) usage('now must be an ISO UTC timestamp with milliseconds, for example 2026-01-01T00:00:00.000Z');
    let report;
    try {
      report = input.mode === 'currency-only' ? input.assessment : assess({ manifest: input.manifest, profile: input.profile, policy: input.policy, evidence: input.evidence, evaluatorDigest: input.evaluatorDigest, now });
      const currency = checkCurrency(report, { manifest: input.manifest, policy: input.policy, incidents, now });
      const s = summarize({ report, currency, mode: input.mode, now, clockSource, failOn });
      for (const line of annotations(s, onActions)) write(line + '\n');
      write(JSON.stringify(s, null, 2) + '\n');
      try {
        if (env.GITHUB_OUTPUT) appendFileSync(resolve(env.GITHUB_OUTPUT), githubOutputs(s));
        if (env.GITHUB_STEP_SUMMARY) appendFileSync(resolve(env.GITHUB_STEP_SUMMARY), markdown(s) + '\n');
      } catch (e) { usage('Cannot write GitHub output or step summary: ' + clean(e.code ?? e.message, 60)); }
      return s.exitCode;
    } catch (e) { if (e instanceof UsageError) throw e; usage(clean(e.message, 300)); }
  } catch (e) {
    const message = clean(e.message, 300);
    if (onActions) write(`::error title=${escapeProperty('KYA usage or input error')}::${escapeData(message)}\n`);
    process.stderr.write(`kya-check: ${message}\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
