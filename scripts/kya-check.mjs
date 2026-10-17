#!/usr/bin/env node
// kya-check: a CI gate over assess and checkCurrency. Standalone; it does not touch bin/kya.mjs.
// Exit codes: 0 reliable and current, 2 not qualified or reassess required, 1 usage or input error.
import { readFileSync, lstatSync, appendFileSync, realpathSync } from 'node:fs';
import { resolve, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assess, checkCurrency, parseJson, digest, BLOCKER_CODES } from '../src/index.mjs';
import { CORE_PROFILE } from '../src/conformance/index.mjs';
import { isMain } from "./lib/is-main.mjs";

const CORE_PROFILE_DIGEST = digest(CORE_PROFILE);

const HELP = `kya-check: gate a pipeline on a KYA policy

  kya-check --assessment-inputs FILE [--incidents FILE] [--now ISO] [--fail-on MODE]
  kya-check --manifest FILE --profile FILE --policy FILE --evidence FILE --evaluator DIGEST [--incidents FILE] [--now ISO] [--fail-on MODE]
  kya-check --assessment FILE --manifest FILE --policy FILE [--incidents FILE] [--now ISO] [--fail-on MODE]

FILE for --assessment-inputs holds {manifest, profile, policy, evidence, evaluatorDigest[, now]}.
--fail-on unreliable (default) | not-qualified | never
--allow-fixture            let fixture (or mixed) evidence count as reliable; default needs runtime evidence
--expect-policy-digest D   refuse (exit 1) unless the policy digest equals D
--expect-evaluator-digest D  refuse (exit 1) unless the evaluator digest equals D
--expect-assessment-digest D  currency-only mode: refuse (exit 1, ASSESSMENT_DIGEST_MISMATCH) unless the assessment reportDigest equals D
--allow-unpinned-assessment  currency-only mode: do not withhold reliability (ASSESSMENT_NOT_PINNED) when no assessment pin is given
--allow-inputs-clock       let the now member of an --assessment-inputs file set the clock under --require-pins (ignored there by default: the file comes from the code under test)
--require-pins             refuse (exit 1, PINS_REQUIRED) unless the policy and evaluator pins (and, in currency-only mode, the assessment pin) are supplied
Take inputs and pinned digests from the base branch or a protected path, never from the code under test.
Exit: 0 reliable and current, 2 not qualified or reassess required, 1 usage or input error.
Without --now the system clock is read and the summary says so.
A result is a local policy check, not an authorization grant.
`;
const VALUE_FLAGS = ['assessment-inputs', 'assessment', 'manifest', 'profile', 'policy', 'evidence', 'evaluator', 'incidents', 'now', 'fail-on', 'expect-policy-digest', 'expect-evaluator-digest', 'expect-assessment-digest'];
const BOOLEAN_FLAGS = ['allow-fixture', 'allow-unpinned-assessment', 'require-pins', 'allow-inputs-clock'];
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
    if (BOOLEAN_FLAGS.includes(name)) { if (flags[name]) usage(`Duplicate flag --${name}`); flags[name] = true; continue; }
    if (!VALUE_FLAGS.includes(name)) usage(`Unknown flag --${name}`);
    if (Object.hasOwn(flags, name)) usage(`Duplicate flag --${name}`);
    const next = argv[++i];
    if (next === undefined || next.startsWith('--')) usage(`Flag --${name} requires a value`);
    flags[name] = next;
  }
  return flags;
}

// A path given inside the workspace (the current directory) must still resolve inside it once every parent is
// resolved, so a checked-in symlinked directory cannot point an input at a file outside the workspace.
function confine(path, label) {
  const lexical = resolve(path), root = resolve('.');
  const rel = relative(root, lexical);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return;
  let real, realRoot;
  try { real = realpathSync(lexical); realRoot = realpathSync(root); } catch { usage(`Cannot read ${label}`); }
  const back = relative(realRoot, real);
  if (back === '..' || back.startsWith('..' + sep) || isAbsolute(back)) usage(`${label} resolves outside the workspace through a symbolic link`);
}

function readJson(path, label) {
  let st;
  confine(path, label);
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

// Only runtime evidence can make a result reliable. Fixture (and mixed) evidence needs an explicit opt-in;
// declaration or unrecognised modes are never reliable. In currency-only mode the evidence mode is read from the
// supplied assessment file, so it is only as trustworthy as that file: without a pinned assessment digest the result
// is not reliable unless --allow-unpinned-assessment is given.
function reasonCodesFor(report, { allowFixture, mode, pins, allowUnpinned }) {
  if (report.decision !== 'qualified') return [];
  const out = [], m = report.evidenceMode;
  if (m === 'fixture') { if (!allowFixture) out.push('FIXTURE_EVIDENCE_NOT_RELIABLE'); }
  else if (m === 'mixed') { if (!allowFixture) out.push('MIXED_EVIDENCE_NOT_RELIABLE'); }
  else if (m !== 'runtime') out.push('EVIDENCE_MODE_NOT_RELIABLE');
  if (mode === 'currency-only' && !pins.assessmentPinned && !allowUnpinned) out.push('ASSESSMENT_NOT_PINNED');
  return out;
}

const REASON_TEXT = {
  ASSESSMENT_NOT_PINNED: 'the assessment file is not pinned, so its evidence mode cannot be trusted; supply --expect-assessment-digest from a trusted source',
  EVIDENCE_MODE_NOT_RELIABLE: 'evidence mode cannot make a result reliable; use runtime evidence',
};

function summarize({ report, currency, mode, now, clockSource, failOn, allowFixture, allowUnpinned, pins, customProfile }) {
  const reasonCodes = reasonCodesFor(report, { allowFixture, mode, pins, allowUnpinned });
  const reliable = currency.reliable === true && !reasonCodes.length;
  const failed = failOn === 'never' ? false : failOn === 'not-qualified' ? report.decision !== 'qualified' || !!reasonCodes.length : !reliable;
  const blockers = (Array.isArray(report.blockers) ? report.blockers : []).slice(0, 20).map(b => clean(b));
  const codes = (Array.isArray(report.blockerCodes) ? report.blockerCodes : []).filter(c => BLOCKER_CODES.includes(c));
  const summary = {
    schema: 'kya.check-summary/v1', mode,
    agent: { id: clean(report.agentId, 128), name: clean(report.agentName, 128), scopeId: clean(report.scopeId, 128) },
    decision: clean(report.decision, 40), evidenceMode: clean(report.evidenceMode, 20),
    score: { earned: num(report.score?.earned), possible: num(report.score?.possible), upperBound: num(report.score?.upperBound) },
    coverage: num(report.coverage), independentCoverage: num(report.independentCoverage),
    blockerCodes: codes, blockers, reasonCodes, allowFixture, allowUnpinnedAssessment: allowUnpinned, customProfile,
    policyDigest: pins.policyDigest, evaluatorDigest: clean(pins.evaluatorDigest, 64),
    pins: { policyPinned: pins.policyPinned, evaluatorPinned: pins.evaluatorPinned, assessmentPinned: pins.assessmentPinned },
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
  s.reasonCodes.forEach(c => out.push(err(c === 'ASSESSMENT_NOT_PINNED' ? 'KYA assessment pin' : 'KYA evidence mode', c === 'ASSESSMENT_NOT_PINNED' ? `${c}: ${REASON_TEXT[c]}` : `${c}: evidence mode ${s.evidenceMode} cannot make a result reliable; use runtime evidence${c === 'EVIDENCE_MODE_NOT_RELIABLE' ? '' : ' or pass --allow-fixture knowingly'}`)));
  s.blockers.forEach((b, i) => out.push(err(`KYA blocker ${s.blockerCodes[i] ?? 'UNCODED'}`, b)));
  s.currency.triggers.forEach(t => out.push(err('KYA reassess required', `${t.code}: ${t.detail}`)));
  if (s.clock.source === 'system-clock') out.push(warn('KYA clock', s.clock.note));
  if (!s.pins.policyPinned || !s.pins.evaluatorPinned) out.push(warn('KYA pins', 'Policy or evaluator digest is not pinned; a change to the inputs under test can rewrite this gate. Pin both from a trusted source'));
  if (s.customProfile) out.push(warn('KYA custom profile', 'The policy is not built on the frozen core profile; template thresholds do not carry their documented meaning'));
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
  if (s.reasonCodes.length) { lines.push('Reliability withheld:', ''); s.reasonCodes.forEach(c => lines.push(`- ${e(c)}: ${c === 'ASSESSMENT_NOT_PINNED' ? e(REASON_TEXT[c]) : 'evidence mode ' + e(s.evidenceMode)}`)); lines.push(''); }
  if (!s.pins.policyPinned || !s.pins.evaluatorPinned) lines.push('Note: policy or evaluator digest is not pinned, so inputs from the code under test could rewrite this gate.', '');
  if (s.customProfile) lines.push('Note: the policy is not built on the frozen core profile (customProfile: true); its thresholds do not carry their documented meaning.', '');
  if (s.mode === 'currency-only' && !s.pins.assessmentPinned) lines.push('Note: currency-only mode reads the evidence mode from the assessment file; it is only as trustworthy as that file unless its digest is pinned.', '');
  if (s.blockers.length) { lines.push('Blockers:', ''); s.blockers.forEach((b, i) => lines.push(`- ${e(s.blockerCodes[i] ?? 'UNCODED')}: ${e(b)}`)); lines.push(''); }
  if (s.currency.triggers.length) { lines.push('Reassessment triggers:', ''); s.currency.triggers.forEach(t => lines.push(`- ${e(t.code)}: ${e(t.detail)}`)); lines.push(''); }
  if (s.clock.source === 'system-clock') lines.push(`Note: ${e(s.clock.note)}.`, '');
  lines.push('This is a local policy check, not an authorization grant. It does not prove truthful execution, human identity or independent review.', '');
  return lines.join('\n');
}

// Never cut a JSON string: past the limit emit a compact, valid object that keeps the fields a caller needs to trust it.
export function compactSummary(s) {
  return { schema: s.schema, truncated: true, decision: s.decision, reliable: s.reliable, exitCode: s.exitCode, evidenceMode: s.evidenceMode, allowFixture: s.allowFixture,
    allowUnpinnedAssessment: s.allowUnpinnedAssessment, customProfile: s.customProfile, pins: { ...s.pins }, reasonCodes: s.reasonCodes, blockerCodes: s.blockerCodes.slice(0, 20),
    triggerCodes: s.currency.triggers.map(t => t.code).slice(0, 20), policyDigest: s.policyDigest };
}

export function githubOutputs(s) {
  const one = v => clean(String(v), 4000);
  const full = JSON.stringify(s);
  const json = full.length <= 3800 ? full : JSON.stringify(compactSummary(s));
  return [['decision', s.decision], ['reliable', s.reliable], ['current', s.currency.current], ['evidence-mode', s.evidenceMode], ['allow-fixture', s.allowFixture], ['score', s.score.earned ?? ''], ['coverage', s.coverage ?? ''],
    ['independent-coverage', s.independentCoverage ?? ''], ['blocker-codes', s.blockerCodes.join(',')], ['trigger-codes', s.currency.triggers.map(t => t.code).join(',')],
    ['exit-code', s.exitCode], ['clock-source', s.clock.source], ['summary-json', json]]
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
    // Under --require-pins the inputs file comes from the code under test, so its clock is ignored unless opted in.
    const fileNow = flags['require-pins'] && !flags['allow-inputs-clock'] ? undefined : input.fileNow;
    const clockSource = flags.now !== undefined ? 'flag' : fileNow !== undefined ? 'inputs-file' : 'system-clock';
    const now = flags.now ?? fileNow ?? new Date().toISOString();
    if (typeof now !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(now) || Number.isNaN(Date.parse(now))) usage('now must be an ISO UTC timestamp with milliseconds, for example 2026-01-01T00:00:00.000Z');
    let report;
    try {
      // Pins are checked before anything is assessed or printed, so a swapped policy or evaluator cannot read as reliable.
      const evaluatorDigest = input.mode === 'currency-only' ? input.assessment?.evaluatorDigest : input.evaluatorDigest;
      const pins = { policyDigest: digest(input.policy), evaluatorDigest, policyPinned: false, evaluatorPinned: false, assessmentPinned: false };
      const currencyOnly = input.mode === 'currency-only';
      const checks = [['expect-policy-digest', pins.policyDigest, 'POLICY_DIGEST_MISMATCH', 'policyPinned', 'policy'], ['expect-evaluator-digest', evaluatorDigest, 'EVALUATOR_DIGEST_MISMATCH', 'evaluatorPinned', 'evaluator']];
      if (currencyOnly) checks.push(['expect-assessment-digest', input.assessment?.reportDigest, 'ASSESSMENT_DIGEST_MISMATCH', 'assessmentPinned', 'assessment']);
      else if (flags['expect-assessment-digest'] !== undefined) usage('--expect-assessment-digest is only used with --assessment');
      for (const [flag, actual, code, key, what] of checks) {
        if (flags[flag] === undefined) continue;
        if (!/^[a-f0-9]{64}$/.test(flags[flag])) usage(`--${flag} must be a 64 character lowercase SHA-256 hex digest`);
        if (flags[flag] !== actual) usage(`${code}: the supplied ${what} does not match the pinned digest`);
        pins[key] = true;
      }
      if (flags['allow-unpinned-assessment'] && !currencyOnly) usage('--allow-unpinned-assessment is only used with --assessment');
      if (flags['require-pins']) {
        const missing = checks.filter(c => !pins[c[3]]).map(c => c[4]);
        if (missing.length) usage(`PINS_REQUIRED: no pinned digest for the ${missing.join(', ')}; supply --expect-${missing.map(m => m + '-digest').join(' and --expect-')} from the base branch or a protected path`);
      }
      const customProfile = input.policy?.profileDigest !== CORE_PROFILE_DIGEST;
      report = input.mode === 'currency-only' ? input.assessment : assess({ manifest: input.manifest, profile: input.profile, policy: input.policy, evidence: input.evidence, evaluatorDigest: input.evaluatorDigest, now });
      const currency = checkCurrency(report, { manifest: input.manifest, policy: input.policy, incidents, now });
      const s = summarize({ report, currency, mode: input.mode, now, clockSource, failOn, allowFixture: flags['allow-fixture'] === true, allowUnpinned: flags['allow-unpinned-assessment'] === true, pins, customProfile });
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

if (isMain(import.meta.url)) process.exitCode = main();
