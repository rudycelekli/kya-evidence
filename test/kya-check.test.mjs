import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { assess, digest, signEvidence, signIncident, hashBytes } from '../src/index.mjs';
import { inputs, payload, keys, publicKey, signerId, NOW, evaluatorDigest, clone } from './helpers.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/kya-check.mjs');
const dir = mkdtempSync(join(tmpdir(), 'kya-check-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
let counter = 0;
const put = (name, value) => { const p = join(dir, `${counter++}-${name}`); writeFileSync(p, typeof value === 'string' ? value : JSON.stringify(value)); return p; };
// Child environments are built from scratch so a GitHub Actions runner cannot leak its own variables into a test.
const run = (args, extra = {}) => spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', timeout: 20000, env: { PATH: process.env.PATH, ...extra } });
const bundleFile = (x = inputs()) => put('inputs.json', { manifest: x.manifest, profile: x.profile, policy: x.policy, evidence: x.evidence, evaluatorDigest: x.evaluatorDigest });
const jsonOf = out => JSON.parse(out.split('\n').filter(l => !l.startsWith('::')).join('\n'));
const reportFile = (x, patch = {}) => { const r = { ...assess(x), ...patch }; delete r.reportDigest; return put('assessment.json', { ...r, reportDigest: digest(r) }); };

test('qualified and current inputs exit 0 and print a compact summary', () => {
  const p = run(['--assessment-inputs', bundleFile(), '--now', NOW]);
  assert.equal(p.status, 0, p.stderr);
  const s = jsonOf(p.stdout);
  assert.equal(s.schema, 'kya.check-summary/v1'); assert.equal(s.decision, 'qualified'); assert.equal(s.reliable, true);
  assert.equal(s.score.earned, 1000); assert.equal(s.coverage, 1); assert.deepEqual(s.blockerCodes, []);
  assert.equal(s.currency.current, true); assert.deepEqual(s.currency.triggers, []);
  assert.equal(s.clock.source, 'flag'); assert.equal(s.clock.now, NOW); assert.equal(s.authenticated, false);
});

test('individual input flags give the same result as an inputs file', () => {
  const x = inputs();
  const flags = ['--manifest', put('m.json', x.manifest), '--profile', put('p.json', x.profile), '--policy', put('pol.json', x.policy), '--evidence', put('e.json', x.evidence), '--evaluator', x.evaluatorDigest, '--now', NOW];
  const a = run(flags), b = run(['--assessment-inputs', bundleFile(x), '--now', NOW]);
  assert.equal(a.status, 0, a.stderr); assert.equal(a.stdout, b.stdout);
});

test('a failed critical check exits 2 with the blocker code', () => {
  const x = inputs(); x.evidence[0] = signEvidence(payload(x.manifest, x.profile, 0, { outcome: 'fail' }), keys.privateKey);
  const p = run(['--assessment-inputs', bundleFile(x), '--now', NOW]);
  assert.equal(p.status, 2);
  const s = jsonOf(p.stdout);
  assert.equal(s.decision, 'blocked'); assert.equal(s.reliable, false); assert.deepEqual(s.blockerCodes, ['CRITICAL_CHECK_FAILED']);
});

test('missing evidence exits 2 as insufficient evidence', () => {
  const x = inputs(); x.evidence = [];
  const p = run(['--assessment-inputs', bundleFile(x), '--now', NOW]);
  assert.equal(p.status, 2); assert.equal(jsonOf(p.stdout).decision, 'insufficient-evidence');
});

test('currency only mode exits 0 when the stored assessment is still current', () => {
  const x = inputs();
  const p = run(['--assessment', reportFile(x), '--manifest', put('m.json', x.manifest), '--policy', put('pol.json', x.policy), '--now', NOW]);
  assert.equal(p.status, 0, p.stderr);
  const s = jsonOf(p.stdout); assert.equal(s.mode, 'currency-only'); assert.equal(s.reliable, true);
});

test('currency only mode exits 2 with trigger codes when the subject changed or the assessment expired', () => {
  const x = inputs(), changed = clone(x.manifest); changed.agent.version = '2';
  const a = run(['--assessment', reportFile(x), '--manifest', put('m.json', changed), '--policy', put('pol.json', x.policy), '--now', NOW]);
  assert.equal(a.status, 2); assert.ok(jsonOf(a.stdout).currency.triggers.some(t => t.code === 'SUBJECT_CHANGED'));
  const later = new Date(Date.parse(NOW) + 30 * 3600_000).toISOString();
  const b = run(['--assessment', reportFile(x), '--manifest', put('m.json', x.manifest), '--policy', put('pol.json', x.policy), '--now', later]);
  assert.equal(b.status, 2); assert.ok(jsonOf(b.stdout).currency.triggers.some(t => t.code === 'ASSESSMENT_EXPIRED'));
});

test('an open high severity incident makes a qualified assessment require reassessment', () => {
  const x = inputs();
  const incident = signIncident({ schema: 'kya.incident/v1', id: 'inc-1', subjectDigest: digest(x.manifest), kind: 'report', severity: 'high', refId: null, reportedAt: '2026-10-13T11:30:00.000Z', detailsDigest: hashBytes('private note') }, keys.privateKey);
  const p = run(['--assessment-inputs', bundleFile(x), '--incidents', put('inc.json', [incident]), '--now', NOW]);
  assert.equal(p.status, 2);
  const s = jsonOf(p.stdout); assert.equal(s.decision, 'qualified'); assert.equal(s.reliable, false);
  assert.ok(s.currency.triggers.some(t => t.code === 'INCIDENT_OPEN')); assert.deepEqual(s.currency.incidentsOpen, ['inc-1']);
});

test('usage and input errors exit 1 with a message on stderr', () => {
  const inp = bundleFile();
  for (const args of [[], ['--evil', 'x'], ['--assessment-inputs'], ['--assessment-inputs', join(dir, 'nope.json')], ['--assessment-inputs', put('bad.json', '{nope')], ['--assessment-inputs', inp, '--assessment-inputs', inp], ['--assessment-inputs', inp, '--manifest', inp], ['--assessment-inputs', inp, '--now', 'yesterday'], ['--assessment-inputs', inp, '--fail-on', 'sometimes'], ['--assessment', inp], ['--manifest', inp]]) {
    const p = run(args); assert.equal(p.status, 1, JSON.stringify(args) + ' ' + p.stdout); assert.ok(p.stderr.length > 0);
  }
});

test('an inputs file with unknown members is refused', () => {
  const x = inputs();
  assert.equal(run(['--assessment-inputs', put('extra.json', { ...x, evaluatorDigest, extra: 1 }), '--now', NOW]).status, 1);
});

test('the same arguments with now produce byte identical output', () => {
  const f = bundleFile();
  const a = run(['--assessment-inputs', f, '--now', NOW]), b = run(['--assessment-inputs', f, '--now', NOW]);
  assert.equal(a.stdout, b.stdout); assert.equal(a.status, b.status);
});

// Inputs dated relative to the real clock, for tests that must not pass --now.
const liveFile = () => {
  const x = inputs(), at = Date.now(), iso = ms => new Date(at + ms).toISOString();
  x.manifest.issuedAt = iso(-3600_000); x.manifest.expiresAt = iso(86400_000);
  x.evidence = x.profile.checks.map((_, i) => signEvidence(payload(x.manifest, x.profile, i, { observedAt: iso(-60_000), expiresAt: iso(3600_000) }), keys.privateKey));
  return bundleFile(x);
};

test('omitting now uses the system clock and says so', () => {
  const f = liveFile();
  const p = run(['--assessment-inputs', f]);
  const s = jsonOf(p.stdout); assert.equal(s.clock.source, 'system-clock'); assert.match(s.clock.note, /system clock/i);
  assert.ok(Math.abs(Date.parse(s.clock.now) - Date.now()) < 60000);
});

test('fail-on controls the exit code without changing the summary', () => {
  const x = inputs(), incident = signIncident({ schema: 'kya.incident/v1', id: 'inc-2', subjectDigest: digest(x.manifest), kind: 'report', severity: 'critical', refId: null, reportedAt: '2026-10-13T11:30:00.000Z', detailsDigest: hashBytes('n') }, keys.privateKey);
  const base = ['--assessment-inputs', bundleFile(x), '--incidents', put('inc.json', [incident]), '--now', NOW];
  assert.equal(run(base).status, 2);
  assert.equal(run([...base, '--fail-on', 'unreliable']).status, 2);
  assert.equal(run([...base, '--fail-on', 'not-qualified']).status, 0);
  assert.equal(run([...base, '--fail-on', 'never']).status, 0);
  const bad = clone(x); bad.evidence = [];
  const worse = ['--assessment-inputs', bundleFile(bad), '--now', NOW];
  assert.equal(run([...worse, '--fail-on', 'not-qualified']).status, 2);
  const never = run([...worse, '--fail-on', 'never']); assert.equal(never.status, 0); assert.equal(jsonOf(never.stdout).reliable, false);
});

test('GitHub annotations appear only when GITHUB_ACTIONS is true', () => {
  const x = inputs(); x.evidence[0] = signEvidence(payload(x.manifest, x.profile, 0, { outcome: 'fail' }), keys.privateKey);
  const args = ['--assessment-inputs', bundleFile(x), '--now', NOW];
  assert.equal(run(args).stdout.includes('::error'), false);
  const p = run(args, { GITHUB_ACTIONS: 'true' });
  assert.match(p.stdout, /^::error title=KYA decision/m); assert.match(p.stdout, /CRITICAL_CHECK_FAILED/);
  assert.ok(jsonOf(p.stdout).decision === 'blocked');
  assert.equal(run(['--assessment-inputs', bundleFile(), '--now', NOW], { GITHUB_ACTIONS: 'true' }).stdout.includes('::error'), false);
});

test('annotation text from untrusted names is escaped and cannot start a new command', () => {
  const x = inputs(); x.manifest.agent.name = 'evil %0A::error::pwned,title=x: <script>alert(1)</script>';
  x.profile.checks[0].id = 'x::error::boom';
  x.policy = { ...x.policy, profileDigest: digest(x.profile) };
  x.evidence = x.profile.checks.map((_, i) => signEvidence(payload(x.manifest, x.profile, i, i === 0 ? { outcome: 'fail' } : {}), keys.privateKey));
  const p = run(['--assessment-inputs', bundleFile(x), '--now', NOW], { GITHUB_ACTIONS: 'true' });
  assert.equal(p.status, 2);
  for (const line of p.stdout.split('\n').filter(l => l.startsWith('::'))) assert.match(line, /^::(error|warning|notice) title=[^:,]*::/);
  assert.equal(p.stdout.split('\n').some(l => l.startsWith('::error::pwned')), false);
  assert.match(p.stdout, /x::error::boom/);
});

test('a forged assessment with newlines in text fields cannot inject workflow commands or markdown', () => {
  const x = inputs(), r = assess(x);
  const evil = '\n::error::pwned\n::set-output name=x::y\r\n# injected';
  const file = reportFile(x, { agentName: 'evil' + evil + '[link](http://evil.example)<img src=x>', blockers: [], decision: 'qualified' });
  const summaryFile = join(dir, 'step-forged.md');
  const p = run(['--assessment', file, '--manifest', put('m.json', x.manifest), '--policy', put('pol.json', x.policy), '--now', NOW], { GITHUB_ACTIONS: 'true', GITHUB_STEP_SUMMARY: summaryFile });
  assert.equal(p.status, 0, p.stderr); assert.ok(r.agentName.length > 0);
  for (const line of p.stdout.split('\n')) assert.equal(line.startsWith('::error::pwned') || line.startsWith('::set-output'), false);
  const md = readFileSync(summaryFile, 'utf8');
  assert.equal(md.includes('<img'), false); assert.equal(md.includes('](http'), false); assert.equal(/^# injected/m.test(md), false); assert.equal(/^::/m.test(md), false);
});

test('GITHUB_OUTPUT and GITHUB_STEP_SUMMARY are appended to and carry no secrets', () => {
  const out = join(dir, 'gh-output.txt'), summary = join(dir, 'gh-summary.md');
  writeFileSync(out, 'prior=keep\n'); writeFileSync(summary, 'earlier step\n');
  const p = run(['--assessment-inputs', bundleFile(), '--now', NOW], { GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: summary, GITHUB_TOKEN: 'ghs_SECRETTOKENVALUE', MY_SECRET: 'hunter2hunter2' });
  assert.equal(p.status, 0, p.stderr);
  const o = readFileSync(out, 'utf8'), lines = o.trim().split('\n');
  assert.equal(lines[0], 'prior=keep');
  for (const l of lines) assert.match(l, /^[a-z][a-z-]*=[^\r\n]*$/);
  const kv = Object.fromEntries(lines.slice(1).map(l => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  assert.equal(kv.decision, 'qualified'); assert.equal(kv.reliable, 'true'); assert.equal(kv.current, 'true'); assert.equal(kv.score, '1000'); assert.equal(kv['exit-code'], '0'); assert.equal(kv['clock-source'], 'flag');
  assert.equal(JSON.parse(kv['summary-json']).decision, 'qualified');
  const md = readFileSync(summary, 'utf8');
  assert.ok(md.startsWith('earlier step\n')); assert.match(md, /KYA check/); assert.match(md, /not an authorization grant/i);
  for (const s of [o, md, p.stdout, p.stderr]) { assert.equal(s.includes('SECRETTOKENVALUE'), false); assert.equal(s.includes('hunter2'), false); }
});

test('outputs are written before a failing exit so the workflow can read them', () => {
  const x = inputs(); x.evidence = [];
  const out = join(dir, 'gh-output-fail.txt');
  const p = run(['--assessment-inputs', bundleFile(x), '--now', NOW], { GITHUB_OUTPUT: out });
  assert.equal(p.status, 2);
  const o = readFileSync(out, 'utf8'); assert.match(o, /^decision=insufficient-evidence$/m); assert.match(o, /^reliable=false$/m); assert.match(o, /^exit-code=2$/m); assert.match(o, /^blocker-codes=.*COVERAGE_BELOW_POLICY/m);
});

test('an unwritable GITHUB_OUTPUT path is an input error', () => {
  const p = run(['--assessment-inputs', bundleFile(), '--now', NOW], { GITHUB_OUTPUT: join(dir, 'no-such-dir', 'out.txt') });
  assert.equal(p.status, 1); assert.ok(p.stderr.length > 0);
});

test('system clock use in GitHub Actions raises a warning annotation', () => {
  const p = run(['--assessment-inputs', liveFile()], { GITHUB_ACTIONS: 'true' });
  assert.match(p.stdout, /^::warning title=KYA clock::/m);
});

test('fixture only evidence raises a warning even when the policy qualifies it', () => {
  const p = run(['--assessment-inputs', bundleFile(), '--now', NOW], { GITHUB_ACTIONS: 'true' });
  assert.equal(p.status, 0); assert.match(p.stdout, /^::warning title=KYA evidence::.*fixture/m);
  assert.ok(signerId.length === 64 && publicKey.includes('PUBLIC KEY'));
});
