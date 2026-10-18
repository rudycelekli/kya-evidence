import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { assess, digest, signEvidence, signIncident, hashBytes } from '../src/index.mjs';
import { CORE_PROFILE } from '../src/conformance/index.mjs';
import { githubOutputs } from '../scripts/kya-check.mjs';
import { policy, bundle, inputs, payload, keys, publicKey, signerId, NOW, evaluatorDigest, clone } from './helpers.mjs';

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
  const p = run(['--assessment-inputs', bundleFile(), '--now', NOW, '--allow-fixture']);
  assert.equal(p.status, 0, p.stderr);
  const s = jsonOf(p.stdout);
  assert.equal(s.schema, 'kya.check-summary/v1'); assert.equal(s.decision, 'qualified'); assert.equal(s.reliable, true);
  assert.equal(s.score.earned, 1000); assert.equal(s.coverage, 1); assert.deepEqual(s.blockerCodes, []);
  assert.equal(s.currency.current, true); assert.deepEqual(s.currency.triggers, []);
  assert.equal(s.clock.source, 'flag'); assert.equal(s.clock.now, NOW); assert.equal(s.authenticated, false);
});

test('individual input flags give the same result as an inputs file', () => {
  const x = inputs();
  const flags = ['--manifest', put('m.json', x.manifest), '--profile', put('p.json', x.profile), '--policy', put('pol.json', x.policy), '--evidence', put('e.json', x.evidence), '--evaluator', x.evaluatorDigest, '--now', NOW, '--allow-fixture'];
  const a = run(flags), b = run(['--assessment-inputs', bundleFile(x), '--now', NOW, '--allow-fixture']);
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
  const p = run(['--assessment', reportFile(x), '--manifest', put('m.json', x.manifest), '--policy', put('pol.json', x.policy), '--now', NOW, '--allow-fixture', '--allow-unpinned-assessment']);
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
  const base = ['--assessment-inputs', bundleFile(x), '--incidents', put('inc.json', [incident]), '--now', NOW, '--allow-fixture'];
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
  assert.equal(run(['--assessment-inputs', bundleFile(), '--now', NOW, '--allow-fixture'], { GITHUB_ACTIONS: 'true' }).stdout.includes('::error'), false);
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
  const p = run(['--assessment', file, '--manifest', put('m.json', x.manifest), '--policy', put('pol.json', x.policy), '--now', NOW, '--allow-fixture', '--allow-unpinned-assessment'], { GITHUB_ACTIONS: 'true', GITHUB_STEP_SUMMARY: summaryFile });
  assert.equal(p.status, 0, p.stderr); assert.ok(r.agentName.length > 0);
  for (const line of p.stdout.split('\n')) assert.equal(line.startsWith('::error::pwned') || line.startsWith('::set-output'), false);
  const md = readFileSync(summaryFile, 'utf8');
  assert.equal(md.includes('<img'), false); assert.equal(md.includes('](http'), false); assert.equal(/^# injected/m.test(md), false); assert.equal(/^::/m.test(md), false);
});

test('GITHUB_OUTPUT and GITHUB_STEP_SUMMARY are appended to and carry no secrets', () => {
  const out = join(dir, 'gh-output.txt'), summary = join(dir, 'gh-summary.md');
  writeFileSync(out, 'prior=keep\n'); writeFileSync(summary, 'earlier step\n');
  const p = run(['--assessment-inputs', bundleFile(), '--now', NOW, '--allow-fixture'], { GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: summary, GITHUB_TOKEN: 'ghs_SECRETTOKENVALUE', MY_SECRET: 'hunter2hunter2' });
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
  const p = run(['--assessment-inputs', bundleFile(), '--now', NOW, '--allow-fixture'], { GITHUB_ACTIONS: 'true' });
  assert.equal(p.status, 0); assert.match(p.stdout, /^::warning title=KYA evidence::.*fixture/m);
  assert.ok(signerId.length === 64 && publicKey.includes('PUBLIC KEY'));
});

// Inputs whose evidence comes from the runtime source, optionally mixed with fixture receipts.
const runtimeInputs = (fixtureIndexes = []) => {
  const x = inputs(); x.policy = { ...x.policy, allowedSources: ['runtime', 'fixture'] };
  x.evidence = x.profile.checks.map((_, i) => signEvidence(payload(x.manifest, x.profile, i, { source: fixtureIndexes.includes(i) ? 'fixture' : 'runtime' }), keys.privateKey));
  return x;
};

test('fixture evidence is not reliable by default and exits 2 with a named reason', () => {
  const f = bundleFile(), out = join(dir, 'gh-fixture.md');
  const p = run(['--assessment-inputs', f, '--now', NOW], { GITHUB_ACTIONS: 'true', GITHUB_STEP_SUMMARY: out });
  assert.equal(p.status, 2);
  const s = jsonOf(p.stdout); assert.equal(s.decision, 'qualified'); assert.equal(s.reliable, false); assert.equal(s.exitCode, 2);
  assert.deepEqual(s.reasonCodes, ['FIXTURE_EVIDENCE_NOT_RELIABLE']);
  assert.match(p.stdout, /^::error title=KYA evidence mode::.*FIXTURE_EVIDENCE_NOT_RELIABLE/m);
  assert.match(readFileSync(out, 'utf8'), /FIXTURE\\_EVIDENCE\\_NOT\\_RELIABLE/);
  assert.equal(run(['--assessment-inputs', f, '--now', NOW, '--fail-on', 'not-qualified']).status, 2);
  assert.equal(run(['--assessment-inputs', f, '--now', NOW, '--fail-on', 'never']).status, 0);
});

test('allow-fixture makes qualified fixture evidence reliable and records no reason code', () => {
  const p = run(['--assessment-inputs', bundleFile(), '--now', NOW, '--allow-fixture']);
  assert.equal(p.status, 0, p.stderr); const s = jsonOf(p.stdout); assert.equal(s.reliable, true); assert.deepEqual(s.reasonCodes, []); assert.equal(s.allowFixture, true);
});

test('runtime evidence is reliable without any flag and mixed evidence is not', () => {
  const ok = run(['--assessment-inputs', bundleFile(runtimeInputs()), '--now', NOW]);
  assert.equal(ok.status, 0, ok.stderr); assert.equal(jsonOf(ok.stdout).evidenceMode, 'runtime');
  const f = bundleFile(runtimeInputs([3]));
  const mixed = run(['--assessment-inputs', f, '--now', NOW]);
  assert.equal(mixed.status, 2); assert.equal(jsonOf(mixed.stdout).evidenceMode, 'mixed'); assert.deepEqual(jsonOf(mixed.stdout).reasonCodes, ['MIXED_EVIDENCE_NOT_RELIABLE']);
  assert.equal(run(['--assessment-inputs', f, '--now', NOW, '--allow-fixture']).status, 0);
});

test('a declaration or unknown evidence mode is never reliable even with allow-fixture', () => {
  const x = inputs(), pol = put('pol.json', x.policy), man = put('m.json', x.manifest);
  for (const mode of ['declaration', 'none']) {
    const p = run(['--assessment', reportFile(x, { evidenceMode: mode }), '--manifest', man, '--policy', pol, '--now', NOW, '--allow-fixture', '--allow-unpinned-assessment']);
    assert.equal(p.status, 2, mode); assert.deepEqual(jsonOf(p.stdout).reasonCodes, ['EVIDENCE_MODE_NOT_RELIABLE']);
  }
});

test('policy and evaluator digest pins pass on a match and refuse a mismatch before any summary', () => {
  const x = inputs(), f = bundleFile(x), base = ['--assessment-inputs', f, '--now', NOW, '--allow-fixture'];
  const ok = run([...base, '--expect-policy-digest', digest(x.policy), '--expect-evaluator-digest', x.evaluatorDigest]);
  assert.equal(ok.status, 0, ok.stderr); const s = jsonOf(ok.stdout); assert.equal(s.pins.policyPinned, true); assert.equal(s.pins.evaluatorPinned, true); assert.equal(s.policyDigest, digest(x.policy));
  const unpinned = jsonOf(run(base).stdout); assert.equal(unpinned.pins.policyPinned, false);
  const bad = hashBytes('some other policy');
  const a = run([...base, '--expect-policy-digest', bad]); assert.equal(a.status, 1); assert.match(a.stderr, /POLICY_DIGEST_MISMATCH/); assert.equal(a.stdout, '');
  const b = run([...base, '--expect-evaluator-digest', bad]); assert.equal(b.status, 1); assert.match(b.stderr, /EVALUATOR_DIGEST_MISMATCH/); assert.equal(b.stdout, '');
  assert.equal(run([...base, '--expect-policy-digest', 'abc']).status, 1);
  const gh = run([...base, '--expect-policy-digest', bad], { GITHUB_ACTIONS: 'true' }); assert.match(gh.stdout, /^::error title=KYA usage or input error::POLICY_DIGEST_MISMATCH/m);
});

test('pins also apply in currency only mode and a policy edited after the pin is refused', () => {
  const x = inputs(), args = ['--assessment', reportFile(x), '--manifest', put('m.json', x.manifest), '--policy', put('pol.json', x.policy), '--now', NOW, '--allow-fixture', '--allow-unpinned-assessment'];
  assert.equal(run([...args, '--expect-policy-digest', digest(x.policy), '--expect-evaluator-digest', evaluatorDigest]).status, 0);
  const edited = clone(x.policy); edited.minScore = 0;
  const p = run(['--assessment', reportFile(x), '--manifest', put('m.json', x.manifest), '--policy', put('pol2.json', edited), '--now', NOW, '--allow-fixture', '--allow-unpinned-assessment', '--expect-policy-digest', digest(x.policy)]);
  assert.equal(p.status, 1); assert.match(p.stderr, /POLICY_DIGEST_MISMATCH/);
  assert.equal(run([...args, '--expect-evaluator-digest', hashBytes('other')]).status, 1);
});

test('an oversized summary becomes a compact valid truncated JSON output value', () => {
  const x = inputs(), n = 20;
  const file = reportFile(x, { decision: 'blocked', blockerCodes: Array(n).fill('SCORE_BELOW_POLICY'), blockers: Array(n).fill('B'.repeat(300)) });
  const out = join(dir, 'gh-big.txt');
  const p = run(['--assessment', file, '--manifest', put('m.json', x.manifest), '--policy', put('pol.json', x.policy), '--now', NOW], { GITHUB_OUTPUT: out });
  assert.equal(p.status, 2);
  const line = readFileSync(out, 'utf8').split('\n').find(l => l.startsWith('summary-json='));
  const v = JSON.parse(line.slice('summary-json='.length));
  assert.equal(v.truncated, true); assert.equal(v.decision, 'blocked'); assert.equal(v.reliable, false); assert.equal(v.exitCode, 2); assert.ok(v.blockerCodes.length > 0 && v.blockerCodes.length <= 20);
  assert.ok(line.length <= 4100);
});

// Currency-only mode takes its evidence mode from the assessment file, so a rewritten file must not read as reliable.
const forgedRuntime = x => reportFile(x, { evidenceMode: 'runtime', limitations: [] });
const currencyArgs = (x, file) => ['--assessment', file, '--manifest', put('m.json', x.manifest), '--policy', put('pol.json', x.policy), '--now', NOW];

test('currency only mode withholds reliability without an assessment pin and names the reason', () => {
  const x = inputs(), file = forgedRuntime(x), gh = join(dir, 'gh-unpinned.md');
  const p = run(currencyArgs(x, file), { GITHUB_ACTIONS: 'true', GITHUB_STEP_SUMMARY: gh });
  assert.equal(p.status, 2); const s = jsonOf(p.stdout);
  assert.equal(s.evidenceMode, 'runtime'); assert.equal(s.reliable, false); assert.deepEqual(s.reasonCodes, ['ASSESSMENT_NOT_PINNED']); assert.equal(s.pins.assessmentPinned, false);
  assert.match(p.stdout, /^::error title=KYA assessment pin::ASSESSMENT_NOT_PINNED/m);
  assert.match(readFileSync(gh, 'utf8'), /ASSESSMENT\\_NOT\\_PINNED/);
  const ok = run([...currencyArgs(x, file), '--allow-unpinned-assessment']);
  assert.equal(ok.status, 0, ok.stderr); assert.equal(jsonOf(ok.stdout).allowUnpinnedAssessment, true);
});

test('an assessment pin accepts the pinned file and refuses a rewritten one before any output', () => {
  const x = inputs(), real = reportFile(x, { evidenceMode: 'runtime' }), pin = JSON.parse(readFileSync(real, 'utf8')).reportDigest;
  const ok = run([...currencyArgs(x, real), '--expect-assessment-digest', pin]);
  assert.equal(ok.status, 0, ok.stderr); const s = jsonOf(ok.stdout); assert.equal(s.reliable, true); assert.equal(s.pins.assessmentPinned, true); assert.deepEqual(s.reasonCodes, []);
  const fixtureFile = reportFile(x), fixturePin = JSON.parse(readFileSync(fixtureFile, 'utf8')).reportDigest;
  const forged = run([...currencyArgs(x, forgedRuntime(x)), '--expect-assessment-digest', fixturePin]);
  assert.equal(forged.status, 1); assert.match(forged.stderr, /ASSESSMENT_DIGEST_MISMATCH/); assert.equal(forged.stdout, '');
  assert.equal(run([...currencyArgs(x, real), '--expect-assessment-digest', 'ABC']).status, 1);
});

test('assessment flags are refused outside currency only mode', () => {
  const base = ['--assessment-inputs', bundleFile(), '--now', NOW, '--allow-fixture'];
  assert.equal(run([...base, '--expect-assessment-digest', hashBytes('x')]).status, 1);
  assert.equal(run([...base, '--allow-unpinned-assessment']).status, 1);
});

test('require-pins refuses with PINS_REQUIRED before any output unless every pin is supplied', () => {
  const x = inputs(), base = ['--assessment-inputs', bundleFile(x), '--now', NOW, '--allow-fixture', '--require-pins'];
  const none = run(base); assert.equal(none.status, 1); assert.match(none.stderr, /PINS_REQUIRED/); assert.equal(none.stdout, '');
  const onlyPolicy = run([...base, '--expect-policy-digest', digest(x.policy)]); assert.equal(onlyPolicy.status, 1); assert.match(onlyPolicy.stderr, /PINS_REQUIRED.*evaluator/);
  const onlyEval = run([...base, '--expect-evaluator-digest', x.evaluatorDigest]); assert.equal(onlyEval.status, 1); assert.match(onlyEval.stderr, /PINS_REQUIRED.*policy/);
  const both = run([...base, '--expect-policy-digest', digest(x.policy), '--expect-evaluator-digest', x.evaluatorDigest]); assert.equal(both.status, 0, both.stderr);
  const gh = run(base, { GITHUB_ACTIONS: 'true' }); assert.match(gh.stdout, /^::error title=KYA usage or input error::PINS_REQUIRED/m);
  const file = reportFile(x);
  const cur = run([...currencyArgs(x, file), '--allow-fixture', '--require-pins', '--expect-policy-digest', digest(x.policy), '--expect-evaluator-digest', evaluatorDigest]);
  assert.equal(cur.status, 1); assert.match(cur.stderr, /PINS_REQUIRED.*assessment/);
});

test('manifest and evidence under test can come from separate paths than the policy and profile', () => {
  const x = inputs(), head = join(dir, 'head'), baseDir = join(dir, 'base');
  mkdirSync(head, { recursive: true }); mkdirSync(baseDir, { recursive: true });
  const w = (d, n, v) => { const f = join(d, n); writeFileSync(f, JSON.stringify(v)); return f; };
  const p = run(['--manifest', w(head, 'manifest.json', x.manifest), '--evidence', w(head, 'evidence.json', x.evidence), '--profile', w(baseDir, 'profile.json', x.profile), '--policy', w(baseDir, 'policy.json', x.policy),
    '--evaluator', x.evaluatorDigest, '--expect-policy-digest', digest(x.policy), '--expect-evaluator-digest', x.evaluatorDigest, '--require-pins', '--now', NOW, '--allow-fixture']);
  assert.equal(p.status, 0, p.stderr);
  const changed = clone(x.manifest); changed.agent.version = '9';
  const q = run(['--manifest', w(head, 'm2.json', changed), '--evidence', w(head, 'evidence.json', x.evidence), '--profile', w(baseDir, 'profile.json', x.profile), '--policy', w(baseDir, 'policy.json', x.policy),
    '--evaluator', x.evaluatorDigest, '--expect-policy-digest', digest(x.policy), '--expect-evaluator-digest', x.evaluatorDigest, '--require-pins', '--now', NOW, '--allow-fixture']);
  assert.notEqual(q.status, 0, 'a changed agent must not pass on evidence collected for the old one');
});

test('github outputs carry the evidence mode and allow-fixture flag', () => {
  const out = join(dir, 'gh-modes.txt');
  run(['--assessment-inputs', bundleFile(runtimeInputs()), '--now', NOW], { GITHUB_OUTPUT: out });
  const t = readFileSync(out, 'utf8'); assert.match(t, /^evidence-mode=runtime$/m); assert.match(t, /^allow-fixture=false$/m);
  const out2 = join(dir, 'gh-modes2.txt');
  run(['--assessment-inputs', bundleFile(), '--now', NOW, '--allow-fixture'], { GITHUB_OUTPUT: out2 });
  const t2 = readFileSync(out2, 'utf8'); assert.match(t2, /^evidence-mode=fixture$/m); assert.match(t2, /^allow-fixture=true$/m);
});

test('the truncated summary keeps evidence mode, allow-fixture, pins, decision and capped blocker codes', () => {
  const huge = { schema: 'kya.check-summary/v1', decision: 'blocked', evidenceMode: 'fixture', allowFixture: true, allowUnpinnedAssessment: false, customProfile: true, reliable: false, exitCode: 2,
    score: { earned: 1, possible: 2, upperBound: 3 }, coverage: 0, independentCoverage: 0, blockerCodes: Array(500).fill('SCORE_BELOW_POLICY'), blockers: Array(500).fill('B'.repeat(300)), reasonCodes: ['FIXTURE_EVIDENCE_NOT_RELIABLE'],
    policyDigest: hashBytes('p'), pins: { policyPinned: true, evaluatorPinned: false, assessmentPinned: false },
    currency: { current: false, triggers: Array(40).fill({ code: 'INCIDENT_OPEN' }) }, clock: { source: 'flag' } };
  const line = githubOutputs(huge).split('\n').find(l => l.startsWith('summary-json='));
  const v = JSON.parse(line.slice('summary-json='.length));
  assert.equal(v.truncated, true); assert.equal(v.evidenceMode, 'fixture'); assert.equal(v.allowFixture, true); assert.equal(v.customProfile, true);
  assert.deepEqual(v.pins, huge.pins); assert.equal(v.decision, 'blocked'); assert.equal(v.reliable, false); assert.equal(v.exitCode, 2);
  assert.equal(v.blockerCodes.length, 20); assert.equal(v.triggerCodes.length, 20); assert.ok(line.length <= 4100);
  assert.match(githubOutputs(huge), /^evidence-mode=fixture$/m);
});

test('a policy not built on the frozen core profile is flagged as a custom profile', () => {
  const x = inputs(), gh = join(dir, 'gh-custom.md');
  const p = run(['--assessment-inputs', bundleFile(x), '--now', NOW, '--allow-fixture'], { GITHUB_ACTIONS: 'true', GITHUB_STEP_SUMMARY: gh });
  const s = jsonOf(p.stdout); assert.equal(s.customProfile, true);
  assert.match(p.stdout, /^::warning title=KYA custom profile::/m); assert.match(readFileSync(gh, 'utf8'), /customProfile: true/);
  const core = inputs(); core.profile = CORE_PROFILE; core.policy = policy(CORE_PROFILE); core.evidence = bundle(core.manifest, CORE_PROFILE);
  const q = run(['--assessment-inputs', bundleFile(core), '--now', NOW, '--allow-fixture'], { GITHUB_ACTIONS: 'true' });
  assert.equal(jsonOf(q.stdout).customProfile, false); assert.equal(/KYA custom profile/.test(q.stdout), false);
});

const liveInputs = () => {
  const x = inputs(), at = Date.now(), iso = ms => new Date(at + ms).toISOString();
  x.manifest.issuedAt = iso(-3600_000); x.manifest.expiresAt = iso(86400_000);
  x.evidence = x.profile.checks.map((_, i) => signEvidence(payload(x.manifest, x.profile, i, { observedAt: iso(-60_000), expiresAt: iso(3600_000) }), keys.privateKey));
  return x;
};
const withClock = (x, now) => put('clock-inputs.json', { manifest: x.manifest, profile: x.profile, policy: x.policy, evidence: x.evidence, evaluatorDigest: x.evaluatorDigest, now });
const pinArgs = x => ['--expect-policy-digest', digest(x.policy), '--expect-evaluator-digest', x.evaluatorDigest, '--require-pins', '--allow-fixture'];

test('require-pins ignores the clock member of the inputs file and uses the system clock', () => {
  const x = liveInputs(), f = withClock(x, NOW);
  const s = jsonOf(run(['--assessment-inputs', f, ...pinArgs(x)]).stdout);
  assert.equal(s.clock.source, 'system-clock');
  assert.notEqual(s.clock.now, NOW);
});

test('allow-inputs-clock lets the inputs file clock count under require-pins', () => {
  const x = liveInputs(), f = withClock(x, NOW);
  const s = jsonOf(run(['--assessment-inputs', f, ...pinArgs(x), '--allow-inputs-clock']).stdout);
  assert.equal(s.clock.source, 'inputs-file');
  assert.equal(s.clock.now, NOW);
});

test('without require-pins the inputs file clock is still honoured and an explicit now wins', () => {
  const x = liveInputs(), f = withClock(x, NOW);
  assert.equal(jsonOf(run(['--assessment-inputs', f, '--allow-fixture']).stdout).clock.source, 'inputs-file');
  const s = jsonOf(run(['--assessment-inputs', f, ...pinArgs(x), '--now', NOW]).stdout);
  assert.equal(s.clock.source, 'flag');
});

test('an input path whose parent directory is a symlink out of the workspace is refused', () => {
  const x = inputs(), outside = mkdtempSync(join(tmpdir(), 'kya-outside-')), ws = mkdtempSync(join(tmpdir(), 'kya-ws-'));
  try {
    writeFileSync(join(outside, 'inputs.json'), JSON.stringify({ manifest: x.manifest, profile: x.profile, policy: x.policy, evidence: x.evidence, evaluatorDigest: x.evaluatorDigest }));
    symlinkSync(outside, join(ws, 'link'));
    mkdirSync(join(ws, 'real'));
    writeFileSync(join(ws, 'real', 'inputs.json'), readFileSync(join(outside, 'inputs.json')));
    const at = args => spawnSync(process.execPath, [script, ...args, '--now', NOW, '--allow-fixture'], { cwd: ws, encoding: 'utf8', timeout: 20000, env: { PATH: process.env.PATH } });
    const bad = at(['--assessment-inputs', 'link/inputs.json']);
    assert.equal(bad.status, 1); assert.match(bad.stderr, /outside the workspace/); assert.equal(bad.stdout, '');
    const good = at(['--assessment-inputs', 'real/inputs.json']);
    assert.ok(good.status === 0 || good.status === 2, good.stderr);
  } finally { rmSync(outside, { recursive: true, force: true }); rmSync(ws, { recursive: true, force: true }); }
});
