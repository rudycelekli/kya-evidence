import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, readdirSync, existsSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { assess, digest, signEvidence, validatePolicy, keyId, hashBytes } from '../src/index.mjs';
import { manifest, payload, keys, publicKey, evaluatorDigest, FUTURE } from './helpers.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/kya-policy-init.mjs');
const TEMPLATES = ['code-agent', 'agentic-payments', 'read-only-assistant'];
const CORE = JSON.parse(readFileSync(join(root, 'profiles/core-v1.json'), 'utf8'));
const dir = mkdtempSync(join(tmpdir(), 'kya-policy-init-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
let counter = 0;
const path = name => join(dir, `${counter++}-${name}`);
const put = (name, value) => { const p = path(name); writeFileSync(p, typeof value === 'string' ? value : JSON.stringify(value)); return p; };
const run = args => spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', timeout: 20000, env: { PATH: process.env.PATH } });
const profileFile = put('profile.json', CORE);
const selfPub = put('self.pem', publicKey);
const indKeys = generateKeyPairSync('ed25519');
const indPem = indKeys.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const indPub = put('ind.pem', indPem);
const privPem = keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
const privFile = put('private.pem', privPem);
const generate = (template, extra = [], trust = ['independent:' + indPub, 'self:' + selfPub]) => {
  const out = path('policy.json');
  const p = run(['--template', template, '--profile', profileFile, ...trust.flatMap(t => ['--trust-key', t]), ...extra, '--out', out]);
  return { p, out, policy: p.status === 0 ? JSON.parse(readFileSync(out, 'utf8')) : null };
};
// A manifest in the default scope, optionally naming an accountable party.
const subject = party => { const m = manifest(); m.scope.id = 'local-readonly'; if (party) m.principal.accountableParty = { kind: 'natural-person', ref: 'person-ref-0001' }; return m; };
const evidenceFor = (m, { source = 'runtime', signer = indKeys.privateKey, patch = () => ({}) } = {}) =>
  CORE.checks.map((c, i) => signEvidence(payload(m, CORE, i, { source, ...patch(c, i) }), signer));
const assessWith = (policy, m, evidence) => assess({ manifest: m, profile: CORE, policy, evidence, evaluatorDigest, now: '2026-10-13T12:00:00.000Z' });

test('every template file is valid JSON with a rationale explicit limits and a not validated flag', () => {
  const files = readdirSync(join(root, 'policies/templates')).sort();
  assert.deepEqual(files, TEMPLATES.map(t => t + '.json').sort());
  for (const t of TEMPLATES) {
    const v = JSON.parse(readFileSync(join(root, 'policies/templates', t + '.json'), 'utf8'));
    assert.equal(v.schema, 'kya.policy-template/v1'); assert.equal(v.id, t); assert.equal(v.notValidated, true); assert.equal(v.targetProfileId, 'kya-core');
    assert.ok(v.rationale.length > 40); assert.ok(v.limits.length >= 4);
    assert.ok(v.limits.some(l => /no template makes an agent safe/i.test(l))); assert.ok(v.limits.some(l => /not a validated threshold/i.test(l)));
  }
});

test('each template generates a policy that passes validatePolicy and binds the real profile digest', () => {
  for (const t of TEMPLATES) {
    const { p, policy } = generate(t);
    assert.equal(p.status, 0, p.stderr);
    assert.doesNotThrow(() => validatePolicy(policy));
    assert.equal(policy.profileDigest, digest(CORE)); assert.equal(policy.scopeId, 'local-readonly');
    assert.deepEqual(policy.trustedKeys.map(k => k.role).sort(), ['independent', 'self']);
    for (const m of policy.mandatoryMinimums) assert.ok(CORE.checks.some(c => c.id === m.checkId));
    const s = JSON.parse(p.stdout); assert.equal(s.notValidated, true); assert.equal(s.policyDigest, digest(policy)); assert.equal(s.profileDigest, digest(CORE));
  }
});

test('templates are conservative and never accept fixture or declaration evidence', () => {
  for (const t of TEMPLATES) {
    const { policy } = generate(t);
    assert.deepEqual(policy.allowedSources, ['runtime']);
    assert.ok(policy.minCoverage >= 0.9); assert.ok(policy.minScore >= 800); assert.ok(policy.maxEvidenceAgeSeconds <= 604800);
    assert.ok(policy.mandatoryMinimums.length >= 4);
  }
  const pay = generate('agentic-payments').policy, code = generate('code-agent').policy, ro = generate('read-only-assistant').policy;
  assert.equal(pay.minIndependentCoverage, 1); assert.equal(pay.requirePrincipalBinding, true); assert.ok(pay.maxEvidenceAgeSeconds <= 3600);
  assert.equal(code.requirePrincipalBinding, true); assert.ok(code.minIndependentCoverage >= 0.5);
  assert.ok(pay.minScore >= code.minScore && code.minScore >= ro.minScore);
  assert.equal(ro.requirePrincipalBinding, false);
});

test('fixture evidence never qualifies any template even when its signer is trusted', () => {
  for (const t of TEMPLATES) {
    const { policy } = generate(t), m = subject(true);
    const r = assessWith(policy, m, evidenceFor(m, { source: 'fixture' }));
    assert.notEqual(r.decision, 'qualified', t); assert.equal(r.coverage, 0, t); assert.ok(r.blockerCodes.includes('NO_SCORED_OBSERVATIONS'), t); assert.ok(r.blockerCodes.includes('MANDATORY_MINIMUM_UNPROVEN'), t);
    assert.ok(r.rejectedEvidence.every(e => e.reason === 'Evidence source is disallowed'), t);
  }
});

test('self signed runtime evidence qualifies the read only template and nothing stricter', () => {
  const m = subject(false), ev = evidenceFor(m, { signer: keys.privateKey });
  const ro = assessWith(generate('read-only-assistant').policy, m, ev);
  assert.equal(ro.decision, 'qualified', JSON.stringify(ro.blockers));
  const code = assessWith(generate('code-agent').policy, subject(true), evidenceFor(subject(true), { signer: keys.privateKey }));
  assert.notEqual(code.decision, 'qualified'); assert.ok(code.blockerCodes.includes('INDEPENDENT_COVERAGE_BELOW_POLICY'));
});

test('independent runtime evidence with a declared accountable party qualifies code agent and payments', () => {
  for (const t of ['code-agent', 'agentic-payments']) {
    const m = subject(true), r = assessWith(generate(t).policy, m, evidenceFor(m));
    assert.equal(r.decision, 'qualified', t + JSON.stringify(r.blockers)); assert.equal(r.independentCoverage, 1);
  }
});

test('an undeclared accountable party withholds the code agent and payments templates', () => {
  for (const t of ['code-agent', 'agentic-payments']) {
    const m = subject(false), r = assessWith(generate(t).policy, m, evidenceFor(m));
    assert.equal(r.decision, 'insufficient-evidence', t); assert.ok(r.blockerCodes.includes('PRINCIPAL_UNBOUND'), t);
  }
});

test('stale runtime evidence is refused by the payments template within its short window', () => {
  const m = subject(true), { policy } = generate('agentic-payments');
  const old = evidenceFor(m, { patch: () => ({ observedAt: '2026-10-13T11:00:00.000Z', expiresAt: FUTURE }) });
  const r = assessWith(policy, m, old);
  assert.notEqual(r.decision, 'qualified'); assert.ok(r.rejectedEvidence.some(e => e.reason === 'Evidence exceeds freshness policy'));
});

test('a failed non critical mandatory check blocks the payments template with a named code', () => {
  const m = subject(true), { policy } = generate('agentic-payments');
  const r = assessWith(policy, m, evidenceFor(m, { patch: c => (c.id === 'operations.budget' ? { outcome: 'fail' } : {}) }));
  assert.equal(r.decision, 'blocked'); assert.ok(r.blockerCodes.includes('MANDATORY_MINIMUM_NOT_MET'));
});

test('a failed critical check blocks every template', () => {
  for (const t of TEMPLATES) {
    const m = subject(true), r = assessWith(generate(t).policy, m, evidenceFor(m, { patch: c => (c.id === 'security.secrets' ? { outcome: 'fail' } : {}) }));
    assert.equal(r.decision, 'blocked', t); assert.ok(r.blockerCodes.includes('CRITICAL_CHECK_FAILED'), t);
  }
});

test('output is deterministic and carries no clock or key material', () => {
  const a = generate('code-agent'), b = generate('code-agent');
  assert.equal(readFileSync(a.out, 'utf8'), readFileSync(b.out, 'utf8')); assert.equal(a.p.stdout.replaceAll(a.out, 'X'), b.p.stdout.replaceAll(b.out, 'X'));
  const text = readFileSync(a.out, 'utf8'); assert.equal(text.includes('PRIVATE'), false); assert.equal(/\d{4}-\d{2}-\d{2}T/.test(text), false);
  const reordered = generate('code-agent', [], ['self:' + selfPub, 'independent:' + indPub]);
  assert.equal(digest(reordered.policy), digest(a.policy));
});

test('overrides can tighten a template and the flags are honoured', () => {
  const { policy, p } = generate('read-only-assistant', ['--require-principal-binding', '--mandatory-minimum', 'reliability.task:independent-pass', '--mandatory-minimum', 'security.secrets:independent-pass', '--max-assessment-age-seconds', '3600', '--scope-id', 'scope:test', '--id', 'my-policy']);
  assert.equal(p.status, 0, p.stderr);
  assert.equal(policy.requirePrincipalBinding, true); assert.equal(policy.maxAssessmentAgeSeconds, 3600); assert.equal(policy.scopeId, 'scope:test'); assert.equal(policy.id, 'my-policy');
  assert.deepEqual(policy.mandatoryMinimums.find(x => x.checkId === 'security.secrets'), { checkId: 'security.secrets', minimum: 'independent-pass' });
  assert.deepEqual(policy.mandatoryMinimums.find(x => x.checkId === 'reliability.task'), { checkId: 'reliability.task', minimum: 'independent-pass' });
  const m = subject(false); m.scope.id = 'scope:test'; m.principal.accountableParty = { kind: 'natural-person', ref: 'p' };
  const r = assessWith(policy, m, evidenceFor(m, { signer: keys.privateKey }));
  assert.equal(r.decision, 'blocked'); assert.ok(r.blockerCodes.includes('MANDATORY_MINIMUM_NOT_MET'));
});

test('unknown templates and path tricks are refused', () => {
  for (const t of ['nope', '../code-agent', 'code-agent.json', 'CODE-AGENT', '', '/etc/passwd']) {
    const out = path('x.json'), p = run(['--template', t, '--profile', profileFile, '--trust-key', 'self:' + selfPub, '--out', out]);
    assert.equal(p.status, 1, JSON.stringify(t)); assert.equal(existsSync(out), false);
  }
});

test('trust key problems are refused without echoing key material', () => {
  const base = ['--template', 'read-only-assistant', '--profile', profileFile];
  const cases = [
    [...base, '--out', path('o.json')],
    [...base, '--trust-key', 'admin:' + selfPub, '--out', path('o.json')],
    [...base, '--trust-key', selfPub, '--out', path('o.json')],
    [...base, '--trust-key', 'self:' + join(dir, 'missing.pem'), '--out', path('o.json')],
    [...base, '--trust-key', 'self:' + privFile, '--out', path('o.json')],
    [...base, '--trust-key', 'self:' + selfPub, '--trust-key', 'independent:' + selfPub, '--out', path('o.json')],
    [...base, '--trust-key', 'self:' + put('junk.pem', 'not a key'), '--out', path('o.json')],
  ];
  for (const args of cases) { const p = run(args); assert.equal(p.status, 1, args.join(' ')); assert.equal(p.stderr.includes('PRIVATE KEY'), false); assert.equal(p.stderr.includes(privPem.split('\n')[1]), false); }
});

test('templates that need independent evidence are refused without an independent key', () => {
  for (const t of ['code-agent', 'agentic-payments']) { const { p } = generate(t, [], ['self:' + selfPub]); assert.equal(p.status, 1, t); assert.match(p.stderr, /independent/i); }
  assert.equal(generate('read-only-assistant', [], ['self:' + selfPub]).p.status, 0);
  assert.equal(generate('read-only-assistant', ['--mandatory-minimum', 'reliability.task:independent-pass'], ['self:' + selfPub]).p.status, 1);
});

test('weakening a template or naming unknown checks is refused', () => {
  assert.equal(generate('code-agent', ['--mandatory-minimum', 'authority.approval:pass']).p.status, 1);
  assert.equal(generate('code-agent', ['--mandatory-minimum', 'no.such-check:pass']).p.status, 1);
  assert.equal(generate('code-agent', ['--mandatory-minimum', 'authority.approval:maybe']).p.status, 1);
  assert.equal(generate('code-agent', ['--mandatory-minimum', 'authority.approval']).p.status, 1);
  assert.equal(generate('code-agent', ['--max-assessment-age-seconds', '999999']).p.status, 1);
  for (const bad of ['0', '-5', '1.5', 'abc', '']) assert.equal(generate('code-agent', ['--max-assessment-age-seconds', bad]).p.status, 1, bad);
  assert.equal(generate('code-agent', ['--max-assessment-age-seconds', '600']).p.status, 0);
  assert.equal(generate('code-agent', ['--unknown-flag', 'x']).p.status, 1);
  assert.equal(generate('code-agent', ['--scope-id', 'bad scope']).p.status, 1);
});

test('a profile missing the template checks or an existing output file is refused', () => {
  const small = put('small.json', { ...CORE, checks: CORE.checks.slice(0, 3) });
  const out = path('o.json'), p = run(['--template', 'code-agent', '--profile', small, '--trust-key', 'independent:' + indPub, '--out', out]);
  assert.equal(p.status, 1); assert.match(p.stderr, /profile/i); assert.equal(existsSync(out), false);
  const first = generate('code-agent'); const again = run(['--template', 'code-agent', '--profile', profileFile, '--trust-key', 'independent:' + indPub, '--out', first.out]);
  assert.equal(again.status, 1); assert.equal(hashBytes(readFileSync(first.out)), hashBytes(JSON.stringify(first.policy, null, 2) + '\n'));
  assert.equal(keyId(indPem).length, 64);
});

test('a profile other than the frozen core profile is refused without allow-custom-profile', () => {
  // The four checks the strictest mandatory minimums need would still leave a smaller denominator.
  const subset = put('subset.json', { ...CORE, checks: CORE.checks.filter(c => ['security.secrets', 'security.injection', 'authority.refusal', 'accountability.tamper'].includes(c.id)) });
  const reweighted = put('reweighted.json', { ...CORE, checks: CORE.checks.map(c => (c.id === 'operations.budget' ? { ...c, weight: 50 } : c)) });
  for (const f of [subset, reweighted]) {
    const out = path('o.json'), p = run(['--template', 'read-only-assistant', '--profile', f, '--trust-key', 'self:' + selfPub, '--out', out]);
    assert.equal(p.status, 1); assert.match(p.stderr, /allow-custom-profile/); assert.equal(existsSync(out), false);
  }
});

test('allow-custom-profile generates a policy with a prominent warning and a marked id', () => {
  const reweighted = put('reweighted2.json', { ...CORE, checks: CORE.checks.map(c => (c.id === 'operations.budget' ? { ...c, weight: 50 } : c)) });
  const out = path('o.json'), p = run(['--template', 'read-only-assistant', '--profile', reweighted, '--trust-key', 'self:' + selfPub, '--allow-custom-profile', '--out', out]);
  assert.equal(p.status, 0, p.stderr);
  const s = JSON.parse(p.stdout), policy = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(s.customProfile, true); assert.match(s.warnings[0], /CUSTOM PROFILE/); assert.equal(policy.id, 'template-read-only-assistant-custom-profile');
  assert.equal(policy.profileDigest, digest(JSON.parse(readFileSync(reweighted, 'utf8'))));
  assert.equal(JSON.parse(run(['--template', 'read-only-assistant', '--profile', profileFile, '--trust-key', 'self:' + selfPub, '--out', path('c.json')]).stdout).customProfile, false);
  const missing = put('missing.json', { ...CORE, checks: CORE.checks.slice(0, 3) });
  assert.equal(run(['--template', 'read-only-assistant', '--profile', missing, '--trust-key', 'self:' + selfPub, '--allow-custom-profile', '--out', path('d.json')]).status, 1);
});

test('the template documentation states these are starting points and no template makes an agent safe', () => {
  const doc = readFileSync(join(root, 'docs/POLICY-TEMPLATES.md'), 'utf8');
  assert.match(doc, /starting points/i); assert.match(doc, /not validated thresholds/i); assert.match(doc, /no template makes an agent safe/i);
  for (const t of TEMPLATES) assert.ok(doc.includes('`' + t + '`'));
  const gh = readFileSync(join(root, 'docs/GITHUB-ACTION.md'), 'utf8');
  assert.match(gh, /does not prove/i); assert.match(gh, /exit code 2/i);
  assert.match(gh, /base branch or a protected path/i); assert.match(gh, /never from the code under test/i); assert.match(gh, /--expect-policy-digest/); assert.match(gh, /--allow-fixture/);
  const wf = readFileSync(join(root, 'docs/examples/kya-check.workflow.yml'), 'utf8');
  assert.match(wf, /expect-policy-digest/); assert.match(wf, /expect-evaluator-digest/); assert.match(wf, /require-pins: 'true'/); assert.equal(/ref: \$\{\{ github\.head_ref/.test(wf), false);
  assert.match(wf, /base\.sha/); assert.match(wf, /pull_request\.head\.sha/); assert.match(wf, /path: base/); assert.match(wf, /path: head/);
  assert.match(wf, /policy: base\//); assert.match(wf, /profile: base\//); assert.match(wf, /manifest: head\//); assert.match(wf, /evidence: head\//);
  assert.equal(/assessment-inputs/.test(wf.replace(/^\s*#.*$/gm, '')), false, 'the gate must not read a single bundle from one checkout');
  const uses = [...wf.matchAll(/uses: (\S+)/g)].map(m => m[1]);
  for (const u of uses.filter(u => u.startsWith('actions/'))) assert.match(u, /@[0-9a-f]{40}$/);
  assert.ok(uses.some(u => u.startsWith('actions/checkout@')));
  assert.match(gh, /--expect-assessment-digest/); assert.match(gh, /ASSESSMENT_NOT_PINNED/); assert.match(gh, /only as trustworthy as the assessment file/i); assert.match(gh, /--require-pins/); assert.match(gh, /PINS_REQUIRED/);
  assert.match(gh, /manifest and evidence under test come from the pull request head/i); assert.match(gh, /customProfile/); assert.match(gh, /no field/i);
  const action = readFileSync(join(root, 'action/action.yml'), 'utf8');
  assert.match(action, /actions\/setup-node@[0-9a-f]{40} # v4/);
  for (const k of ['allow-fixture', 'expect-policy-digest', 'expect-evaluator-digest', 'expect-assessment-digest', 'allow-unpinned-assessment', 'require-pins', 'evidence-mode']) assert.ok(action.includes(k + ':'), k);
  assert.match(action, /require-pins:\n(?:.*\n){2}\s+default: 'true'/);
  assert.match(doc, /allow-custom-profile/);
});
