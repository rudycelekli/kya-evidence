import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { assess, signEvidence, keyId, digest, hashBytes, validatePolicy, verifyAssessment } from '../src/index.mjs';
import { verifyCaptureIssuerPolicy } from '../src/campaign/index.mjs';
import { parseTap, mapTapToRequirements } from '../src/conformance-report/index.mjs';
import { inputs, payload, keys, signerId, NOW, clone } from './helpers.mjs';

// Second, independent killers for single-killer controls in assessment, minimums, blocker codes and roles.
// Most go through the public kya-check CLI; the first killers call the library directly.
const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/kya-check.mjs');
const dir = mkdtempSync(join(tmpdir(), 'kya-redundancy-assessment-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
let counter = 0;
const put = (name, value) => { const p = join(dir, (counter++) + '-' + name); writeFileSync(p, JSON.stringify(value)); return p; };
const kya = args => spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', timeout: 20000, env: { PATH: process.env.PATH } });
const jsonOf = p => JSON.parse(p.stdout.split('\n').filter(l => !l.startsWith('::')).join('\n'));
const runInputs = (x, now = NOW) => kya(['--assessment-inputs', put('inputs.json', { manifest: x.manifest, profile: x.profile, policy: x.policy, evidence: x.evidence, evaluatorDigest: x.evaluatorDigest }), '--now', now, '--allow-fixture']);
const reseal = (r, edit) => { const c = clone(r); delete c.reportDigest; edit(c); return { ...c, reportDigest: digest(c) }; };
const currencyOnly = (x, report) => kya(['--assessment', put('assessment.json', report), '--manifest', put('manifest.json', x.manifest), '--policy', put('policy.json', x.policy), '--now', NOW, '--allow-fixture', '--allow-unpinned-assessment']);

test('cli refuses evidence signed by a revoked key and withholds qualification', () => {
  const x = inputs();
  assert.equal(runInputs(x).status, 0);
  x.policy.revokedKeyIds = [signerId];
  const p = runInputs(x), s = jsonOf(p);
  assert.equal(p.status, 2);
  assert.equal(s.decision, 'insufficient-evidence');
  assert.equal(s.reliable, false);
  assert.ok(s.blockerCodes.includes('RUN_INVALIDATED'));
  assert.equal(s.coverage, 0);
});

test('cli blocks an independent pass minimum met only by a self issued receipt', () => {
  const x = inputs(); x.policy.minCoverage = 0.8; x.policy.mandatoryMinimums = [{ checkId: 'check-5', minimum: 'independent-pass' }];
  const p = runInputs(x), s = jsonOf(p);
  assert.equal(p.status, 2);
  assert.equal(s.decision, 'blocked');
  assert.deepEqual(s.blockerCodes, ['MANDATORY_MINIMUM_NOT_MET']);
  const y = clone(x); y.policy.trustedKeys[0].role = 'independent';
  const q = runInputs(y);
  assert.equal(q.status, 0, q.stderr);
  assert.equal(jsonOf(q).decision, 'qualified');
});

test('cli keeps revoked and expired subjects on their own decision despite an unmet minimum', () => {
  const x = inputs(); x.policy.mandatoryMinimums = [{ checkId: 'check-5', minimum: 'independent-pass' }];
  const revoked = clone(x); revoked.policy.revokedSubjectDigests = [digest(x.manifest)];
  const r = jsonOf(runInputs(revoked));
  assert.equal(r.decision, 'revoked'); assert.deepEqual(r.blockerCodes, ['SUBJECT_REVOKED']);
  const e = assess({ ...x, now: '2026-10-15T00:00:00.000Z' });
  assert.equal(e.decision, 'expired'); assert.deepEqual(e.blockerCodes, ['SUBJECT_EXPIRED']);
  const live = jsonOf(runInputs(x));
  assert.equal(live.decision, 'blocked'); assert.deepEqual(live.blockerCodes, ['MANDATORY_MINIMUM_NOT_MET']);
});

test('a minimum naming a check outside the profile is refused even for a revoked or expired subject', () => {
  const x = inputs(); x.policy.mandatoryMinimums = [{ checkId: 'check-404', minimum: 'pass' }];
  assert.throws(() => assess({ ...x, now: NOW }), /mandatory minimum names a check outside the frozen profile/i);
  const revoked = clone(x); revoked.policy.revokedSubjectDigests = [digest(x.manifest)];
  assert.throws(() => assess({ ...revoked, now: NOW }), /outside the frozen profile/i);
  assert.throws(() => assess({ ...x, now: '2026-10-15T00:00:00.000Z' }), /outside the frozen profile/i);
  const cli = runInputs(x);
  assert.equal(cli.status, 1);
  assert.match(cli.stderr, /outside the frozen profile/);
});

test('duplicate mandatory minimums are refused by the policy validator, assessment and cli', () => {
  const dup = [{ checkId: 'check-5', minimum: 'pass' }, { checkId: 'check-5', minimum: 'pass' }];
  const x = inputs(); x.policy.mandatoryMinimums = dup;
  assert.throws(() => validatePolicy(x.policy), /duplicate/i);
  assert.throws(() => assess({ ...x, now: NOW }), /duplicate/i);
  const p = runInputs(x);
  assert.equal(p.status, 1);
  assert.match(p.stderr, /duplicate/i);
  const ok = inputs(); ok.policy.mandatoryMinimums = [dup[0]];
  assert.equal(runInputs(ok).status, 0);
});

test('cli refuses a resealed blocker code swap that hides a critical failure', () => {
  const x = inputs(); x.evidence[0] = signEvidence(payload(x.manifest, x.profile, 0, { outcome: 'fail' }), keys.privateKey);
  const report = assess({ ...x, now: NOW });
  assert.deepEqual(report.blockerCodes, ['CRITICAL_CHECK_FAILED']);
  assert.equal(currencyOnly(x, report).status, 2);
  const swapped = reseal(report, r => { r.blockerCodes = ['SCORE_BELOW_POLICY']; });
  assert.doesNotThrow(() => JSON.stringify(swapped));
  const p = currencyOnly(x, swapped);
  assert.equal(p.status, 1);
  assert.match(p.stderr, /blocker codes/i);
});

test('verifyAssessment refuses a critical blocker code that no failed critical check backs', () => {
  const x = inputs(); x.policy.minCoverage = 0.8; x.policy.minScore = 900;
  x.evidence[5] = signEvidence(payload(x.manifest, x.profile, 5, { outcome: 'fail' }), keys.privateKey);
  const report = assess({ ...x, now: NOW });
  assert.deepEqual(report.blockerCodes, ['SCORE_BELOW_POLICY']);
  assert.equal(verifyAssessment(report).integrity, true);
  assert.throws(() => verifyAssessment(reseal(report, r => { r.blockerCodes = ['CRITICAL_CHECK_FAILED']; })), /critical failure count/i);
  assert.throws(() => verifyAssessment(reseal(report, r => { r.blockerCodes = ['SCORE_BELOW_POLICY', 'SCORE_BELOW_POLICY']; })));
});

test('cli never qualifies when the only trusted signer holds the capture issuer role', () => {
  const x = inputs(), cap = generateKeyPairSync('ed25519'), pem = cap.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  x.policy.trustedKeys = [{ id: keyId(pem), publicKey: pem, role: 'capture-issuer' }];
  x.evidence = x.profile.checks.map((_, i) => signEvidence(payload(x.manifest, x.profile, i), cap.privateKey));
  const p = runInputs(x), s = jsonOf(p);
  assert.equal(p.status, 2);
  assert.notEqual(s.decision, 'qualified');
  assert.equal(s.reliable, false);
  assert.equal(s.coverage, 0);
  assert.equal(s.score.earned, 0);
});

test('one capture issuer receipt among trusted receipts leaves its check unscored', () => {
  const x = inputs(), cap = generateKeyPairSync('ed25519'), pem = cap.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  x.policy.trustedKeys.push({ id: keyId(pem), publicKey: pem, role: 'capture-issuer' });
  x.evidence[5] = signEvidence(payload(x.manifest, x.profile, 5), cap.privateKey);
  const r = assess({ ...x, now: NOW });
  assert.equal(r.checks[5].status, 'unknown');
  assert.equal(r.rejectedEvidence.length, 1);
  assert.equal(r.rejectedEvidence[0].index, 5);
  assert.notEqual(r.decision, 'qualified');
});

test('capture issuer policy check inspects every issuer anchor for evidence signer and evaluator clashes', () => {
  const a = generateKeyPairSync('ed25519'), b = generateKeyPairSync('ed25519');
  const pa = a.publicKey.export({ format: 'pem', type: 'spki' }).toString(), pb = b.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const policy = inputs().policy;
  policy.trustedKeys = [{ id: keyId(pa), publicKey: pa, role: 'capture-issuer' }, { id: keyId(pb), publicKey: pb, role: 'capture-issuer' }, policy.trustedKeys[0]];
  assert.deepEqual(verifyCaptureIssuerPolicy({ policy, evidenceKeyIds: [signerId] }).sort(), [keyId(pa), keyId(pb)].sort());
  assert.throws(() => verifyCaptureIssuerPolicy({ policy, evidenceKeyIds: [signerId, keyId(pb)] }), /cannot sign scoring evidence/);
  assert.throws(() => verifyCaptureIssuerPolicy({ policy, evidenceKeyIds: [keyId(pa)], evaluatorKeyId: hashBytes('elsewhere') }), /cannot sign scoring evidence/);
  assert.throws(() => verifyCaptureIssuerPolicy({ policy, evaluatorKeyId: keyId(pb) }), /cannot be the evaluator key/);
});

test('conformance mapping withholds pass when the process outcome disagrees with clean tap output', () => {
  const reg = { requirements: [
    { id: 'KYA-AAA-001', tests: [{ file: 'one.test.mjs', title: 'alpha' }, { file: 'two.test.mjs', title: 'beta' }] },
    { id: 'KYA-AAA-002', tests: [{ file: 'one.test.mjs', title: 'alpha' }] },
    { id: 'KYA-AAA-003', tests: [{ file: 'two.test.mjs', title: 'beta' }] }
  ] };
  const clean = parseTap('TAP version 13\nok 1 - alpha\n1..1\n'), other = parseTap('ok 1 - beta\n');
  assert.deepEqual(clean, [{ title: 'alpha', status: 'pass' }]);
  const healthy = mapTapToRequirements(reg, { 'one.test.mjs': { exitCode: 0, tests: clean }, 'two.test.mjs': { exitCode: 0, tests: other } });
  assert.deepEqual(Object.values(healthy).map(r => r.result), ['pass', 'pass', 'pass']);
  for (const bad of [{ exitCode: 137, tests: other }, { exitCode: null, tests: other }, { exitCode: 0, error: 'ETIMEDOUT', tests: other }, { exitCode: 2, error: 'ENOBUFS', tests: other }]) {
    const r = mapTapToRequirements(reg, { 'one.test.mjs': { exitCode: 0, tests: clean }, 'two.test.mjs': bad });
    assert.equal(r['KYA-AAA-001'].result, 'not-run');
    assert.equal(r['KYA-AAA-002'].result, 'pass');
    assert.equal(r['KYA-AAA-003'].result, 'not-run');
    assert.deepEqual(r['KYA-AAA-003'].executed, []);
  }
});
