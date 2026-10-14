import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { assess, signEvidence, verifyAssessment, compareAssessments, checkCurrency, createDossier, validateDossier, digest, keyId, BLOCKER_CODES, CURRENCY_CODES } from '../src/index.mjs';
import { validateReport, parseReport } from '../dashboard/model.mjs';
import { inputs, payload, keys, NOW, FUTURE, clone } from './helpers.mjs';

const legacy = JSON.parse(readFileSync(new URL('./fixtures/legacy-assessment-b3b09bd.json', import.meta.url), 'utf8'));
const codes = report => report.blockerCodes;
const reseal = (report, edit) => { const r = clone(report); delete r.reportDigest; edit(r); return { ...r, reportDigest: digest(r) }; };
const stripCodes = report => reseal(report, r => { delete r.blockerCodes; });
const secondSigner = x => {
  const other = generateKeyPairSync('ed25519'), pem = other.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  x.policy.trustedKeys.push({ id: keyId(pem), publicKey: pem, role: 'self' });
  return other;
};

test('blocker code table is a frozen, stable, upper snake case set', () => {
  assert.ok(Object.isFrozen(BLOCKER_CODES));
  for (const required of ['SUBJECT_REVOKED', 'SUBJECT_EXPIRED', 'CRITICAL_CHECK_FAILED', 'CRITICAL_CHECK_UNPROVEN', 'COVERAGE_BELOW_POLICY', 'INDEPENDENT_COVERAGE_BELOW_POLICY', 'SCORE_BELOW_POLICY', 'AMBIGUOUS_RUNS', 'RUN_CONFLICT', 'RUN_INVALIDATED', 'MIXED_RUN_ISSUERS', 'REPEATED_RUN_CHECKS', 'NO_SCORED_OBSERVATIONS', 'PRINCIPAL_UNBOUND', 'MANDATORY_MINIMUM_NOT_MET'])assert.ok(BLOCKER_CODES.includes(required), required);
  assert.ok(BLOCKER_CODES.every(c => /^[A-Z][A-Z0-9_]+$/.test(c)));
  assert.equal(new Set(BLOCKER_CODES).size, BLOCKER_CODES.length);
});

test('a qualified report carries an empty blocker code list and verifies', () => {
  const r = assess(inputs());
  assert.equal(r.decision, 'qualified'); assert.deepEqual(r.blockers, []); assert.deepEqual(codes(r), []);
  assert.equal(verifyAssessment(r).integrity, true);
});

test('revoked, expired and not yet valid subjects name their own codes', () => {
  const revoked = inputs(); revoked.policy.revokedSubjectDigests = [digest(revoked.manifest)];
  assert.deepEqual(codes(assess(revoked)), ['SUBJECT_REVOKED']);
  const expired = inputs(); expired.now = FUTURE;
  assert.deepEqual(codes(assess(expired)), ['SUBJECT_EXPIRED']);
  const early = inputs(); early.now = '2026-10-13T10:00:00.000Z';
  const r = assess(early); assert.equal(r.decision, 'expired'); assert.deepEqual(codes(r), ['SUBJECT_NOT_YET_VALID']);
});

test('critical failure and critical unproven checks name one code per check', () => {
  const failed = inputs(); failed.evidence[0] = signEvidence(payload(failed.manifest, failed.profile, 0, { outcome: 'fail' }), keys.privateKey);
  failed.evidence[1] = signEvidence(payload(failed.manifest, failed.profile, 1, { outcome: 'fail' }), keys.privateKey);
  const f = assess(failed); assert.equal(f.decision, 'blocked'); assert.deepEqual(codes(f), ['CRITICAL_CHECK_FAILED', 'CRITICAL_CHECK_FAILED']);
  const missing = inputs(); missing.evidence.splice(0, 1);
  const m = assess(missing); assert.equal(m.decision, 'insufficient-evidence'); assert.deepEqual(codes(m), ['CRITICAL_CHECK_UNPROVEN', 'COVERAGE_BELOW_POLICY']);
});

test('coverage, independence and score thresholds each name their code', () => {
  const independent = inputs(); independent.policy.minIndependentCoverage = 1;
  assert.deepEqual(codes(assess(independent)), ['INDEPENDENT_COVERAGE_BELOW_POLICY']);
  const partial = inputs(); partial.evidence.pop();
  assert.deepEqual(codes(assess(partial)), ['COVERAGE_BELOW_POLICY']);
  const score = inputs(); score.policy.minScore = 1000; score.evidence[5] = signEvidence(payload(score.manifest, score.profile, 5, { outcome: 'fail' }), keys.privateKey);
  const r = assess(score); assert.equal(r.decision, 'blocked'); assert.deepEqual(codes(r), ['SCORE_BELOW_POLICY']);
});

test('run integrity failures name ambiguity, conflict, invalidation, mixed issuers and repeats', () => {
  const ambiguous = inputs(); ambiguous.evidence.push(...ambiguous.evidence.map(e => signEvidence({ ...e.payload, runId: 'run-2', id: 'new-' + e.payload.id }, keys.privateKey)));
  assert.ok(codes(assess(ambiguous)).includes('AMBIGUOUS_RUNS'));
  const conflict = inputs(); conflict.evidence.push(conflict.evidence[0]);
  const c = codes(assess(conflict)); assert.ok(c.includes('RUN_CONFLICT')); assert.ok(c.includes('RUN_INVALIDATED'));
  const invalidated = inputs(); invalidated.policy.revokedEvidenceIds = ['evidence-3'];
  assert.ok(codes(assess(invalidated)).includes('RUN_INVALIDATED'));
  const mixed = inputs(); const other = secondSigner(mixed); mixed.evidence[3] = signEvidence(payload(mixed.manifest, mixed.profile, 3), other.privateKey);
  assert.ok(codes(assess(mixed)).includes('MIXED_RUN_ISSUERS'));
  const repeated = inputs(); repeated.now = '2026-10-13T12:00:02.000Z';
  repeated.evidence.push(signEvidence(payload(repeated.manifest, repeated.profile, 3, { id: 'late-pass', observedAt: '2026-10-13T12:00:01.000Z' }), keys.privateKey));
  assert.ok(codes(assess(repeated)).includes('REPEATED_RUN_CHECKS'));
});

test('empty evidence and an unbound principal name their codes', () => {
  const empty = inputs(); empty.evidence = [];
  assert.ok(codes(assess(empty)).includes('NO_SCORED_OBSERVATIONS'));
  const unbound = inputs(); unbound.policy.requirePrincipalBinding = true;
  assert.deepEqual(codes(assess(unbound)), ['PRINCIPAL_UNBOUND']);
});

test('every report keeps exactly one known code per human blocker in the same order', () => {
  const scenarios = [];
  const a = inputs(); a.evidence = []; scenarios.push(a);
  const b = inputs(); b.policy.requirePrincipalBinding = true; b.policy.minIndependentCoverage = 1; scenarios.push(b);
  const c = inputs(); c.evidence[0] = signEvidence(payload(c.manifest, c.profile, 0, { outcome: 'fail' }), keys.privateKey); scenarios.push(c);
  const d = inputs(); d.now = FUTURE; scenarios.push(d);
  for (const x of scenarios) {
    const r = assess(x);
    assert.equal(r.blockerCodes.length, r.blockers.length);
    assert.ok(r.blockerCodes.every(code => BLOCKER_CODES.includes(code)));
  }
});

test('report verification rejects a code list that disagrees with the blockers or is unknown', () => {
  const r = assess(Object.assign(inputs(), { evidence: [] }));
  assert.equal(verifyAssessment(r).integrity, true);
  assert.throws(() => verifyAssessment(reseal(r, x => { x.blockerCodes = x.blockerCodes.slice(1); })), /blocker codes/i);
  assert.throws(() => verifyAssessment(reseal(r, x => { x.blockerCodes[0] = 'NOT_A_CODE'; })), /blocker codes/i);
  assert.throws(() => verifyAssessment(reseal(r, x => { x.blockerCodes = 'SUBJECT_REVOKED'; })), /blocker codes/i);
});

test('legacy reports without blocker codes still verify and keep their original digests', () => {
  for (const kind of ['qualified', 'blocked']) {
    const old = legacy[kind].report;
    assert.equal('blockerCodes' in old, false);
    assert.equal(verifyAssessment(old).integrity, true);
    const { reportDigest, ...body } = old; assert.equal(digest(body), reportDigest);
  }
});

test('a new report equals its legacy report in every field except the added code list', () => {
  for (const kind of ['qualified', 'blocked']) {
    const old = legacy[kind].report, current = assess(legacy[kind].inputs);
    const { reportDigest: oldDigest, ...oldBody } = old, { reportDigest: newDigest, blockerCodes, ...newBody } = current;
    assert.deepEqual(newBody, oldBody);
    assert.notEqual(newDigest, oldDigest);
    assert.equal(blockerCodes.length, old.blockers.length);
  }
});

test('legacy and new reports compare in either order', () => {
  const old = legacy.qualified.report, current = assess(legacy.qualified.inputs);
  assert.equal(compareAssessments(old, current).scoreDelta, 0);
  assert.equal(compareAssessments(current, old).decisionChanged, false);
  const oldBlocked = legacy.blocked.report, newBlocked = assess(legacy.blocked.inputs);
  assert.equal(compareAssessments(oldBlocked, newBlocked).scoreDelta, 0);
});

test('currency accepts legacy and new reports and gives every trigger a stable code', () => {
  const i = legacy.qualified.inputs, ctx = { manifest: i.manifest, policy: i.policy, now: NOW };
  for (const report of [legacy.qualified.report, assess(i)]) {
    const ok = checkCurrency(report, ctx); assert.equal(ok.current, true); assert.equal(ok.action, 'none');
  }
  const report = assess(i);
  const fired = (c, now = NOW) => checkCurrency(report, { ...c, now }).triggers;
  const edited = edit => { const c = clone({ manifest: i.manifest, policy: i.policy }); edit(c); return c; };
  const expectCode = (triggers, id, code) => { const t = triggers.find(x => x.id === id); assert.ok(t, id); assert.equal(t.code, code); };
  expectCode(fired(edited(c => { c.manifest.agent.version = '2'; })), 'subject-changed', 'SUBJECT_CHANGED');
  expectCode(fired(edited(c => { c.policy.minScore = 0; })), 'policy-changed', 'POLICY_CHANGED');
  expectCode(fired(edited(c => { c.policy.revokedSubjectDigests = [report.subjectDigest]; })), 'subject-revoked', 'SUBJECT_REVOKED');
  expectCode(fired(edited(() => {}), new Date(Date.parse(report.validUntil) + 1).toISOString()), 'assessment-expired', 'ASSESSMENT_EXPIRED');
  expectCode(fired(edited(() => {}), new Date(Date.parse(report.assessedAt) - 1).toISOString()), 'clock-regression', 'CLOCK_REGRESSION');
  expectCode(fired(edited(c => { c.policy.maxAssessmentAgeSeconds = 60; }), new Date(Date.parse(report.assessedAt) + 61000).toISOString()), 'assessment-aged', 'ASSESSMENT_AGED');
  assert.ok(Object.isFrozen(CURRENCY_CODES));
  assert.deepEqual(Object.keys(CURRENCY_CODES).sort(), ['assessment-aged', 'assessment-expired', 'clock-regression', 'incident-open', 'policy-changed', 'subject-changed', 'subject-revoked']);
});

test('dossiers accept new reports and legacy reports without codes but reject a mismatched code list', () => {
  const dossier = createDossier({ inputs: Object.assign(inputs(), { evidence: inputs().evidence.slice(0, 5) }) });
  assert.equal(validateDossier(dossier).assessment.blockerCodes.length, dossier.assessment.blockers.length);
  const rebuild = edit => {
    const d = clone(dossier); delete d.dossierDigest; d.assessment = reseal(d.assessment, edit);
    return { ...d, dossierDigest: digest(d) };
  };
  assert.equal(validateDossier(rebuild(a => { delete a.blockerCodes; })).assessment.blockerCodes, undefined);
  assert.throws(() => validateDossier(rebuild(a => { a.blockerCodes = a.blockerCodes.slice(1); })), /blocker codes/i);
  assert.throws(() => validateDossier(rebuild(a => { a.blockerCodes[0] = 'MADE_UP'; })), /blocker codes/i);
});

test('a dossier built from a fully passing run has no blocker codes', () => {
  const d = createDossier({ inputs: inputs() });
  assert.deepEqual(d.assessment.blockerCodes, []); assert.equal(validateDossier(d).assessment.decision, 'qualified');
});

test('the dashboard viewer accepts legacy and new reports and rejects malformed code lists', () => {
  const view = r => ({ ...r, agentName: r.agentName });
  assert.equal(validateReport(view(legacy.blocked.report)).decision, 'blocked');
  const current = assess(legacy.blocked.inputs);
  assert.equal(validateReport(view(current)).blockerCodes.length, 1);
  assert.equal(parseReport(JSON.stringify(current)).blockerCodes[0], 'SCORE_BELOW_POLICY');
  assert.throws(() => validateReport({ ...current, blockerCodes: [] }), /blocker codes/i);
  assert.throws(() => validateReport({ ...current, blockerCodes: [7] }), /blocker codes/i);
  assert.throws(() => validateReport({ ...current, blockerCodes: 'x' }), /blocker codes/i);
});

test('the assessment schema type and docs name the code list', () => {
  const types = readFileSync(new URL('../src/index.d.ts', import.meta.url), 'utf8');
  assert.match(types, /blockerCodes\?:BlockerCode\[\]/); assert.match(types, /export type BlockerCode/);
  const docs = readFileSync(new URL('../docs/SCORING.md', import.meta.url), 'utf8');
  for (const code of BLOCKER_CODES) assert.ok(docs.includes('`' + code + '`'), code);
  for (const code of Object.values(CURRENCY_CODES)) assert.ok(docs.includes('`' + code + '`'), code);
});

test('blocker codes are cross-checked against the report checks, so a resealed code swap is rejected', () => {
  const i = inputs(); i.evidence = i.evidence.map(e => e); // keep inputs shape
  const criticalFail = inputs();
  criticalFail.evidence = criticalFail.evidence.slice();
  const failing = assess({ ...criticalFail, evidence: criticalFail.evidence.map((e, n) => n === 0 ? signEvidence({ ...e.payload, outcome: 'fail' }, keys.privateKey) : e) });
  assert.equal(failing.decision, 'blocked'); assert.ok(codes(failing).includes('CRITICAL_CHECK_FAILED'));
  assert.equal(verifyAssessment(failing).integrity, true);
  const nCritical = failing.checks.filter(c => c.critical && c.status === 'fail').length;
  assert.ok(nCritical > 0);
  // swapping every code for a different one, or hiding the critical failure code, must not verify
  assert.throws(() => verifyAssessment(reseal(failing, x => { x.blockerCodes = x.blockerCodes.map(() => 'SCORE_BELOW_POLICY'); })), /blocker codes/i);
  assert.throws(() => verifyAssessment(reseal(failing, x => { x.blockerCodes = x.blockerCodes.map(c => c === 'CRITICAL_CHECK_FAILED' ? 'COVERAGE_BELOW_POLICY' : c); })), /blocker codes/i);
  // a qualified report cannot carry blockers or codes
  const q = assess(inputs());
  assert.throws(() => verifyAssessment(reseal(q, x => { x.blockers = ['x']; x.blockerCodes = ['SCORE_BELOW_POLICY']; })), /blocker codes/i);
});
