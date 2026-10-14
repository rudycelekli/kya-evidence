import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assess, signEvidence, checkCurrency, createDossier, validateDossier, validatePolicy, digest } from '../src/index.mjs';
import { inputs, payload, keys, NOW, clone } from './helpers.mjs';

const CODE = 'MANDATORY_MINIMUM_NOT_MET';
// Check 5 is non-critical with weight 1 of 6: a missing or failed check 5 still leaves a policy-qualifying score of 833.
const lenient = (minimums, edit = () => {}) => {
  const x = inputs(); x.policy.minCoverage = 0.8; x.policy.minScore = 800;
  if (minimums !== undefined) x.policy.mandatoryMinimums = minimums;
  edit(x); return x;
};
const fail5 = x => { x.evidence[5] = signEvidence(payload(x.manifest, x.profile, 5, { outcome: 'fail' }), keys.privateKey); };

test('an absent mandatory minimums field leaves policy digests and decisions unchanged', () => {
  const x = lenient(); fail5(x);
  assert.equal('mandatoryMinimums' in validatePolicy(x.policy), false);
  const r = assess(x); assert.equal(r.decision, 'qualified'); assert.equal(r.score.earned, 833); assert.deepEqual(r.blockerCodes, []);
  const base = inputs(), withField = clone(base); withField.policy.mandatoryMinimums = [{ checkId: 'check-5', minimum: 'pass' }];
  assert.notEqual(assess(withField).policyDigest, assess(base).policyDigest);
  assert.equal(assess(base).policyDigest, digest(base.policy));
});

test('passing every mandatory check qualifies exactly as without the field', () => {
  const plain = assess(lenient()), gated = assess(lenient([{ checkId: 'check-5', minimum: 'pass' }, { checkId: 'check-0', minimum: 'pass' }]));
  assert.equal(gated.decision, 'qualified'); assert.deepEqual(gated.blockerCodes, []); assert.equal(gated.score.earned, plain.score.earned);
});

test('a failed mandatory check blocks regardless of a passing score and names its code', () => {
  const r = assess(lenient([{ checkId: 'check-5', minimum: 'pass' }], fail5));
  assert.equal(r.decision, 'blocked'); assert.equal(r.score.earned, 833); assert.ok(r.score.earned >= 800);
  assert.deepEqual(r.blockerCodes, [CODE]); assert.match(r.blockers[0], /check-5/);
});

test('a missing or abstaining mandatory check blocks instead of staying unknown', () => {
  const missing = lenient([{ checkId: 'check-5', minimum: 'pass' }], x => x.evidence.pop());
  assert.equal(assess(lenient(undefined, x => x.evidence.pop())).decision, 'qualified');
  const m = assess(missing); assert.equal(m.decision, 'blocked'); assert.deepEqual(m.blockerCodes, [CODE]);
  const abstain = lenient([{ checkId: 'check-5', minimum: 'pass' }], x => { x.evidence[5] = signEvidence(payload(x.manifest, x.profile, 5, { outcome: 'abstain' }), keys.privateKey); });
  assert.equal(assess(abstain).decision, 'blocked');
});

test('removing evidence for a mandatory check can never lift the cap', () => {
  const failing = lenient([{ checkId: 'check-5', minimum: 'pass' }], fail5);
  assert.equal(assess(failing).decision, 'blocked');
  const removed = clone(failing); removed.evidence.pop();
  assert.equal(assess(removed).decision, 'blocked');
  const none = clone(failing); none.evidence = [];
  const r = assess(none); assert.equal(r.decision, 'blocked'); assert.ok(r.blockerCodes.includes(CODE));
});

test('the independent pass threshold separates self issued from independent evidence', () => {
  const selfIssued = lenient([{ checkId: 'check-5', minimum: 'independent-pass' }]);
  const blocked = assess(selfIssued); assert.equal(blocked.decision, 'blocked'); assert.deepEqual(blocked.blockerCodes, [CODE]);
  assert.equal(assess(lenient([{ checkId: 'check-5', minimum: 'pass' }])).decision, 'qualified');
  const independent = lenient([{ checkId: 'check-5', minimum: 'independent-pass' }], x => { x.policy.trustedKeys[0].role = 'independent'; });
  assert.equal(assess(independent).decision, 'qualified');
});

test('a declaration cannot satisfy a mandatory minimum', () => {
  const x = lenient([{ checkId: 'check-5', minimum: 'pass' }], y => {
    y.policy.allowedSources.push('declaration');
    y.evidence[5] = signEvidence(payload(y.manifest, y.profile, 5, { source: 'declaration' }), keys.privateKey);
  });
  const r = assess(x); assert.equal(r.decision, 'blocked'); assert.deepEqual(r.blockerCodes, [CODE]);
  assert.ok(r.rejectedEvidence.some(e => /declaration/i.test(e.reason)));
});

test('an unmet minimum cannot soften a revoked or expired subject but does cap other decisions', () => {
  const revoked = lenient([{ checkId: 'check-5', minimum: 'pass' }], x => { x.policy.revokedSubjectDigests = [digest(x.manifest)]; });
  const r = assess(revoked); assert.equal(r.decision, 'revoked'); assert.deepEqual(r.blockerCodes, ['SUBJECT_REVOKED']);
  const insufficient = lenient([{ checkId: 'check-5', minimum: 'pass' }], x => { x.evidence = []; });
  const i = assess(insufficient); assert.equal(i.decision, 'blocked'); assert.ok(i.blockerCodes.includes('NO_SCORED_OBSERVATIONS')); assert.ok(i.blockerCodes.includes(CODE));
  const critical = lenient([{ checkId: 'check-5', minimum: 'pass' }], x => { x.evidence[0] = signEvidence(payload(x.manifest, x.profile, 0, { outcome: 'fail' }), keys.privateKey); fail5(x); });
  assert.deepEqual(assess(critical).blockerCodes, ['CRITICAL_CHECK_FAILED', CODE]);
});

test('each unmet mandatory check is named once and met checks are not listed', () => {
  const x = lenient([{ checkId: 'check-3', minimum: 'pass' }, { checkId: 'check-4', minimum: 'pass' }, { checkId: 'check-5', minimum: 'pass' }], y => {
    y.policy.minCoverage = 0.5; y.policy.minScore = 0;
    for (const i of [3, 5]) y.evidence[i] = signEvidence(payload(y.manifest, y.profile, i, { outcome: 'fail' }), keys.privateKey);
  });
  const r = assess(x); assert.equal(r.decision, 'blocked'); assert.deepEqual(r.blockerCodes, [CODE, CODE]);
  assert.ok(r.blockers[0].includes('check-3')); assert.ok(r.blockers[1].includes('check-5')); assert.ok(!r.blockers.some(b => b.includes('check-4')));
});

test('mandatory minimums are validated strictly', () => {
  const bad = value => { const p = inputs().policy; p.mandatoryMinimums = value; return () => validatePolicy(p); };
  assert.doesNotThrow(bad([{ checkId: 'check-5', minimum: 'pass' }]));
  assert.throws(bad([]), /mandatory/i);
  assert.throws(bad('check-5'), /mandatory/i);
  assert.throws(bad(null), /mandatory/i);
  assert.throws(bad([{ checkId: 'check-5', minimum: 'pass' }, { checkId: 'check-5', minimum: 'independent-pass' }]), /duplicate/i);
  assert.throws(bad([{ checkId: 'check-5' }]));
  assert.throws(bad([{ checkId: 'check-5', minimum: 'mostly' }]), /minimum/i);
  assert.throws(bad([{ checkId: 'check-5', minimum: 'pass', extra: true }]));
  assert.throws(bad([{ checkId: '', minimum: 'pass' }]));
  assert.throws(bad([{ checkId: 'bad id', minimum: 'pass' }]));
  assert.throws(bad(Array.from({ length: 257 }, (_, i) => ({ checkId: 'c' + i, minimum: 'pass' }))));
});

test('minimums naming a check outside the frozen profile are refused at assessment', () => {
  const x = lenient([{ checkId: 'check-99', minimum: 'pass' }]);
  assert.throws(() => assess(x), /mandatory minimum.*profile/i);
  assert.equal(assess(lenient([{ checkId: 'check-0', minimum: 'pass' }])).decision, 'qualified');
});

test('currency treats an added minimum as a policy change and accepts policies with the field', () => {
  const i = inputs(), report = assess(i);
  const withMinimum = clone(i.policy); withMinimum.mandatoryMinimums = [{ checkId: 'check-5', minimum: 'pass' }];
  const result = checkCurrency(report, { manifest: i.manifest, policy: withMinimum, now: NOW });
  assert.deepEqual(result.triggers.map(t => t.id), ['policy-changed']); assert.equal(result.action, 'reassess');
  const gated = assess({ ...i, policy: withMinimum });
  assert.equal(checkCurrency(gated, { manifest: i.manifest, policy: withMinimum, now: NOW }).current, true);
});

test('a dossier built from a capped assessment validates', () => {
  const x = lenient([{ checkId: 'check-5', minimum: 'pass' }], fail5);
  const d = createDossier({ inputs: x });
  assert.equal(d.assessment.decision, 'blocked'); assert.deepEqual(d.assessment.blockerCodes, [CODE]);
  assert.equal(validateDossier(d).assessment.decision, 'blocked');
});

test('policy schema and types describe the optional minimums', () => {
  const schema = JSON.parse(readFileSync(new URL('../schemas/policy.schema.json', import.meta.url), 'utf8'));
  const field = schema.properties.mandatoryMinimums;
  assert.ok(field); assert.equal(field.minItems, 1); assert.deepEqual(field.items.properties.minimum.enum, ['pass', 'independent-pass']);
  assert.equal(schema.required.includes('mandatoryMinimums'), false);
  assert.match(readFileSync(new URL('../src/index.d.ts', import.meta.url), 'utf8'), /mandatoryMinimums\?:/);
});
