import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { assess, digest } from '../src/index.mjs';

// The field rules and the dimension layout were enforced by the reference validators but were not written in the
// specification, so a second implementation had to guess them. These tests pin the written text to the
// reference behaviour, so the text cannot drift from the code in either direction.
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const SPEC = readFileSync(join(ROOT, 'docs/SPECIFICATION.md'), 'utf8');
const SCORING = readFileSync(join(ROOT, 'docs/SCORING.md'), 'utf8');
const VECTORS = JSON.parse(readFileSync(join(ROOT, 'evidence/assessment-vectors.json'), 'utf8'));
const BASE = VECTORS.vectors.find(v => v.id === 'assess.qualified-all-pass-runtime').inputs;
const clone = v => structuredClone(v);
const accepts = inputs => { try { assess(clone(inputs)); return true; } catch { return false; } };
const withPolicy = patch => ({ ...clone(BASE), policy: { ...clone(BASE.policy), ...patch } });
const withManifest = f => { const i = clone(BASE); f(i.manifest); return i; };
const withProfile = f => { const i = clone(BASE); f(i.profile); i.policy.profileDigest = digest(i.profile); return i; };

test('the specification states the field rules and the scoring document states the dimension layout', () => {
  for (const phrase of ['Field rules', 'agent.id', 'principal.accountableParty.ref', 'at most 256 unique', 'approvalRequired', 'minCoverage', 'maxEvidenceAgeSeconds', 'SHA-256 of the DER SPKI', 'must be unique', 'expiresAt', 'strictly after']) {
    assert.ok(SPEC.includes(phrase), 'SPECIFICATION.md lacks ' + phrase);
  }
  assert.ok(SCORING.includes('always lists the six fixed dimensions'));
  assert.ok(SCORING.includes('the number of `CRITICAL_CHECK_FAILED` codes equals the number of checks'));
  assert.ok(SCORING.includes('identity, authority, security, reliability, accountability, operations'));
  assert.ok(SCORING.includes('earned 0, possible 0, upperBound 0, coverage 0 and weight 0'));
});

test('the specification states which receipts the run rules are evaluated over', () => {
  for (const phrase of ['as recent as the latest observation time', 'bound receipts', 'counts toward recency', 'in the whole bundle, in any run', 'keeps the first reason', 'every bound receipt, including those of runs that are not selected']) {
    assert.ok(SPEC.includes(phrase), 'SPECIFICATION.md lacks ' + phrase);
  }
  assert.ok(/RUN_INVALIDATED[^\n]*quarantined/.test(SCORING), 'SCORING.md RUN_INVALIDATED row does not mention quarantined duplicates');
});

test('stated numeric ranges are enforced at both edges by the reference', () => {
  assert.equal(accepts(BASE), true);
  const cases = [['minCoverage', 0, 1, -0.0001, 1.0001], ['minIndependentCoverage', 0, 1, -0.0001, 1.0001], ['minScore', 0, 1000, -1, 1001], ['maxEvidenceAgeSeconds', 1, 31536000, 0, 31536001], ['maxAssessmentAgeSeconds', 1, 31536000, 0, 31536001]];
  for (const [field, lo, hi, below, above] of cases) {
    assert.equal(accepts(withPolicy({ [field]: lo })), true, field + ' low edge');
    assert.equal(accepts(withPolicy({ [field]: hi })), true, field + ' high edge');
    assert.equal(accepts(withPolicy({ [field]: below })), false, field + ' below');
    assert.equal(accepts(withPolicy({ [field]: above })), false, field + ' above');
  }
  assert.equal(accepts(withPolicy({ minScore: 700.5 })), false);
});

test('stated profile rules are enforced by the reference', () => {
  assert.equal(accepts(withProfile(p => { p.checks[0].weight = 100000; })), true);
  assert.equal(accepts(withProfile(p => { p.checks[0].weight = 100001; })), false);
  assert.equal(accepts(withProfile(p => { p.checks[0].weight = 0; })), false);
  assert.equal(accepts(withProfile(p => { p.checks[0].dimension = 'safety'; })), false);
  assert.equal(accepts(withProfile(p => { p.checks = []; })), false);
  assert.equal(accepts(withProfile(p => { p.checks.push({ ...p.checks[0] }); })), false);
  assert.equal(accepts(withProfile(p => { p.version = 'v'.repeat(64); })), true);
  assert.equal(accepts(withProfile(p => { p.version = 'v'.repeat(65); })), false);
});

test('stated manifest rules are enforced by the reference', () => {
  const ok = f => accepts(withManifest(f));
  assert.equal(ok(m => { m.agent.id = 'a'.repeat(128); }), true);
  assert.equal(ok(m => { m.agent.id = 'a'.repeat(129); }), false);
  assert.equal(ok(m => { m.agent.id = '-a'; }), false);
  assert.equal(ok(m => { m.agent.version = 'v'.repeat(129); }), false);
  assert.equal(ok(m => { m.scope.purpose = 'p'.repeat(512); }), true);
  assert.equal(ok(m => { m.scope.purpose = 'p'.repeat(513); }), false);
  assert.equal(ok(m => { m.scope.approvalRequired = ['publish']; }), false);
  assert.equal(ok(m => { m.system.tools[0].permissions = ['delete']; }), false);
  assert.equal(ok(m => { m.system.tools.push({ ...m.system.tools[0] }); }), false);
  assert.equal(ok(m => { m.scope.permissions = ['read', 'write', 'read']; }), false);
  assert.equal(ok(m => { m.expiresAt = m.issuedAt; }), false);
  assert.equal(ok(m => { m.principal.accountableParty = { kind: 'legal-entity', ref: 'Agent:Vector-Subject' }; }), false);
});

test('stated policy list and trust anchor rules are enforced by the reference', () => {
  assert.equal(accepts(withPolicy({ allowedSources: ['runtime', 'fixture', 'declaration'] })), true);
  assert.equal(accepts(withPolicy({ allowedSources: ['runtime', 'runtime'] })), false);
  assert.equal(accepts(withPolicy({ allowedSources: ['simulated'] })), false);
  const anchors = BASE.policy.trustedKeys;
  assert.equal(accepts(withPolicy({ trustedKeys: [...anchors, anchors[0]] })), false);
  assert.equal(accepts(withPolicy({ trustedKeys: anchors.map((k, i) => i === 0 ? { ...k, id: '0'.repeat(64) } : k) })), false);
  assert.equal(accepts(withPolicy({ trustedKeys: anchors.map((k, i) => i === 0 ? { ...k, role: 'admin' } : k) })), false);
});

test('an assessment always lists the six fixed dimensions in order and a dimension without checks is all zero', () => {
  const profile = { ...clone(BASE.profile), checks: [{ id: 'a.one', dimension: 'security', title: 'One', weight: 3, critical: false }] };
  const policy = { ...clone(BASE.policy), profileDigest: digest(profile), minCoverage: 0, minScore: 0 };
  const report = assess({ ...clone(BASE), profile, policy, evidence: [] });
  assert.deepEqual(report.dimensions.map(d => d.id), ['identity', 'authority', 'security', 'reliability', 'accountability', 'operations']);
  assert.deepEqual(report.dimensions[0], { id: 'identity', earned: 0, possible: 0, upperBound: 0, coverage: 0, weight: 0 });
  assert.deepEqual(report.dimensions[2], { id: 'security', earned: 0, possible: 1000, upperBound: 1000, coverage: 0, weight: 3 });
});
