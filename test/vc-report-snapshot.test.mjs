import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { assess, canonical } from '../src/index.mjs';
import { inputs } from './helpers.mjs';
import { exportAssessmentCredential, verifyAssessmentCredential } from '../src/vc-bridge/index.mjs';

const issuer = generateKeyPairSync('ed25519');
const report = assess(inputs());
const exported = exportAssessmentCredential(report, { issuerKey: issuer.privateKey });
const now = '2026-10-13T12:30:00.000Z';
const [header, encoded] = exported.jwt.split('.');
const forged = JSON.parse(Buffer.from(encoded, 'base64url'));
forged.credentialSubject.score.earned = 0;
const signingInput = header + '.' + Buffer.from(JSON.stringify(forged)).toString('base64url');
const changedToken = signingInput + '.' + sign(null, Buffer.from(signingInput), issuer.privateKey).toString('base64url');

test('VC report binding retains ordinary JSON compatibility, tamper refusal and unauthenticated limits', () => {
  const original = canonical(report);
  const valid = verifyAssessmentCredential(exported.jwt, { now, report });
  assert.equal(valid.valid, true);
  assert.equal(valid.reportChecked, true);
  assert.equal(valid.authenticated, false);
  const mismatch = verifyAssessmentCredential(changedToken, { now, report });
  assert.equal(mismatch.valid, false);
  assert.ok(mismatch.errors.some(e => e.code === 'REPORT_MISMATCH'));
  const stale = JSON.parse(original); stale.score.earned = 0;
  const invalid = verifyAssessmentCredential(changedToken, { now, report: stale });
  assert.equal(invalid.valid, false);
  assert.ok(invalid.errors.some(e => e.code === 'REPORT_INVALID'));
  assert.equal(canonical(report), original);
});

test('VC comparison cannot replace the checksum-checked score with a live GET or second-capture view', () => {
  for (const changeDescriptors of [false, true]) {
    let captures = 0;
    const live = new Proxy(report, {
      ownKeys(target) { captures++; return Reflect.ownKeys(target); },
      get(target, key, receiver) { return key === 'score' ? { ...report.score, earned: 0 } : Reflect.get(target, key, receiver); },
      getOwnPropertyDescriptor(target, key) {
        const d = Reflect.getOwnPropertyDescriptor(target, key);
        return changeDescriptors && key === 'score' && captures >= 2 ? { ...d, value: { ...report.score, earned: 0 } } : d;
      }
    });
    const result = verifyAssessmentCredential(changedToken, { now, report: live });
    assert.equal(result.valid, false, `changing descriptors: ${changeDescriptors}`);
    assert.ok(result.errors.some(e => e.code === 'REPORT_MISMATCH'));
    assert.equal(result.authenticated, false);
  }
});

test('VC verification captures an honest native report once and never reads its GET view', () => {
  let reads = 0, captures = 0;
  const live = new Proxy(report, {
    ownKeys(target) { captures++; return Reflect.ownKeys(target); },
    get() { reads++; throw Error('Live report read'); }
  });
  const result = verifyAssessmentCredential(exported.jwt, { now, report: live });
  assert.equal(result.valid, true);
  assert.equal(result.reportChecked, true);
  assert.equal(reads, 0);
  assert.equal(captures, 1);
});
