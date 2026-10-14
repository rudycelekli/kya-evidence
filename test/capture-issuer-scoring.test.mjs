import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { assess, signEvidence, keyId } from '../src/index.mjs';
import { inputs, payload, NOW } from './helpers.mjs';

test('a capture-issuer key can never issue scoring evidence even when it signs a valid receipt', () => {
  const x = inputs(), cap = generateKeyPairSync('ed25519'), pem = cap.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  x.policy.trustedKeys = [{ id: keyId(pem), publicKey: pem, role: 'capture-issuer' }];
  x.evidence = x.profile.checks.map((_, i) => signEvidence(payload(x.manifest, x.profile, i), cap.privateKey));
  const r = assess({ ...x, now: NOW });
  assert.notEqual(r.decision, 'qualified');
  assert.equal(r.coverage, 0);
  assert.equal(r.score.earned, 0);
  assert.ok(r.rejectedEvidence.length > 0 && r.rejectedEvidence.every(e => /capture-issuer/i.test(e.reason)), JSON.stringify(r.rejectedEvidence.slice(0, 1)));
});

test('a policy with only self and independent anchors is unaffected by the capture-issuer rule', () => {
  const r = assess(inputs());
  assert.equal(r.decision, 'qualified');
  assert.equal(r.rejectedEvidence.length, 0);
});
