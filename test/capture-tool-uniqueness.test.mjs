import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonical, digest, hashBytes } from '../src/shared/canonical.mjs';
import { keyId } from '../src/index.mjs';
import { CAPTURE_DOMAIN, DECLARED_TOOLS, carefulAgent, captureToCandidates, deriveFindings,
  runAndSign, signCapture, validateCapture, verifyCapture } from '../src/capture-cell/index.mjs';

const issuer = generateKeyPairSync('ed25519');
const publicKey = issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const issuerId = keyId(publicKey);
const bind = { subjectDigest: hashBytes('synthetic subject'), scopeDigest: hashBytes('synthetic scope'),
  profileDigest: hashBytes('synthetic profile'), evaluatorKeyId: hashBytes('synthetic evaluator') };
const options = { agent: carefulAgent, ...bind, rng: () => Buffer.from('0123456789abcdef') };
const trust = { trustedIssuerKeyIds: [issuerId], expected: { runId: 'run-1', ...bind } };
const candidates = verification => captureToCandidates(verification, {
  checkMap: { toolSurface: 'surface-check' }, scopeId: 'scope:synthetic',
  evaluatorDigest: hashBytes('synthetic evaluator version'), evaluatorKeyId: bind.evaluatorKeyId,
  expiresAt: '2026-11-04T00:00:00.000Z'
});
// Sign the exact synthetic bytes directly so a bad public payload reaches verification even
// after signCapture learns to refuse it. No invalid signature can stand in for shape refusal.
const rawSign = payload => ({ payload, proof: { algorithm: 'Ed25519', keyId: issuerId, publicKey,
  signature: sign(null, Buffer.from(CAPTURE_DOMAIN + canonical(payload)), issuer.privateKey).toString('base64url') } });

test('unique capture tool surfaces preserve verified fixture candidate behavior and deterministic bytes', () => {
  const run = runAndSign(options, issuer.privateKey), again = runAndSign(options, issuer.privateKey);
  assert.equal(canonical(run.envelope), canonical(again.envelope));
  const v = verifyCapture(run.envelope, trust);
  assert.equal(v.valid, true, JSON.stringify(v.problems));
  assert.equal(v.bound, true);
  assert.deepEqual(v.findings, []);
  assert.equal(v.payload.cell.kind, 'simulated');
  assert.equal(v.payload.cell.isolation, 'none');
  const result = candidates(v);
  assert.equal(result[0].outcome, 'pass');
  assert.equal(result[0].source, 'fixture');
  assert.equal(result[0].artifactDigest, digest(run.payload));
});

test('signed exposed tool duplicates are refused for identical and conflicting definitions in either position', () => {
  const base = runAndSign(options, issuer.privateKey).payload;
  for (const conflict of [false, true]) for (const prepend of [false, true]) {
    const payload = structuredClone(base), original = payload.toolSurface.exposed.find(t => t.name === 'read_file');
    const duplicate = conflict ? { ...original, permissionsDigest: hashBytes('unexpected permission'), effect: 'outbound' } : { ...original };
    payload.toolSurface.exposed[prepend ? 'unshift' : 'push'](duplicate);
    const v = verifyCapture(rawSign(payload), trust);
    assert.equal(v.valid, false, JSON.stringify({ conflict, prepend }));
    assert.equal(v.payload, null);
    assert.ok(v.problems.some(p => p.code === 'schema' && /duplicate tool name/i.test(p.message)));
    assert.throws(() => validateCapture(payload), /duplicate tool name/i);
    assert.throws(() => signCapture(payload, issuer.privateKey), /duplicate tool name/i);
    assert.throws(() => deriveFindings(payload), /duplicate tool name/i);
    assert.throws(() => candidates(v), /verified capture/i);
  }
});

test('signed declared tool duplicates are refused for identical and conflicting definitions in either position', () => {
  const base = runAndSign(options, issuer.privateKey).payload;
  for (const conflict of [false, true]) for (const prepend of [false, true]) {
    const payload = structuredClone(base), original = payload.toolSurface.declared.find(t => t.name === 'read_file');
    const duplicate = conflict ? { ...original, permissionsDigest: hashBytes('unexpected declaration') } : { ...original };
    payload.toolSurface.declared[prepend ? 'unshift' : 'push'](duplicate);
    const v = verifyCapture(rawSign(payload), trust);
    assert.equal(v.valid, false, JSON.stringify({ conflict, prepend }));
    assert.equal(v.payload, null);
    assert.ok(v.problems.some(p => p.code === 'schema' && /duplicate tool name/i.test(p.message)));
    assert.throws(() => validateCapture(payload), /duplicate tool name/i);
    assert.throws(() => signCapture(payload, issuer.privateKey), /duplicate tool name/i);
    assert.throws(() => deriveFindings(payload), /duplicate tool name/i);
    assert.throws(() => candidates(v), /verified capture/i);
  }
});

test('duplicate cell declarations are refused before any simulated agent invocation', () => {
  for (const conflict of [false, true]) {
    let calls = 0;
    const original = DECLARED_TOOLS[0];
    const duplicate = { ...original, permissions: conflict ? ['unexpected'] : [...original.permissions] };
    assert.throws(() => runAndSign({ ...options,
      declaredTools: [duplicate, ...DECLARED_TOOLS],
      agent: (...args) => { calls++; return carefulAgent(...args); }
    }, issuer.privateKey), /duplicate declared tool id/i);
    assert.equal(calls, 0);
  }
});
