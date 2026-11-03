import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { hashBytes, keyId } from '../src/index.mjs';
import { carefulAgent, captureToCandidates, defaultProbes, probeSetDigest, runAndSign, verifyCapture } from '../src/capture-cell/index.mjs';

const issuer = generateKeyPairSync('ed25519');
const issuerId = keyId(issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString());
const bind = { subjectDigest: hashBytes('synthetic subject'), scopeDigest: hashBytes('synthetic scope'),
  profileDigest: hashBytes('synthetic profile'), evaluatorKeyId: hashBytes('synthetic evaluator') };
const envelope = runAndSign({ agent: carefulAgent, ...bind }, issuer.privateKey).envelope;
const expected = { runId: 'run-1', ...bind };
const verify = (options = {}) => verifyCapture(envelope, { trustedIssuerKeyIds: [issuerId], expected, ...options });
const candidates = v => captureToCandidates(v, { checkMap: { toolSurface: 'surface-check' }, scopeId: 'scope:synthetic',
  evaluatorDigest: hashBytes('synthetic evaluator version'), evaluatorKeyId: bind.evaluatorKeyId, expiresAt: '2026-11-04T00:00:00.000Z' });
const codes = v => v.problems.map(p => p.code);

test('plain capture trust and complete or partial expected bindings preserve their existing behavior', () => {
  const full = verify({ expected: { ...expected, probeSetDigest: probeSetDigest(defaultProbes()) } });
  assert.equal(full.valid, true, JSON.stringify(full.problems));
  assert.equal(full.bound, true);
  assert.equal(full.probeSetPinned, true);
  assert.equal(candidates(full)[0].outcome, 'pass');
  assert.equal(candidates(full)[0].source, 'fixture');
  for (const partial of [{}, { runId: 'run-1' }]) {
    const v = verify({ expected: partial });
    assert.equal(v.valid, true);
    assert.equal(v.bound, false);
    assert.throws(() => candidates(v), /bound/);
  }
});

test('caller-controlled trust array methods cannot admit an issuer absent from the captured members', () => {
  let methodCalls = 0;
  const wrong = hashBytes('different synthetic issuer');
  const extended = [wrong];
  extended.includes = () => { methodCalls++; return true; };
  const proxied = new Proxy([wrong], { get(target, key) {
    if (key === 'includes') return () => { methodCalls++; return true; };
    return Reflect.get(target, key);
  } });
  for (const trustedIssuerKeyIds of [extended, proxied]) {
    const v = verify({ trustedIssuerKeyIds });
    assert.equal(v.valid, false);
    assert.ok(codes(v).includes('untrusted-issuer'));
    assert.equal(v.payload, null);
    assert.throws(() => candidates(v), /verified capture/);
  }
  assert.equal(methodCalls, 0);
});

test('changing expected binding GET views cannot turn a wrong captured scope into a bound candidate', () => {
  const target = { ...expected, scopeDigest: hashBytes('wrong expected synthetic scope') };
  let reads = 0;
  const changing = new Proxy(target, { get(object, key) {
    if (key === 'scopeDigest') {
      reads++;
      return reads === 1 ? object[key] : reads === 2 ? undefined : bind.scopeDigest;
    }
    return Reflect.get(object, key);
  } });
  const v = verify({ expected: changing });
  assert.equal(v.valid, false);
  assert.ok(codes(v).includes('binding-mismatch'));
  assert.equal(v.payload, null);
  assert.equal(reads, 0);
  assert.throws(() => candidates(v), /verified capture/);
});

test('expected data descriptors are consumed without executing binding GET views or accessors', () => {
  let reads = 0;
  const data = new Proxy({ ...expected }, { get(target, key) {
    reads++;
    return Reflect.get(target, key);
  } });
  const good = verify({ expected: data });
  assert.equal(good.valid, true);
  assert.equal(good.bound, true);
  assert.equal(reads, 0);
  let getters = 0;
  const accessor = { ...expected };
  Object.defineProperty(accessor, 'scopeDigest', { enumerable: true, get() { getters++; return bind.scopeDigest; } });
  const bad = verify({ expected: accessor });
  assert.equal(bad.valid, false);
  assert.ok(codes(bad).includes('schema'));
  assert.equal(getters, 0);
});

test('unknown and explicit undefined expected-binding diagnostics remain distinct from omitted bindings', () => {
  for (const key of ['runId', 'evaluatorKeyId', 'probeSetDigest']) {
    const v = verify({ expected: { ...expected, [key]: undefined } });
    assert.equal(v.valid, false);
    assert.ok(codes(v).includes('binding-undefined'));
  }
  const unknown = verify({ expected: { ...expected, colour: 'synthetic-blue' } });
  assert.equal(unknown.valid, false);
  assert.ok(codes(unknown).includes('binding-unknown'));
  const mismatch = verify({ expected: { ...expected, probeSetDigest: hashBytes('wrong synthetic probes') } });
  assert.equal(mismatch.valid, false);
  assert.ok(codes(mismatch).includes('probe-set-mismatch'));
});
