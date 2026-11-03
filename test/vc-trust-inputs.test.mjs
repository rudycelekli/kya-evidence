import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { assess, keyId } from '../src/index.mjs';
import { inputs } from './helpers.mjs';
import { exportAssessmentCredential, verifyAssessmentCredential, didKeyFromPublicKey,
  buildStatusListCredential, checkStatus } from '../src/vc-bridge/index.mjs';

const source = inputs(), report = assess(source);
const issuer = generateKeyPairSync('ed25519'), other = generateKeyPairSync('ed25519');
const issuerPem = issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const otherPem = other.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const issuerId = keyId(issuerPem), otherId = keyId(otherPem);
const goodDid = didKeyFromPublicKey(issuer.publicKey), badDid = didKeyFromPublicKey(other.publicKey);
const token = exportAssessmentCredential(report, { issuerKey: issuer.privateKey }).jwt;
const now = '2026-10-13T12:30:00.000Z';
const anchor = () => ({ id: issuerId, publicKey: issuerPem, role: 'independent' });
const policy = () => ({ trustedKeys: [anchor()], revokedKeyIds: [] });
const verify = options => verifyAssessmentCredential(token, { now, ...options });
const hasCode = (result, code) => result.errors.some(e => e.code === code);

test('VC trust preserves supported key forms, unchecked defaults and partial policy projections', () => {
  const raw = Uint8Array.from(Buffer.from(issuer.publicKey.export({ format: 'jwk' }).x, 'base64url'));
  for (const key of [goodDid, issuer.publicKey, issuerPem, raw]) {
    const result = verify({ expectedIssuerKeys: [key] });
    assert.equal(result.valid, true);
    assert.equal(result.issuerTrust, 'expected');
    assert.equal(result.authenticated, false);
  }
  for (const options of [{}, { expectedIssuerKeys: [] }]) {
    const result = verify(options);
    assert.equal(result.valid, true);
    assert.equal(result.issuerTrust, 'unchecked');
  }
  for (const projection of [policy(), { ...source.policy, ...policy() }]) {
    const result = verify({ policy: projection });
    assert.equal(result.valid, true);
    assert.equal(result.issuerTrust, 'anchored');
    assert.equal(result.issuerRole, 'independent');
    assert.equal(result.authenticated, false);
  }
  assert.ok(hasCode(verify({ policy: { ...policy(), revokedKeyIds: [issuerId] } }), 'ISSUER_NOT_TRUSTED'));
});

test('VC expected issuer keys refuse malformed or non-dense collections without executing array overrides', () => {
  const sparse = new Array(1), accessor = [];
  let reads = 0;
  Object.defineProperty(accessor, '0', { enumerable: true, configurable: true, get() { reads++; return goodDid; } });
  const overridden = [badDid]; overridden.map = () => { reads++; return [goodDid]; };
  for (const value of [new Set([badDid]), {}, 42, false, '', null, sparse, accessor, overridden, Array(257).fill(goodDid)]) {
    let result;
    assert.doesNotThrow(() => { result = verify({ expectedIssuerKeys: value }); });
    assert.equal(result.valid, false);
    assert.ok(hasCode(result, 'ISSUER_KEYS_INVALID'), JSON.stringify(result.errors));
  }
  assert.equal(reads, 0);
});

test('VC expected issuer matching uses captured array membership instead of a live GET view', () => {
  let reads = 0;
  const keys = new Proxy([badDid], { get(target, key, receiver) {
    if (key === '0') { reads++; return goodDid; }
    return Reflect.get(target, key, receiver);
  } });
  const result = verify({ expectedIssuerKeys: keys });
  assert.equal(result.valid, false);
  assert.ok(hasCode(result, 'ISSUER_NOT_EXPECTED'));
  assert.equal(reads, 0);
});

test('VC policy trust projection validates fingerprints, roles, uniqueness, bounds and required fields', () => {
  const base = policy();
  const malformed = [
    { ...base, trustedKeys: [{ ...anchor(), publicKey: otherPem }] },
    { ...base, trustedKeys: [{ ...anchor(), role: 'administrator' }] },
    { ...base, trustedKeys: [anchor(), anchor()] },
    { ...base, trustedKeys: Array(257).fill(anchor()) },
    { ...base, trustedKeys: [{ ...anchor(), extra: true }] },
    { ...base, revokedKeyIds: [otherId, otherId] },
    { ...base, revokedKeyIds: ['not-a-digest'] },
    { ...base, revokedKeyIds: Array(4097).fill(otherId) },
    { trustedKeys: [anchor()] }, { revokedKeyIds: [] }, null, false, 0, ''
  ];
  for (const value of malformed) {
    let result;
    assert.doesNotThrow(() => { result = verify({ policy: value }); });
    assert.equal(result.valid, false);
    assert.ok(hasCode(result, 'POLICY_INVALID'), JSON.stringify(result.errors));
    assert.notEqual(result.issuerTrust, 'anchored');
  }
});

test('VC policy anchoring uses captured own data and retains descriptor-backed revocations', () => {
  let reads = 0;
  const benign = new Proxy(policy(), { get() { reads++; throw Error('Live policy read'); } });
  let result;
  assert.doesNotThrow(() => { result = verify({ policy: benign }); });
  assert.equal(result.valid, true);
  assert.equal(result.issuerTrust, 'anchored');
  assert.equal(reads, 0);
  const revoked = new Proxy([issuerId], { get(target, key, receiver) {
    if (key === '0') { reads++; return otherId; }
    return Reflect.get(target, key, receiver);
  } });
  result = verify({ policy: { ...policy(), revokedKeyIds: revoked } });
  assert.equal(result.valid, false);
  assert.ok(hasCode(result, 'ISSUER_NOT_TRUSTED'));
  assert.equal(reads, 0);
});

test('status-list verification shares strict expected issuer collection and membership checks', () => {
  const url = 'https://example.test/status/frozen';
  const list = buildStatusListCredential({ issuerKey: issuer.privateKey, id: url, purpose: 'revocation', indices: [],
    validFrom: '2026-10-13T12:00:00.000Z', validUntil: '2026-10-13T13:00:00.000Z' });
  const entry = { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: url };
  assert.equal(checkStatus(list.jwt, entry, { now, expectedIssuerKeys: [goodDid] }).valid, true);
  assert.throws(() => checkStatus(list.jwt, entry, { now, expectedIssuerKeys: new Set([badDid]) }), /ISSUER_KEYS_INVALID/);
  const keys = new Proxy([badDid], { get: (target, key, receiver) => key === '0' ? goodDid : Reflect.get(target, key, receiver) });
  assert.throws(() => checkStatus(list.jwt, entry, { now, expectedIssuerKeys: keys }),
    e => e.code === 'STATUS_VERIFICATION_ERROR' && /not an expected issuer/.test(e.message));
});
