import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { hashBytes, keyId } from '../src/index.mjs';
import { signDisclosure, checkAssessorStanding } from '../src/assessor/index.mjs';

// Published synthetic fixture seed; never an operational key.
const key = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + '31'.repeat(32), 'hex'), type: 'pkcs8', format: 'der' });
const id = keyId(createPublicKey(key).export({ format: 'pem', type: 'spki' }).toString());
const operator = hashBytes('synthetic standing operator'), other = hashBytes('other synthetic assessor');
const now = '2026-10-20T00:00:00.000Z';
const disclosure = signDisclosure({ schema: 'kya.assessor-disclosure/v1', id: 'disclosure:synthetic', kind: 'disclosure',
  assessorKeyId: id, operatorDigest: operator, relationships: ['none'], priorEngagementEndedAt: null,
  refId: null, refDigest: null, issuedAt: '2026-10-01T00:00:00.000Z', expiresAt: '2027-03-01T00:00:00.000Z',
  detailsDigest: hashBytes('synthetic details') }, key);
const policy = () => ({ operatorDigest: operator, assessorKeyIds: [id] });
const check = p => checkAssessorStanding([disclosure], p, now).standings[0];

test('plain standing policies preserve defaults and revoked-key refusal', () => {
  const good = check(policy());
  assert.equal(good.keyId, id); assert.equal(good.standing, 'good'); assert.deepEqual(good.reasons, []);
  const revoked = check({ ...policy(), revokedKeyIds: [id] });
  assert.equal(revoked.standing, 'not-standing'); assert.ok(revoked.reasons.includes('key-revoked'));
});

test('standing revocations cannot be hidden by top-level or array GET views', () => {
  const target = { ...policy(), revokedKeyIds: [id] };
  const live = new Proxy(target, { get(t, k, receiver) { return k === 'revokedKeyIds' ? [] : Reflect.get(t, k, receiver); } });
  const members = new Proxy([id], { get(t, k, receiver) { return k === '0' ? other : Reflect.get(t, k, receiver); } });
  for (const input of [live, { ...policy(), revokedKeyIds: members }]) {
    const result = check(input);
    assert.equal(result.standing, 'not-standing'); assert.ok(result.reasons.includes('key-revoked'));
  }
});

test('honest native standing policy is captured once without GET reads', () => {
  let reads = 0, captures = 0;
  const live = new Proxy(policy(), { ownKeys(t) { captures++; return Reflect.ownKeys(t); }, get() { reads++; throw Error('Live policy read'); } });
  assert.equal(check(live).standing, 'good');
  assert.equal(reads, 0); assert.equal(captures, 1);
});

test('disclosure capture cannot replace the already selected assessor population', () => {
  const p = policy();
  const live = new Proxy(disclosure, { ownKeys(t) { p.assessorKeyIds[0] = other; return Reflect.ownKeys(t); } });
  const result = checkAssessorStanding([live], p, now);
  assert.deepEqual(result.standings.map(s => s.keyId), [id]);
  assert.equal(result.standings[0].standing, 'good');
});
