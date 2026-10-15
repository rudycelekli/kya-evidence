import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { signDisclosure, verifyDisclosure, checkAssessorStanding } from '../src/assessor/index.mjs';
import { keyId, hashBytes } from '../src/index.mjs';

const pem = k => k.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const A = generateKeyPairSync('ed25519'), B = generateKeyPairSync('ed25519'), D = generateKeyPairSync('ed25519'), X = generateKeyPairSync('ed25519');
const idA = keyId(pem(A)), idB = keyId(pem(B)), idD = keyId(pem(D));
const OP = hashBytes('operator'), NOW = '2026-10-20T00:00:00.000Z';
const base = (patch = {}) => ({ schema: 'kya.assessor-disclosure/v1', id: 'disc:1', kind: 'disclosure', assessorKeyId: idA, operatorDigest: OP, relationships: ['none'], priorEngagementEndedAt: null, refId: null, issuedAt: '2026-10-01T00:00:00.000Z', expiresAt: '2027-03-01T00:00:00.000Z', detailsDigest: hashBytes('private'), ...patch });
const disc = (patch, key = A.privateKey) => signDisclosure(base(patch), key);
const policy = (patch = {}) => ({ operatorDigest: OP, assessorKeyIds: [idA], declarerKeyIds: [idD], ...patch });
const stand = (recs, pol = policy(), now = NOW) => checkAssessorStanding(recs, pol, now).standings[0];

test('assessor disclosures are signed, domain separated and strict', () => {
  const e = disc(); assert.equal(verifyDisclosure(e).payload.id, 'disc:1');
  assert.throws(() => verifyDisclosure({ ...e, payload: { ...e.payload, relationships: ['financial'] } }), /signature/i);
  assert.throws(() => verifyDisclosure({ payload: e.payload, proof: { ...e.proof, signature: 'A'.repeat(86) } }));
});

test('assessor disclosure rejects a forged signature from another key', () => {
  const e = disc(), f = disc({ id: 'disc:other' }, B.privateKey);
  assert.throws(() => verifyDisclosure({ payload: e.payload, proof: f.proof }), /signature/i);
});

test('assessor disclosure signed under another domain does not verify', async () => {
  const { sign } = await import('node:crypto'), { canonical } = await import('../src/shared/canonical.mjs');
  const e = disc(), wrong = sign(null, Buffer.from('kya.incident/v1\n' + canonical(e.payload)), A.privateKey).toString('base64url');
  assert.throws(() => verifyDisclosure({ payload: e.payload, proof: { ...e.proof, signature: wrong } }), /signature/i);
});

test('assessor disclosure rejects extra fields, free text, bad codes and oversize input', () => {
  for (const patch of [{ summary: 'free text' }, { relationships: ['friend'] }, { relationships: ['none', 'financial'] }, { relationships: ['financial', 'control'] }, { relationships: [] }, { kind: 'withdrawal' }, { kind: 'conflict-declaration' }, { priorEngagementEndedAt: '2026-01-01T00:00:00.000Z' }, { relationships: ['prior-engagement'] }, { expiresAt: '2030-01-01T00:00:00.000Z' }, { expiresAt: '2026-09-01T00:00:00.000Z' }, { detailsDigest: 'x' }, { id: 'has space' }])
    assert.throws(() => disc(patch), undefined, JSON.stringify(patch));
  assert.throws(() => signDisclosure({ ...base(), relationships: Array(9).fill('financial') }));
  assert.throws(() => signDisclosure({ ...base(), id: 'x'.repeat(5000) }));
  const e = disc(); delete e.payload.id; assert.throws(() => verifyDisclosure(e));
  assert.throws(() => verifyDisclosure({ ...disc(), extra: 1 }));
});

test('a current own disclosure with no relationship gives good standing', () => {
  const s = stand([disc()]); assert.equal(s.standing, 'good'); assert.deepEqual(s.reasons, []);
});

test('missing and expired and future disclosures name their reasons', () => {
  assert.deepEqual(stand([]).reasons, ['no-disclosure']);
  assert.deepEqual(stand([disc()], policy(), '2027-04-01T00:00:00.000Z').reasons, ['disclosure-expired']);
  assert.deepEqual(stand([disc()], policy(), '2026-09-01T00:00:00.000Z').reasons, ['disclosure-not-yet-valid']);
});

test('a revoked assessor key is not in standing even with a valid disclosure', () => {
  assert.deepEqual(stand([disc()], policy({ revokedKeyIds: [idA] })).reasons, ['key-revoked']);
});

test('a blocking relationship removes standing and prior engagement is judged by cooling off', () => {
  assert.deepEqual(stand([disc({ relationships: ['financial'] })]).reasons, ['blocking-relationship']);
  assert.equal(stand([disc({ relationships: ['tooling-dependency'] })]).standing, 'good');
  const pe = ended => disc({ relationships: ['prior-engagement'], priorEngagementEndedAt: ended });
  assert.deepEqual(stand([pe('2026-06-01T00:00:00.000Z')]).reasons, ['cooling-off-not-elapsed']);
  assert.equal(stand([pe('2025-06-01T00:00:00.000Z')]).standing, 'good');
  assert.equal(stand([pe('2026-06-01T00:00:00.000Z')], policy({ coolingOffDays: 30 })).standing, 'good');
  assert.deepEqual(stand([pe('2027-01-01T00:00:00.000Z')]).reasons, ['cooling-off-not-elapsed']);
});

test('an undisclosed conflict declared by a trusted other party removes standing', () => {
  const decl = disc({ id: 'decl:1', kind: 'conflict-declaration', relationships: ['financial'] }, D.privateKey);
  const s = stand([disc(), decl]); assert.ok(s.reasons.includes('undisclosed-conflict-declared-by-other-party')); assert.ok(s.reasons.includes('blocking-relationship'));
  const disclosed = stand([disc({ relationships: ['financial'] }), decl]); assert.ok(!disclosed.reasons.includes('undisclosed-conflict-declared-by-other-party'));
  // a non blocking declared relationship still must be disclosed
  const soft = disc({ id: 'decl:2', kind: 'conflict-declaration', relationships: ['tooling-dependency'] }, D.privateKey);
  assert.deepEqual(stand([disc(), soft]).reasons, ['undisclosed-conflict-declared-by-other-party']);
});

test('declarations from the assessor itself or untrusted keys are ignored with reasons', () => {
  const self = disc({ id: 'decl:3', kind: 'conflict-declaration', relationships: ['financial'] });
  const stranger = disc({ id: 'decl:4', kind: 'conflict-declaration', relationships: ['financial'] }, X.privateKey);
  const r = checkAssessorStanding([disc(), self, stranger], policy(), NOW);
  assert.equal(r.standings[0].standing, 'good'); assert.deepEqual(r.ignored.map(x => x.reason), ['untrusted-declarer', 'untrusted-declarer']);
});

test('replaying another keys disclosure does not give standing', () => {
  const forB = disc({ assessorKeyId: idB }, B.privateKey);
  // B signed a disclosure about B; presented for A it names a different key and cannot help A
  const r = checkAssessorStanding([forB], policy(), NOW); assert.deepEqual(r.standings[0].reasons, ['no-disclosure']); assert.equal(r.ignored[0].reason, 'unrelated-key');
  // B signed a disclosure that claims to be about A
  const lie = disc({ assessorKeyId: idA }, B.privateKey);
  const r2 = checkAssessorStanding([lie], policy(), NOW); assert.deepEqual(r2.standings[0].reasons, ['no-disclosure']); assert.equal(r2.ignored[0].reason, 'signer-mismatch');
});

test('a disclosure for another operator is ignored and corrupt records are listed', () => {
  const r = checkAssessorStanding([disc({ operatorDigest: hashBytes('other') }), { junk: true }], policy(), NOW);
  assert.deepEqual(r.standings[0].reasons, ['no-disclosure']); assert.deepEqual(r.ignored.map(x => x.reason).sort(), ['different-operator', 'invalid-record']);
});

test('a withdrawal by the same key ends a disclosure and cannot be forged by another key', () => {
  const w = disc({ id: 'wd:1', kind: 'withdrawal', relationships: [], refId: 'disc:1' });
  assert.deepEqual(stand([disc(), w]).reasons, ['no-disclosure']);
  const forged = disc({ id: 'wd:2', kind: 'withdrawal', relationships: [], refId: 'disc:1' }, B.privateKey);
  assert.equal(stand([disc(), forged]).standing, 'good');
});

test('the newest disclosure wins and equal time conflicts fail closed', () => {
  const old = disc({ id: 'disc:old', relationships: ['financial'], issuedAt: '2026-09-01T00:00:00.000Z' });
  assert.equal(stand([old, disc()]).standing, 'good');
  const tie = disc({ id: 'disc:2', relationships: ['tooling-dependency'] });
  assert.ok(stand([disc(), tie]).reasons.includes('conflicting-disclosures'));
});

test('duplicate delivery of one envelope is harmless and results do not depend on order', () => {
  const e = disc(), decl = disc({ id: 'decl:5', kind: 'conflict-declaration', relationships: ['control'] }, D.privateKey);
  assert.deepEqual(checkAssessorStanding([e, e], policy(), NOW), checkAssessorStanding([e], policy(), NOW));
  assert.deepEqual(checkAssessorStanding([e, decl], policy(), NOW).standings, checkAssessorStanding([decl, e], policy(), NOW).standings);
});

test('standing policy and input are validated strictly', () => {
  assert.throws(() => checkAssessorStanding([], { ...policy(), mystery: 1 }, NOW), /Unknown/);
  assert.throws(() => checkAssessorStanding([], policy({ coolingOffDays: -1 }), NOW));
  assert.throws(() => checkAssessorStanding([], policy({ blockingRelationships: ['none'] }), NOW));
  assert.throws(() => checkAssessorStanding({}, policy(), NOW));
  assert.throws(() => checkAssessorStanding([], policy(), 'yesterday'));
  assert.throws(() => checkAssessorStanding(Array(1025).fill(disc()), policy(), NOW));
});
