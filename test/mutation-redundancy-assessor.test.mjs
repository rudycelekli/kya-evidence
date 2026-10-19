import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { signDisclosure, verifyDisclosure, checkAssessorStanding, DISCLOSURE_DOMAIN } from '../src/assessor/index.mjs';
import { keyId, hashBytes } from '../src/index.mjs';
import { canonical } from '../src/shared/canonical.mjs';

// Second, independent killers for the assessor disclosure and standing gates. The first killers use one assessor,
// one declarer and whole-day boundaries; these use other keys, two assessors and millisecond precision dates.
const pem = k => k.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const P1 = generateKeyPairSync('ed25519'), P2 = generateKeyPairSync('ed25519'), Q1 = generateKeyPairSync('ed25519'), Q2 = generateKeyPairSync('ed25519'), Z = generateKeyPairSync('ed25519');
const id1 = keyId(pem(P1)), id2 = keyId(pem(P2)), q1 = keyId(pem(Q1)), q2 = keyId(pem(Q2)), z = keyId(pem(Z));
const OP = hashBytes('redundancy operator'), NOW = '2026-11-02T10:00:00.000Z';
const base = (patch = {}) => ({ schema: 'kya.assessor-disclosure/v1', id: 'r:disc', kind: 'disclosure', assessorKeyId: id1, operatorDigest: OP, relationships: ['none'], priorEngagementEndedAt: null, refId: null, refDigest: null, issuedAt: '2026-10-05T08:15:30.250Z', expiresAt: '2027-02-01T00:00:00.000Z', detailsDigest: hashBytes('redundancy private'), ...patch });
const disc = (patch, key = P1.privateKey) => signDisclosure(base(patch), key);
const decl = (patch = {}, key = Q1.privateKey) => disc({ id: 'r:decl', kind: 'conflict-declaration', relationships: ['employment'], ...patch }, key);
const policy = (patch = {}) => ({ operatorDigest: OP, assessorKeyIds: [id1], declarerKeyIds: [q1, q2], ...patch });
const run = (recs, pol = policy(), now = NOW) => checkAssessorStanding(recs, pol, now);
const stand = (recs, pol, now) => run(recs, pol, now).standings[0];
const ms = (iso, delta) => new Date(Date.parse(iso) + delta).toISOString();

test('the disclosure domain constant is pinned and the library signature verifies independently over it', () => {
  assert.equal(DISCLOSURE_DOMAIN, 'kya.assessor-disclosure/v1\n');
  const e = disc();
  const message = Buffer.from(DISCLOSURE_DOMAIN + canonical(e.payload));
  const publicKey = P1.publicKey;
  assert.equal(verify(null, message, publicKey, Buffer.from(e.proof.signature, 'base64url')), true);
  assert.equal(verify(null, Buffer.from(canonical(e.payload)), publicKey, Buffer.from(e.proof.signature, 'base64url')), false);
  const other = sign(null, Buffer.from('kya.assessor-disclosure/v1\n' + canonical(e.payload)), P1.privateKey).toString('base64url');
  assert.equal(verifyDisclosure({ payload: e.payload, proof: { ...e.proof, signature: other } }).keyId, id1);
});

test('a disclosure signed by one key but relabelled with another key id never verifies or grants standing', () => {
  const theirs = disc({ assessorKeyId: id1 }, P2.privateKey);
  const relabelled = { payload: theirs.payload, proof: { ...theirs.proof, keyId: id1 } };
  assert.throws(() => verifyDisclosure(relabelled), /fingerprint/i);
  const r = run([relabelled]);
  assert.deepEqual(r.standings[0].reasons, ['no-disclosure']);
  assert.deepEqual(r.ignored.map(x => x.reason), ['invalid-record']);
});

test('a stranger declaration is ignored whatever relationship it names', () => {
  const strangers = [decl({ id: 'r:s1', relationships: ['control'] }, Z.privateKey), decl({ id: 'r:s2', relationships: ['employment', 'financial'] }, P2.privateKey)];
  const r = run([disc(), ...strangers]);
  assert.equal(r.standings[0].standing, 'good');
  assert.deepEqual(r.standings[0].relationships, ['none']);
  assert.deepEqual(r.ignored.map(x => x.reason), ['untrusted-declarer', 'untrusted-declarer']);
  const trusted = run([disc(), decl()]);
  assert.equal(trusted.standings[0].standing, 'not-standing');
  assert.deepEqual(trusted.standings[0].relationships, ['none', 'employment']);
});

test('an assessor listed only as a declarer still cannot declare a conflict against itself', () => {
  const self = decl({ relationships: ['control'] }, P1.privateKey);
  const r = run([disc(), self], policy({ declarerKeyIds: [id1] }));
  assert.equal(r.standings[0].standing, 'good');
  assert.deepEqual(r.standings[0].relationships, ['none']);
  assert.deepEqual(r.ignored.map(x => x.reason), ['untrusted-declarer']);
});

test('a revoked declarer is ignored while a second trusted declarer still counts', () => {
  const bad = decl({ id: 'r:bad', relationships: ['financial'] }, Q1.privateKey), good = decl({ id: 'r:good', relationships: ['tooling-dependency'] }, Q2.privateKey);
  const r = run([disc({ relationships: ['tooling-dependency'] }), bad, good], policy({ revokedKeyIds: [q1] }));
  assert.deepEqual(r.ignored.map(x => x.reason), ['declarer-revoked']);
  assert.equal(r.standings[0].standing, 'good');
  assert.deepEqual(r.standings[0].relationships, ['tooling-dependency']);
  const unrevoked = run([disc({ relationships: ['tooling-dependency'] }), bad, good]);
  assert.ok(unrevoked.standings[0].reasons.includes('blocking-relationship'));
});

test('a declarer cannot withdraw the assessor own disclosure', () => {
  const own = disc();
  const attempt = decl({ id: 'r:wd', kind: 'withdrawal', relationships: [], refId: own.payload.id, refDigest: verifyDisclosure(own).envelopeDigest }, Q1.privateKey);
  const r = run([own, attempt]);
  assert.equal(r.standings[0].standing, 'good');
  assert.deepEqual(r.ignored.map(x => x.reason), ['signer-mismatch']);
  const byOwner = decl({ id: 'r:wd2', kind: 'withdrawal', relationships: [], refId: own.payload.id, refDigest: verifyDisclosure(own).envelopeDigest, issuedAt: '2026-10-20T00:00:00.000Z' }, P1.privateKey);
  assert.deepEqual(run([own, byOwner]).standings[0].reasons, ['no-disclosure']);
});

test('a second declarer cannot withdraw the declaration of the first', () => {
  const first = decl();
  const attempt = decl({ id: 'r:wd3', kind: 'withdrawal', relationships: [], refId: first.payload.id, refDigest: verifyDisclosure(first).envelopeDigest }, Q2.privateKey);
  const r = run([disc(), first, attempt]);
  assert.equal(r.standings[0].standing, 'not-standing');
  assert.deepEqual(r.ignored.map(x => x.reason), ['signer-mismatch']);
});

test('cross signed disclosures give neither of two assessors standing', () => {
  const pol = policy({ assessorKeyIds: [id1, id2] });
  const forOne = disc({ assessorKeyId: id1 }, P2.privateKey), forTwo = disc({ id: 'r:two', assessorKeyId: id2 }, P1.privateKey), stray = disc({ id: 'r:three', assessorKeyId: id1 }, Z.privateKey);
  const r = run([forOne, forTwo, stray], pol);
  assert.deepEqual(r.standings.map(s => s.reasons), [['no-disclosure'], ['no-disclosure']]);
  assert.deepEqual(r.ignored.map(x => x.reason), ['signer-mismatch', 'signer-mismatch', 'signer-mismatch']);
  const own = run([disc(), disc({ id: 'r:own2', assessorKeyId: id2 }, P2.privateKey)], pol);
  assert.deepEqual(own.standings.map(s => s.standing), ['good', 'good']);
});

test('a disclosure stops counting at its exact millisecond expiry', () => {
  const expiresAt = '2026-11-15T12:30:45.123Z';
  const d = disc({ expiresAt });
  assert.equal(stand([d], policy(), ms(expiresAt, -1)).standing, 'good');
  assert.deepEqual(stand([d], policy(), expiresAt).reasons, ['disclosure-expired']);
  assert.deepEqual(stand([d], policy(), ms(expiresAt, 1)).reasons, ['disclosure-expired']);
});

test('a disclosure starts counting at its exact millisecond issue time', () => {
  const issuedAt = '2026-11-01T23:59:59.999Z';
  const d = disc({ issuedAt, expiresAt: '2026-12-31T00:00:00.000Z' });
  assert.deepEqual(stand([d], policy(), ms(issuedAt, -1)).reasons, ['disclosure-not-yet-valid']);
  assert.equal(stand([d], policy(), issuedAt).standing, 'good');
  assert.equal(stand([d], policy(), ms(issuedAt, 1)).standing, 'good');
});

test('a conflict declaration is counted from its issue time and dropped at its millisecond expiry', () => {
  const expiresAt = '2026-11-20T08:00:00.500Z';
  const d = decl({ issuedAt: '2026-11-01T00:00:00.000Z', expiresAt });
  const withDisclosure = at => stand([disc(), d], policy(), at);
  assert.ok(withDisclosure(ms(expiresAt, -1)).reasons.includes('undisclosed-conflict-declared-by-other-party'));
  assert.equal(withDisclosure(expiresAt).standing, 'good');
  assert.equal(withDisclosure(ms(expiresAt, 1)).standing, 'good');
  assert.equal(withDisclosure('2026-10-31T23:59:59.999Z').standing, 'good');
});

test('cooling off lasts until its exact millisecond boundary for a fractional start', () => {
  const ended = '2026-10-13T06:00:00.250Z', boundary = ms(ended, 7 * 86_400_000);
  const pe = disc({ relationships: ['prior-engagement'], priorEngagementEndedAt: ended });
  const pol = policy({ coolingOffDays: 7 });
  assert.deepEqual(stand([pe], pol, ms(boundary, -1)).reasons, ['cooling-off-not-elapsed']);
  assert.equal(stand([pe], pol, boundary).standing, 'good');
  assert.equal(stand([pe], pol, ms(boundary, 1)).standing, 'good');
});
