import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { signDisclosure, verifyDisclosure, checkAssessorStanding } from '../src/assessor/index.mjs';
import { keyId, hashBytes } from '../src/index.mjs';
import { canonical } from '../src/shared/canonical.mjs';
import { validateProfileMetadata } from '../src/profiles/validate-metadata.mjs';
import { scanContent } from '../scripts/privacy-scan.mjs';

// Pins for security-relevant boundaries that scripts/mutation-check.mjs mutates. Each test names the gate it protects.

const pem = k => k.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const A = generateKeyPairSync('ed25519'), B = generateKeyPairSync('ed25519'), D = generateKeyPairSync('ed25519');
const idA = keyId(pem(A)), idB = keyId(pem(B)), idD = keyId(pem(D));
const OP = hashBytes('operator'), NOW = '2026-10-20T00:00:00.000Z';
const base = (patch = {}) => ({ schema: 'kya.assessor-disclosure/v1', id: 'disc:1', kind: 'disclosure', assessorKeyId: idA, operatorDigest: OP, relationships: ['none'], priorEngagementEndedAt: null, refDigest: null, refId: null, issuedAt: '2026-10-01T00:00:00.000Z', expiresAt: '2027-03-01T00:00:00.000Z', detailsDigest: hashBytes('private'), ...patch });
const disc = (patch, key = A.privateKey) => signDisclosure(base(patch), key);
const policy = (patch = {}) => ({ operatorDigest: OP, assessorKeyIds: [idA], declarerKeyIds: [idD], ...patch });
const stand = (recs, pol = policy(), now = NOW) => checkAssessorStanding(recs, pol, now).standings[0];
const ms = (iso, delta) => new Date(Date.parse(iso) + delta).toISOString();
const decl = (patch = {}, key = D.privateKey) => disc({ id: 'decl:1', kind: 'conflict-declaration', relationships: ['financial'], ...patch }, key);

test('disclosure signature domain is pinned to its exact prefix and a bare payload signature is refused', () => {
  const e = disc();
  const withDomain = sign(null, Buffer.from('kya.assessor-disclosure/v1\n' + canonical(e.payload)), A.privateKey).toString('base64url');
  assert.equal(verifyDisclosure({ payload: e.payload, proof: { ...e.proof, signature: withDomain } }).payload.id, 'disc:1');
  const bare = sign(null, Buffer.from(canonical(e.payload)), A.privateKey).toString('base64url');
  assert.throws(() => verifyDisclosure({ payload: e.payload, proof: { ...e.proof, signature: bare } }), /signature/i);
});

test('a disclosure proof naming a key that is not the signing key is refused', () => {
  const e = disc();
  assert.throws(() => verifyDisclosure({ payload: e.payload, proof: { ...e.proof, keyId: idB } }), /fingerprint/i);
});

test('standing ignores a conflict declaration signed by the assessor even when that key is listed as a declarer', () => {
  const self = decl({}, A.privateKey);
  const r = checkAssessorStanding([disc(), self], policy({ declarerKeyIds: [idA, idD] }), NOW);
  assert.equal(r.standings[0].standing, 'good'); assert.deepEqual(r.ignored.map(x => x.reason), ['untrusted-declarer']);
});

test('standing ignores a declaration from a revoked declarer key', () => {
  const r = checkAssessorStanding([disc(), decl()], policy({ revokedKeyIds: [idD] }), NOW);
  assert.equal(r.standings[0].standing, 'good'); assert.deepEqual(r.ignored.map(x => x.reason), ['declarer-revoked']);
  assert.ok(checkAssessorStanding([disc(), decl()], policy(), NOW).standings[0].reasons.includes('blocking-relationship'));
});

test('standing expiry and start boundaries are exact to the millisecond', () => {
  const exp = '2027-03-01T00:00:00.000Z', start = '2026-10-01T00:00:00.000Z';
  assert.equal(stand([disc()], policy(), ms(exp, -1)).standing, 'good');
  assert.deepEqual(stand([disc()], policy(), exp).reasons, ['disclosure-expired']);
  assert.deepEqual(stand([disc()], policy(), ms(start, -1)).reasons, ['disclosure-not-yet-valid']);
  assert.equal(stand([disc()], policy(), start).standing, 'good');
});

test('a conflict declaration stops counting at its exact expiry', () => {
  const d = decl({ expiresAt: '2026-12-01T00:00:00.000Z' });
  assert.ok(stand([disc(), d], policy(), '2026-11-30T23:59:59.999Z').reasons.includes('undisclosed-conflict-declared-by-other-party'));
  assert.equal(stand([disc(), d], policy(), '2026-12-01T00:00:00.000Z').standing, 'good');
});

test('cooling off ends at its exact boundary', () => {
  const pe = disc({ relationships: ['prior-engagement'], priorEngagementEndedAt: '2026-09-20T00:00:00.000Z' });
  const p = policy({ coolingOffDays: 30 });
  assert.deepEqual(stand([pe], p, ms(NOW, -1)).reasons, ['cooling-off-not-elapsed']);
  assert.equal(stand([pe], p, NOW).standing, 'good');
});

const REGISTRY = JSON.parse(await readFile(new URL('../evidence/profile-registry.json', import.meta.url), 'utf8'));
const entry = () => JSON.parse(JSON.stringify(REGISTRY.profiles[0]));

test('a sign-off record with an unexpected field is refused and a complete one is accepted', () => {
  const so = { reviewer: 'A. Reviewer', role: 'domain expert', date: '2026-10-14', evidenceDigest: hashBytes('review record') };
  const ok = entry(); ok.signOff = so;
  assert.equal(validateProfileMetadata(ok).signOff.reviewer, 'A. Reviewer');
  const extra = entry(); extra.signOff = { ...so, note: 'unreviewed free text' };
  assert.throws(() => validateProfileMetadata(extra), /Sign-off/);
});

test('privacy scan never echoes a malformed digest, narrative or coded value from structural findings', () => {
  const secret = 'confidential customer narrative';
  for (const doc of [{ subjectDigest: secret }, { schema: 'kya.incident/v1', note: secret }, { runId: secret }]) {
    const r = scanContent(JSON.stringify(doc), '.json');
    assert.ok(r.findings.length >= 1, JSON.stringify(doc));
    assert.ok(!JSON.stringify(r).includes('confidential'), 'echoed ' + JSON.stringify(doc));
  }
});
