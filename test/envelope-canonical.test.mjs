import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { signDisclosure, verifyDisclosure, checkAssessorStanding } from '../src/assessor/index.mjs';
import { signEvidence, verifyEvidence, keyId, hashBytes } from '../src/index.mjs';
import { bundle } from './helpers.mjs';
import { validatePublicPem, publicKeyObject } from '../src/identity/domain/services/validation.mjs';

const pemOf = k => k.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const A = generateKeyPairSync('ed25519'), D = generateKeyPairSync('ed25519');
const idA = keyId(pemOf(A)), idD = keyId(pemOf(D));
const OP = hashBytes('operator'), NOW = '2026-10-20T00:00:00.000Z';
const base = (patch = {}) => ({ schema: 'kya.assessor-disclosure/v1', id: 'disc:1', kind: 'disclosure', assessorKeyId: idA, operatorDigest: OP, relationships: ['none'], priorEngagementEndedAt: null, refId: null, refDigest: null, issuedAt: '2026-10-01T00:00:00.000Z', expiresAt: '2027-03-01T00:00:00.000Z', detailsDigest: hashBytes('private'), ...patch });
const disc = (patch, key = A.privateKey) => signDisclosure(base(patch), key);

// Spellings of the same SPKI key that Node still parses.
function spellings(pem) {
  const lines = pem.trim().split('\n'), b64 = lines.slice(1, -1).join('');
  const head = '-----BEGIN PUBLIC KEY-----', tail = '-----END PUBLIC KEY-----';
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const last = b64.replace(/=+$/, '').slice(-1), pad = b64.slice(b64.replace(/=+$/, '').length);
  const sloppy = b64.replace(/=+$/, '').slice(0, -1) + ALPHA[(ALPHA.indexOf(last) + 1) % 64] + pad; // same bytes only if unused bits are ignored
  const der = Buffer.from(b64, 'base64');
  const longForm = Buffer.concat([Buffer.from([0x30, 0x81, der[1]]), der.subarray(2)]);
  const trailing = Buffer.concat([der, Buffer.from([0, 0])]);
  const wrap = buf => head + '\n' + buf.toString('base64').replace(/(.{40})/g, '$1\n').replace(/\n$/, '') + '\n' + tail + '\n';
  return {
    crlf: pem.replace(/\n/g, '\r\n'),
    wrapped: head + '\n' + b64.replace(/(.{40})/g, '$1\n').replace(/\n$/, '') + '\n' + tail + '\n',
    noTrailingNewline: pem.replace(/\n$/, ''),
    blankLine: head + '\n\n' + b64 + '\n' + tail + '\n',
    trailingBits: head + '\n' + sloppy + '\n' + tail + '\n',
    derLongForm: wrap(longForm),
    derTrailingZeros: wrap(trailing)
  };
}

test('only the canonical SPKI PEM spelling of a key is accepted', () => {
  const pem = pemOf(A);
  assert.doesNotThrow(() => validatePublicPem(pem));
  for (const [name, spelled] of Object.entries(spellings(pem))) {
    if (spelled === pem) continue;
    assert.throws(() => validatePublicPem(spelled), undefined, 'must refuse spelling ' + name);
  }
});

test('re-encoded public key spellings do not verify as a disclosure envelope', () => {
  const e = disc();
  assert.doesNotThrow(() => verifyDisclosure(e));
  for (const [name, spelled] of Object.entries(spellings(e.proof.publicKey))) {
    assert.throws(() => verifyDisclosure({ payload: e.payload, proof: { ...e.proof, publicKey: spelled } }), undefined, 'must refuse spelling ' + name);
  }
});

test('re-encoded public key spellings do not verify as an evidence envelope', () => {
  const env = bundle()[0];
  assert.doesNotThrow(() => verifyEvidence(env));
  for (const [name, spelled] of Object.entries(spellings(env.proof.publicKey))) {
    assert.throws(() => verifyEvidence({ payload: env.payload, proof: { ...env.proof, publicKey: spelled } }), undefined, 'must refuse spelling ' + name);
  }
});

test('a re-encoded copy of a conflict declaration cannot dodge its digest-bound withdrawal', () => {
  const o = disc();
  const decl = disc({ id: 'decl:1', kind: 'conflict-declaration', relationships: ['control'] }, D.privateKey);
  const w = signDisclosure(base({ id: 'wd:decl:1', kind: 'withdrawal', relationships: [], refId: 'decl:1', refDigest: verifyDisclosure(decl).envelopeDigest }), D.privateKey);
  const policy = { operatorDigest: OP, assessorKeyIds: [idA], declarerKeyIds: [idD] };
  assert.equal(checkAssessorStanding([o, decl, w], policy, NOW).standings[0].standing, 'good');
  const copy = { payload: decl.payload, proof: { ...decl.proof, publicKey: spellings(decl.proof.publicKey).crlf } };
  const r = checkAssessorStanding([o, decl, copy, w], policy, NOW);
  assert.equal(r.standings[0].standing, 'good', 'the withdrawn declaration must stay withdrawn');
  assert.ok(r.ignored.some(i => i.reason === 'invalid-record'));
});

const identityDer = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from([1]), Buffer.alloc(31)]);
const identityPem = '-----BEGIN PUBLIC KEY-----\n' + identityDer.toString('base64') + '\n-----END PUBLIC KEY-----\n';

test('a small order public key is refused by the core key checks', () => {
  assert.doesNotThrow(() => createPublicKey(identityPem));
  assert.throws(() => validatePublicPem(identityPem), /small-order|Ed25519/);
  assert.throws(() => publicKeyObject(identityPem), /small-order|Ed25519/);
  assert.throws(() => keyId(identityPem), /small-order|Ed25519/);
});

test('the identity point signature does not verify any envelope', () => {
  const e = disc();
  const sig = Buffer.concat([Buffer.from([1]), Buffer.alloc(63)]).toString('base64url');
  const forged = { payload: e.payload, proof: { algorithm: 'Ed25519', keyId: hashBytes(identityDer), publicKey: identityPem, signature: sig } };
  assert.throws(() => verifyDisclosure(forged));
});
