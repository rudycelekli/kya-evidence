import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHmac, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { assess, signEvidence, digest, keyId } from '../src/index.mjs';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inputs, keys, clone, policy as mkPolicy } from './helpers.mjs';
import { exportAssessmentCredential, verifyAssessmentCredential, didKeyFromPublicKey, publicKeyFromDidKey, base58btcEncode, base58btcDecode, createBitstring, setBit, getBit, encodeList, decodeList, buildStatusListCredential, checkStatus, allocateStatusIndices, revokedLedgerEntries, MIN_STATUS_ENTRIES, b64u , base58btcEncode as b58 } from '../src/vc-bridge/index.mjs';

const issuer = generateKeyPairSync('ed25519');
const other = generateKeyPairSync('ed25519');
const secret = 'a'.repeat(40);
const VF = '2026-10-13T12:00:00.000Z';
const AT = '2026-10-13T12:30:00.000Z';
const LU = '2026-10-13T18:00:00.000Z';
const report = () => assess(inputs());
const exportIt = (r = report(), extra = {}) => exportAssessmentCredential(r, { issuerKey: issuer.privateKey, validFrom: VF, ...extra });
const resign = (jwt, mutate, key = issuer.privateKey) => {
  const [h, p] = jwt.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url')); const payload = JSON.parse(Buffer.from(p, 'base64url'));
  mutate(header, payload);
  const hb = Buffer.from(JSON.stringify(header)).toString('base64url'), pb = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${hb}.${pb}.${sign(null, Buffer.from(`${hb}.${pb}`), key).toString('base64url')}`;
};
const codes = r => r.errors.map(e => e.code);
const listUrl = 'https://example.test/status/rev';
const entry = (i, purpose = 'revocation', extra = {}) => ({ type: 'BitstringStatusListEntry', statusPurpose: purpose, statusListIndex: i, statusListCredential: listUrl, ...extra });
const mkList = (purpose, indices, url = listUrl, extra = {}) => buildStatusListCredential({ issuerKey: issuer.privateKey, id: url, purpose, indices, validFrom: VF, validUntil: LU, ...extra });

test('did key vectors from the CCG spec decode to ed25519 multicodec and re-encode identically', () => {
  for (const did of ['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP']) {
    const raw = publicKeyFromDidKey(did);
    assert.equal(raw.length, 32);
    assert.equal(didKeyFromPublicKey(raw), did);
    const prefixed = base58btcDecode(did.slice(9));
    assert.equal(prefixed[0], 0xed); assert.equal(prefixed[1], 0x01); assert.equal(prefixed.length, 34);
  }
});
test('did key derivation round trips a node key and rejects foreign multicodecs and malformed strings', () => {
  const did = didKeyFromPublicKey(issuer.publicKey);
  assert.match(did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
  assert.equal(didKeyFromPublicKey(publicKeyFromDidKey(did)), did);
  assert.throws(() => publicKeyFromDidKey('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme'), /multicodec/);
  for (const bad of ['did:key:', 'did:web:example.com', 'did:key:u6Mk', 'did:key:z6Mk0OIl', did + '#x', did.slice(0, -2)]) assert.throws(() => publicKeyFromDidKey(bad));
});
test('base58btc keeps leading zero bytes and rejects bad alphabets', () => {
  assert.equal(base58btcEncode(Uint8Array.from([0, 0, 1])), '112');
  assert.deepEqual([...base58btcDecode('112')], [0, 0, 1]);
  assert.throws(() => base58btcDecode('0abc'));
});
test('credential round trips and verifies with a did key issuer and reports authenticated false', () => {
  const r = report(); const out = exportIt(r);
  assert.match(out.jwt, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  const v = verifyAssessmentCredential(out.jwt, { now: AT });
  assert.equal(v.valid, true); assert.equal(v.authenticated, false); assert.equal(v.issuerTrust, 'unchecked');
  assert.equal(v.credential.credentialSubject.decision, r.decision);
  assert.equal(v.credential.credentialSubject.subjectDigest, r.subjectDigest);
  assert.match(v.warning, /possession of the issuer key/);
});
test('header carries vc plus jwt typ EdDSA and a did key kid and payload is the bare credential', () => {
  const out = exportIt(); const [h, p] = out.jwt.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url')); const payload = JSON.parse(Buffer.from(p, 'base64url'));
  assert.deepEqual(Object.keys(header).sort(), ['alg', 'cty', 'kid', 'typ']);
  assert.equal(header.alg, 'EdDSA'); assert.equal(header.typ, 'vc+jwt'); assert.equal(header.cty, 'vc');
  assert.equal(header.kid, `${out.issuer}#${out.issuer.slice(8)}`);
  assert.equal(payload['@context'][0], 'https://www.w3.org/ns/credentials/v2');
  assert.deepEqual(payload.type, ['VerifiableCredential', 'KyaAssessmentCredential']);
  assert.equal(payload.vc, undefined); assert.equal(payload.vp, undefined);
});
test('subject binds the agent by digest only with no person identity or principal fields', () => {
  const r = report(); const c = exportIt(r).credential; const s = c.credentialSubject;
  assert.equal(s.id, `urn:kya:subject:sha256:${r.subjectDigest}`);
  for (const k of ['principalId', 'agentName', 'agentId', 'name', 'email']) assert.equal(Object.hasOwn(s, k), false);
  assert.deepEqual(s.notAsserted, ['human identity', 'authorization grant', 'truthful execution']);
  assert.deepEqual(s.limitations, r.limitations);
  assert.equal(JSON.stringify(c).includes('controller:test'), false);
});
test('credential carries digests score coverage blockers and exact input digest evidence', () => {
  const x = inputs(); x.evidence = x.evidence.slice(0, 3); const r = assess(x); const c = exportIt(r).credential;
  const s = c.credentialSubject;
  assert.deepEqual(s.score, r.score); assert.equal(s.coverage, r.coverage); assert.equal(s.independentCoverage, r.independentCoverage);
  assert.equal(s.profileDigest, r.profileDigest); assert.equal(s.policyDigest, r.policyDigest); assert.equal(s.evaluatorDigest, r.evaluatorDigest);
  assert.deepEqual(s.blockerCodes, r.blockerCodes); assert.ok(s.blockerCodes.length > 0);
  assert.equal(c.evidence[0].type, 'KyaInputDigests');
  assert.equal(c.evidence[0].evidenceBundleDigest, r.evidenceBundleDigest);
  assert.deepEqual(c.evidence[0].acceptedEvidenceDigests, r.acceptedEvidenceDigests);
  assert.equal(c.evidence[0].reportDigest, r.reportDigest);
});
test('export is deterministic for fixed inputs and differs when any input changes', () => {
  const a = exportIt(), b = exportIt();
  assert.equal(a.jwt, b.jwt);
  assert.notEqual(exportIt(report(), { validUntil: '2026-10-13T12:45:00.000Z' }).jwt, a.jwt);
  assert.notEqual(exportAssessmentCredential(report(), { issuerKey: other.privateKey, validFrom: VF }).jwt, a.jwt);
});
test('fixture source assessments are never exported as runtime', () => {
  const r = report(); assert.equal(r.evidenceMode, 'fixture');
  const c = exportIt(r).credential;
  assert.equal(c.credentialSubject.evidenceMode, 'fixture');
  assert.ok(c.credentialSubject.limitations.some(l => /synthetic fixture/.test(l)));
  const stripped = clone(r); stripped.limitations = stripped.limitations.filter(l => !/fixture/.test(l));
  const { reportDigest, ...body } = stripped; stripped.reportDigest = digest(body);
  assert.throws(() => exportIt(stripped), /fixture/);
  const forged = resign(exportIt(r).jwt, (h, p) => { p.credentialSubject.evidenceMode = 'runtime'; });
  const v = verifyAssessmentCredential(forged, { now: AT });
  assert.equal(v.valid, false); assert.ok(codes(v).includes('EVIDENCE_MODE_LIMITATION_MISMATCH'));
  assert.throws(() => exportIt(r, { evidenceMode: 'runtime' }), /Unknown option/);
});
test('runtime evidence mode is preserved verbatim and mixed carries the fixture limitation', () => {
  const x = inputs(); x.policy.allowedSources = ['runtime', 'fixture'];
  x.evidence = x.evidence.map((e, i) => signEvidence({ ...e.payload, source: i === 0 ? 'runtime' : 'fixture' }, keys.privateKey));
  const m = assess(x); assert.equal(m.evidenceMode, 'mixed');
  assert.equal(exportIt(m).credential.credentialSubject.evidenceMode, 'mixed');
  const y = inputs(); y.policy.allowedSources = ['runtime'];
  y.evidence = y.evidence.map(e => signEvidence({ ...e.payload, source: 'runtime' }, keys.privateKey));
  const rt = assess(y); assert.equal(rt.evidenceMode, 'runtime');
  const v = verifyAssessmentCredential(exportIt(rt).jwt, { now: AT });
  assert.equal(v.valid, true); assert.equal(v.credential.credentialSubject.evidenceMode, 'runtime');
});
test('tampered report digest or body is refused at export', () => {
  const r = report(); r.score = { ...r.score, earned: 1 };
  assert.throws(() => exportIt(r), /digest/i);
  assert.throws(() => exportIt({ ...report(), schema: 'x' }));
});
test('payload tampering invalidates the signature', () => {
  const [h, p, s] = exportIt().jwt.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url')); payload.credentialSubject.decision = 'blocked'; payload.credentialSubject.score.earned = 1;
  const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
  assert.ok(codes(verifyAssessmentCredential(forged, { now: AT })).includes('SIGNATURE_INVALID'));
});
test('header tampering and signature tampering are detected', () => {
  const [h, p, s] = exportIt().jwt.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url')); header.kid += 'x';
  assert.equal(verifyAssessmentCredential(`${Buffer.from(JSON.stringify(header)).toString('base64url')}.${p}.${s}`, { now: AT }).valid, false);
  const sig = Buffer.from(s, 'base64url'); sig[0] ^= 1;
  assert.ok(codes(verifyAssessmentCredential(`${h}.${p}.${sig.toString('base64url')}`, { now: AT })).includes('SIGNATURE_INVALID'));
  assert.ok(codes(verifyAssessmentCredential(`${h}.${p}.${s.slice(0, -2)}`, { now: AT })).length > 0);
});
test('a correctly signed token whose kid names a different method is refused', () => {
  const jwt = exportIt().jwt; const otherDid = didKeyFromPublicKey(other.publicKey);
  const r = verifyAssessmentCredential(resign(jwt, h => { h.kid = `${otherDid}#${otherDid.slice(8)}`; }), { now: AT });
  assert.equal(r.valid, false); assert.ok(codes(r).includes('KID_MISMATCH'));
  assert.ok(codes(verifyAssessmentCredential(resign(jwt, h => { h.kid = 'did:key:zabc'; }), { now: AT })).includes('KID_MISMATCH'));
});
test('alg none HS256 and unknown algorithms are refused before any key use', () => {
  const jwt = exportIt().jwt; const [, p, s] = jwt.split('.');
  for (const alg of ['none', 'HS256', 'RS256', 'ES256', 'EdDSA ', 'eddsa', 'Ed25519']) {
    const h = Buffer.from(JSON.stringify({ alg, typ: 'vc+jwt', cty: 'vc', kid: 'x' })).toString('base64url');
    const r = verifyAssessmentCredential(`${h}.${p}.${alg === 'none' ? '' : s}`, { now: AT });
    assert.equal(r.valid, false); assert.ok(codes(r).includes('ALG_NOT_ALLOWED') || codes(r).includes('MALFORMED'), alg);
  }
  const mac = createHmac('sha256', 'k').update('a.b').digest('base64url');
  const h2 = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'vc+jwt', kid: 'x' })).toString('base64url');
  assert.ok(codes(verifyAssessmentCredential(`${h2}.${p}.${mac}`, { now: AT })).includes('ALG_NOT_ALLOWED'));
});
test('typ cty and unknown or key bearing header members are refused', () => {
  const jwt = exportIt().jwt;
  assert.ok(codes(verifyAssessmentCredential(resign(jwt, h => { h.typ = 'JWT'; }), { now: AT })).includes('TYP_NOT_ALLOWED'));
  assert.ok(codes(verifyAssessmentCredential(resign(jwt, h => { h.cty = 'vp'; }), { now: AT })).includes('TYP_NOT_ALLOWED'));
  for (const member of ['jwk', 'jku', 'x5u', 'crit', 'x5c']) assert.ok(codes(verifyAssessmentCredential(resign(jwt, h => { h[member] = member === 'crit' ? ['x'] : 'y'; }), { now: AT })).includes('HEADER_MEMBER_NOT_ALLOWED'), member);
});
test('signature by a different key than the issuer did is refused', () => {
  const forged = resign(exportIt().jwt, () => {}, other.privateKey);
  assert.ok(codes(verifyAssessmentCredential(forged, { now: AT })).includes('SIGNATURE_INVALID'));
});
test('expired and not yet valid credentials are refused at explicit times', () => {
  const out = exportIt(report(), { validUntil: '2026-10-13T13:00:00.000Z' });
  assert.ok(codes(verifyAssessmentCredential(out.jwt, { now: '2026-10-13T11:59:59.999Z' })).includes('NOT_YET_VALID'));
  assert.equal(verifyAssessmentCredential(out.jwt, { now: '2026-10-13T12:00:00.000Z' }).valid, true);
  assert.ok(codes(verifyAssessmentCredential(out.jwt, { now: '2026-10-13T13:00:00.000Z' })).includes('EXPIRED'));
});
test('validity can only narrow the assessment window and never predate it', () => {
  const r = report();
  assert.equal(exportIt(r).credential.validUntil, r.validUntil);
  assert.throws(() => exportIt(r, { validUntil: '2030-01-01T00:00:00.000Z' }), /outlive/);
  assert.throws(() => exportIt(r, { validFrom: '2026-10-13T11:00:00.000Z' }), /predate/);
  assert.throws(() => exportIt(r, { validFrom: 'yesterday' }));
});
test('expected issuer keys must include the issuer and a policy must anchor it', () => {
  const out = exportIt(); const good = didKeyFromPublicKey(issuer.publicKey), bad = didKeyFromPublicKey(other.publicKey);
  assert.equal(verifyAssessmentCredential(out.jwt, { now: AT, expectedIssuerKeys: [good] }).issuerTrust, 'expected');
  assert.ok(codes(verifyAssessmentCredential(out.jwt, { now: AT, expectedIssuerKeys: [bad] })).includes('ISSUER_NOT_EXPECTED'));
  const pol = { trustedKeys: [{ id: keyId(issuer.publicKey), publicKey: issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString(), role: 'independent' }], revokedKeyIds: [] };
  const a = verifyAssessmentCredential(out.jwt, { now: AT, policy: pol });
  assert.equal(a.valid, true); assert.equal(a.issuerTrust, 'anchored'); assert.equal(a.issuerRole, 'independent'); assert.equal(a.authenticated, false);
  assert.ok(codes(verifyAssessmentCredential(out.jwt, { now: AT, policy: { ...pol, trustedKeys: [] } })).includes('ISSUER_NOT_TRUSTED'));
  assert.ok(codes(verifyAssessmentCredential(out.jwt, { now: AT, policy: { ...pol, revokedKeyIds: [keyId(issuer.publicKey)] } })).includes('ISSUER_NOT_TRUSTED'));
});
test('compact token shape is strict', () => {
  const jwt = exportIt().jwt;
  for (const bad of ['', 'a.b', `${jwt}.x`, jwt + '=', jwt.replace('.', '. '), 'a..c', 42, null]) assert.ok(codes(verifyAssessmentCredential(bad, { now: AT })).includes('MALFORMED'));
});
test('status list bit order matches the spec with index zero as the leftmost bit', () => {
  const b = createBitstring(131072); setBit(b, 0); setBit(b, 9); setBit(b, 131071);
  assert.equal(b[0], 0b10000000); assert.equal(b[1], 0b01000000); assert.equal(b[16383], 0b00000001);
  assert.equal(getBit(b, 0), 1); assert.equal(getBit(b, 1), 0); assert.equal(getBit(b, 9), 1); assert.equal(getBit(b, 131071), 1);
  assert.equal(MIN_STATUS_ENTRIES, 131072); assert.equal(b.length, 16384);
});
test('status list encoding round trips with gzip and the u multibase prefix', () => {
  const b = createBitstring(131072); [3, 77, 99999].forEach(i => setBit(b, i));
  const enc = encodeList(b); assert.equal(enc[0], 'u'); assert.match(enc, /^u[A-Za-z0-9_-]+$/);
  assert.equal(enc.includes('='), false);
  assert.deepEqual(decodeList(enc), b);
  assert.equal(Buffer.from(enc.slice(1), 'base64url').subarray(0, 2).toString('hex'), '1f8b');
});
test('status list decoding refuses wrong prefix padding and corrupt data', () => {
  const enc = encodeList(createBitstring(131072));
  assert.throws(() => decodeList('z' + enc.slice(1)), /prefix/);
  assert.throws(() => decodeList(enc + '='), /encoding/);
  assert.throws(() => decodeList('u'));
  assert.throws(() => decodeList('u' + Buffer.from('not gzip').toString('base64url')));
  assert.throws(() => decodeList(5));
});
test('gzip bombs are rejected by bounded decompression', () => {
  const bomb = 'u' + gzipSync(Buffer.alloc(64 * 1024 * 1024)).toString('base64url');
  assert.ok(bomb.length < 200_000);
  assert.throws(() => decodeList(bomb), /exceeds/);
  assert.throws(() => decodeList(encodeList(createBitstring(131072)), { maxBytes: 1024 }), /exceeds/);
  assert.throws(() => decodeList('u' + 'A'.repeat(3_000_000)), /too large/);
});
test('status list credential sets only the requested bits and key changes are detected by checkStatus', () => {
  const list = mkList('revocation', [5, 100]);
  assert.equal(checkStatus(list.jwt, entry('5'), { now: AT }).valid, false);
  assert.equal(checkStatus(list.jwt, entry('100'), { now: AT }).set, true);
  assert.equal(checkStatus(list.jwt, entry('6'), { now: AT }).valid, true);
  assert.equal(checkStatus(list.jwt, entry('131071'), { now: AT }).valid, true);
  const c = list.credential; assert.deepEqual(c.type, ['VerifiableCredential', 'BitstringStatusListCredential']);
  assert.equal(c.credentialSubject.type, 'BitstringStatusList'); assert.equal(c.credentialSubject.statusPurpose, 'revocation');
  const flip = (h, p) => { const b = decodeList(p.credentialSubject.encodedList); b[0] ^= 0b00000100; p.credentialSubject.encodedList = encodeList(b); };
  assert.throws(() => checkStatus(resign(list.jwt, flip, other.privateKey), entry('5'), { now: AT }), /STATUS_VERIFICATION_ERROR/);
  assert.equal(checkStatus(resign(list.jwt, flip), entry('5'), { now: AT }).valid, true);
});
test('wrong index out of range and wrong purpose and malformed entries are refused', () => {
  const list = mkList('revocation', [1]);
  assert.throws(() => checkStatus(list.jwt, entry('131072'), { now: AT }), /RANGE_ERROR/);
  assert.throws(() => checkStatus(list.jwt, entry('-1'), { now: AT }), /index/);
  assert.throws(() => checkStatus(list.jwt, entry(1), { now: AT }), /index/);
  assert.throws(() => checkStatus(list.jwt, entry('01'), { now: AT }), /index/);
  assert.throws(() => checkStatus(list.jwt, entry('1', 'suspension'), { now: AT }), /purpose/);
  assert.throws(() => checkStatus(list.jwt, entry('1', 'revocation', { statusSize: 2 }), { now: AT }), /statusSize/);
  assert.throws(() => checkStatus(list.jwt, { ...entry('1'), type: 'Other' }, { now: AT }), /type/);
});
test('undersized lists are refused at build and at check', () => {
  assert.throws(() => mkList('revocation', [1], listUrl, { size: 1024 }), /at least 131072/);
  const small = createBitstring(1024); setBit(small, 3);
  const jwt = resign(mkList('revocation', [1]).jwt, (h, p) => { p.credentialSubject.encodedList = encodeList(small); });
  assert.throws(() => checkStatus(jwt, entry('3'), { now: AT }), /STATUS_LIST_LENGTH_ERROR/);
  assert.equal(checkStatus(jwt, entry('3'), { now: AT, minimumEntries: 1024 }).valid, false);
});
test('suspension is reversible by republishing and only revocation and suspension purposes are built', () => {
  const url = 'https://example.test/status/sus';
  const sus = mkList('suspension', [42], url);
  const e = entry('42', 'suspension', { statusListCredential: url });
  assert.equal(checkStatus(sus.jwt, e, { now: AT }).valid, false);
  const lifted = mkList('suspension', [], url, { validFrom: '2026-10-13T12:10:00.000Z' });
  assert.equal(checkStatus(lifted.jwt, e, { now: AT }).valid, true);
  assert.throws(() => mkList('message', []), /purpose/);
});
test('status list must be signed by the expected issuer and be in its validity window', () => {
  const list = mkList('revocation', [1], listUrl, { validUntil: '2026-10-13T13:00:00.000Z' });
  assert.throws(() => checkStatus(list.jwt, entry('1'), { now: AT, expectedIssuerKeys: [didKeyFromPublicKey(other.publicKey)] }), /issuer/);
  assert.equal(checkStatus(list.jwt, entry('1'), { now: AT, expectedIssuerKeys: [didKeyFromPublicKey(issuer.publicKey)] }).valid, false);
  assert.throws(() => checkStatus(list.jwt, entry('1'), { now: '2026-10-13T13:00:00.000Z' }), /STATUS_LIST_EXPIRED/);
  assert.throws(() => checkStatus(list.jwt, entry('1'), { now: '2026-10-13T11:00:00.000Z' }), /window/);
  assert.throws(() => checkStatus(list.jwt, entry('1', 'revocation', { statusListCredential: 'https://example.test/other' }), { now: AT }), /URL/);
});
test('index assignment is deterministic keyed and does not reveal the subject digest', () => {
  const r = report();
  const a = allocateStatusIndices({ secret, reportDigest: r.reportDigest, ledger: [] });
  assert.deepEqual(a, allocateStatusIndices({ secret, reportDigest: r.reportDigest, ledger: [] }));
  assert.notDeepEqual(a, allocateStatusIndices({ secret: 'b'.repeat(40), reportDigest: r.reportDigest, ledger: [] }));
  assert.notEqual(a.revocation, a.suspension);
  assert.notEqual(a.revocation, Number(BigInt('0x' + r.subjectDigest) % 131072n));
  assert.notEqual(a.revocation, Number(BigInt('0x' + r.reportDigest) % 131072n));
  const spread = new Set(Array.from({ length: 20 }, (_, i) => allocateStatusIndices({ secret, reportDigest: digest({ i }), ledger: [] }).revocation));
  assert.ok(spread.size >= 19, 'indices depend on the credential');
  assert.throws(() => allocateStatusIndices({ secret: 'short', reportDigest: r.reportDigest, ledger: [] }), /secret/);
  assert.throws(() => allocateStatusIndices({ secret, reportDigest: r.subjectDigest.slice(1), ledger: [] }));
});
test('index assignment avoids collisions with earlier ledger entries and never moves them', () => {
  const ledger = []; const seen = new Set();
  for (let i = 0; i < 300; i++) {
    const reportDigest = digest({ i }); const idx = allocateStatusIndices({ secret, reportDigest, ledger, size: 512 });
    assert.equal(seen.has(idx.revocation), false); seen.add(idx.revocation);
    ledger.push({ reportDigest, subjectDigest: digest({ s: i }), evidenceIds: [], indices: idx });
  }
  assert.equal(allocateStatusIndices({ secret, reportDigest: ledger[7].reportDigest, ledger: ledger.slice(0, 7), size: 512 }).revocation, ledger[7].indices.revocation);
  const full = Array.from({ length: 512 }, (_, i) => ({ reportDigest: digest(['f', i]), subjectDigest: digest(i), evidenceIds: [], indices: { revocation: i, suspension: i } }));
  assert.throws(() => allocateStatusIndices({ secret, reportDigest: digest('full'), ledger: full, size: 512 }), /full/);
});
test('kya revocation lists map to revoked ledger entries by subject digest and by evidence id', () => {
  const r = report(); const ledger = [];
  const mk = (reportDigest, subjectDigest, evidenceIds) => { const indices = allocateStatusIndices({ secret, reportDigest, ledger }); const e = { reportDigest, subjectDigest, evidenceIds, indices }; ledger.push(e); return e; };
  const a = mk(r.reportDigest, r.subjectDigest, ['evidence-0', 'evidence-1']);
  const b = mk(digest('b'), digest('sb'), ['evidence-9']);
  const c = mk(digest('c'), digest('sc'), ['evidence-5']);
  const rev = revokedLedgerEntries(ledger, { ...mkPolicy(), revokedSubjectDigests: [r.subjectDigest], revokedEvidenceIds: ['evidence-5'] });
  assert.deepEqual(rev.map(x => x.reportDigest).sort(), [a.reportDigest, c.reportDigest].sort());
  assert.equal(rev.includes(b), false);
  assert.deepEqual(revokedLedgerEntries(ledger, mkPolicy()), []);
});
test('exported credential status entries verify against status lists and revoked credentials fail verification', () => {
  const r = report(); const indices = allocateStatusIndices({ secret, reportDigest: r.reportDigest, ledger: [] });
  const sus = 'https://example.test/status/sus';
  const out = exportIt(r, { status: { revocation: { statusListCredential: listUrl, statusListIndex: indices.revocation }, suspension: { statusListCredential: sus, statusListIndex: indices.suspension } } });
  const st = out.credential.credentialStatus; assert.equal(st.length, 2); assert.equal(st[0].type, 'BitstringStatusListEntry'); assert.equal(st[0].statusListIndex, String(indices.revocation));
  const clean = { [listUrl]: mkList('revocation', []).jwt, [sus]: mkList('suspension', [], sus).jwt };
  const ok = verifyAssessmentCredential(out.jwt, { now: AT, statusLists: clean });
  assert.equal(ok.valid, true); assert.equal(ok.status.checked, true); assert.equal(ok.authenticated, false);
  const bad = verifyAssessmentCredential(out.jwt, { now: AT, statusLists: { ...clean, [listUrl]: mkList('revocation', [indices.revocation]).jwt } });
  assert.equal(bad.valid, false); assert.ok(codes(bad).includes('REVOKED'));
  assert.ok(codes(verifyAssessmentCredential(out.jwt, { now: AT, statusLists: { ...clean, [sus]: mkList('suspension', [indices.suspension], sus).jwt } })).includes('SUSPENDED'));
  const none = verifyAssessmentCredential(out.jwt, { now: AT });
  assert.equal(none.valid, true); assert.equal(none.status.checked, false);
  assert.ok(codes(verifyAssessmentCredential(out.jwt, { now: AT, requireStatusCheck: true })).includes('STATUS_NOT_CHECKED'));
  const foreign = { ...clean, [listUrl]: buildStatusListCredential({ issuerKey: other.privateKey, id: listUrl, purpose: 'revocation', indices: [], validFrom: VF, validUntil: LU }).jwt };
  assert.ok(codes(verifyAssessmentCredential(out.jwt, { now: AT, statusLists: foreign })).includes('STATUS_VERIFICATION_ERROR'));
});
test('legacy reports without blocker codes export with explicit null codes', () => {
  const { blockerCodes, reportDigest, ...rest } = report(); const legacy = { ...rest, reportDigest: digest(rest) };
  assert.equal(exportIt(legacy).credential.credentialSubject.blockerCodes, null);
});
test('base64url helper is canonical and strict', () => {
  assert.equal(b64u.decode(b64u.encode(Buffer.from('hello'))).toString(), 'hello');
  assert.throws(() => b64u.decode('aGVsbG8='));
  assert.throws(() => b64u.decode('aGVsbG9'));
});

const P = (1n << 255n) - 19n;
const modpow = (b, e, m = P) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };
const inv = a => modpow(a, P - 2n);
const leBytes = (n, len = 32) => { const o = Buffer.alloc(len); for (let i = 0; i < len; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o; };
const didOf = raw => 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));
const D = (P - 121665n * inv(121666n) % P) % P;
const onCurve = y => { const u = (y * y - 1n + P) % P, v = (D * y * y + 1n) % P; const t = u * inv(v) % P; return t === 0n || modpow(t, (P - 1n) / 2n) === 1n; };

test('small order and non canonical ed25519 public keys are rejected in did key decoding', () => {
  const identity = leBytes(1n), order2 = leBytes(P - 1n), nonCanonical = leBytes(P + 1n);
  let y = 2n; while (onCurve(y)) y++;
  const offCurve = leBytes(y);
  assert.equal(order2.toString('hex'), 'ec' + 'ff'.repeat(30) + '7f');
  for (const [name, raw, re] of [['identity', identity, /small-order/], ['order two', order2, /small-order/], ['non-canonical y', nonCanonical, /non-canonical/], ['off curve', offCurve, /not on the curve/]]) {
    assert.throws(() => publicKeyFromDidKey(didOf(raw)), re, name);
    assert.throws(() => didKeyFromPublicKey(raw), re, name);
  }
  const identityNegativeSign = Buffer.from(identity); identityNegativeSign[31] |= 0x80;
  assert.throws(() => publicKeyFromDidKey(didOf(identityNegativeSign)), /non-canonical|small-order/);
  for (let i = 0; i < 8; i++) { const k = generateKeyPairSync('ed25519').publicKey; assert.equal(publicKeyFromDidKey(didKeyFromPublicKey(k)).length, 32); }
  assert.equal(publicKeyFromDidKey('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK').length, 32);
});
test('identity key forgery with base point R and S equal one is refused by credential and status list verification', () => {
  const did = didOf(leBytes(1n));
  const basepointY = 4n * inv(5n) % P;
  const sig = Buffer.concat([leBytes(basepointY), leBytes(1n)]);
  const header = { alg: 'EdDSA', typ: 'vc+jwt', cty: 'vc', kid: `${did}#${did.slice(8)}` };
  const payload = { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'KyaAssessmentCredential'], issuer: did, validFrom: VF, credentialSubject: { type: 'KyaAssessment' } };
  const enc = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forged = `${enc(header)}.${enc(payload)}.${sig.toString('base64url')}`;
  const r = verifyAssessmentCredential(forged, { now: AT });
  assert.equal(r.valid, false); assert.ok(codes(r).includes('ISSUER_INVALID'));
  assert.throws(() => checkStatus(forged, entry('1'), { now: AT }), /STATUS_VERIFICATION_ERROR/);
});
test('status lists must carry validUntil and an expired or stale list is reported as STATUS_LIST_EXPIRED', () => {
  assert.throws(() => buildStatusListCredential({ issuerKey: issuer.privateKey, id: listUrl, purpose: 'revocation', indices: [], validFrom: VF }), /validUntil/);
  const noExpiry = resign(mkList('revocation', [1]).jwt, (h, p) => { delete p.validUntil; });
  assert.throws(() => checkStatus(noExpiry, entry('1'), { now: AT }), /STATUS_LIST_NO_EXPIRY/);
  const list = mkList('revocation', [1], listUrl, { validUntil: '2026-10-13T13:00:00.000Z' });
  assert.equal(list.credential.validUntil, '2026-10-13T13:00:00.000Z');
  assert.throws(() => checkStatus(list.jwt, entry('1'), { now: '2026-10-13T13:00:00.000Z' }), /STATUS_LIST_EXPIRED/);
  const ttl = mkList('revocation', [1], listUrl, { ttl: 600000 });
  assert.equal(ttl.credential.credentialSubject.ttl, 600000);
  assert.equal(checkStatus(ttl.jwt, entry('1'), { now: '2026-10-13T12:09:59.999Z' }).set, true);
  assert.throws(() => checkStatus(ttl.jwt, entry('1'), { now: '2026-10-13T12:10:00.000Z' }), /STATUS_LIST_EXPIRED/);
  assert.throws(() => mkList('revocation', [1], listUrl, { ttl: 0 }), /ttl/);
});
test('credential verification reports an expired status list distinctly and a stale list never counts as checked', () => {
  const r = report(); const indices = allocateStatusIndices({ secret, reportDigest: r.reportDigest, ledger: [] });
  const out = exportIt(r, { status: { revocation: { statusListCredential: listUrl, statusListIndex: indices.revocation } } });
  const stale = mkList('revocation', [], listUrl, { validUntil: '2026-10-13T12:10:00.000Z' });
  const v = verifyAssessmentCredential(out.jwt, { now: AT, statusLists: { [listUrl]: stale.jwt }, requireStatusCheck: true });
  assert.equal(v.valid, false); assert.ok(codes(v).includes('STATUS_LIST_EXPIRED')); assert.equal(v.status.checked, false);
});
test('revokedLedgerEntries validates the policy and the ledger and rejects junk', () => {
  const ledger = [{ reportDigest: digest('a'), subjectDigest: digest('b'), evidenceIds: [], indices: { revocation: 1, suspension: 2 } }];
  assert.throws(() => revokedLedgerEntries(ledger, {}));
  assert.throws(() => revokedLedgerEntries(ledger, { revokedSubjectDigests: [], revokedEvidenceIds: [] }));
  assert.throws(() => revokedLedgerEntries([{ subjectDigest: 'x' }], mkPolicy()), /ledger/i);
  assert.throws(() => revokedLedgerEntries('nope', mkPolicy()), /ledger/i);
});
test('status-list CLI refuses an empty policy and a missing valid until and signs a bounded list otherwise', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-vc-'));
  const pem = join(dir, 'k.pem'); writeFileSync(pem, issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  const pol = join(dir, 'pol.json'), good = join(dir, 'good.json'), led = join(dir, 'led.json');
  writeFileSync(pol, '{}'); writeFileSync(good, JSON.stringify(mkPolicy())); writeFileSync(led, '[]');
  const base = ['status-list', '--purpose', 'revocation', '--url', listUrl, '--ledger', led, '--key', pem, '--now', VF];
  const run = args => spawnSync(process.execPath, ['scripts/kya-vc.mjs', ...args], { encoding: 'utf8', timeout: 20000 });
  assert.notEqual(run([...base, '--policy', pol, '--valid-until', LU]).status, 0);
  assert.notEqual(run([...base, '--policy', good]).status, 0);
  const ok = run([...base, '--policy', good, '--valid-until', LU, '--out', join(dir, 'l.jwt')]);
  assert.equal(ok.status, 0, ok.stderr);
});
test('verification with the source report cross checks mode decision and digests and exposes a re-signed edit', () => {
  const r = report(); const jwt = exportIt(r).jwt;
  const edit = (h, p) => { p.credentialSubject.evidenceMode = 'runtime'; p.credentialSubject.limitations = p.credentialSubject.limitations.filter(l => !/fixture/.test(l)); };
  const forged = resign(jwt, edit);
  const alone = verifyAssessmentCredential(forged, { now: AT });
  assert.equal(alone.valid, true, 'without the report only internal consistency is checked');
  assert.equal(alone.reportChecked, false); assert.equal(alone.authenticated, false);
  const checked = verifyAssessmentCredential(forged, { now: AT, report: r });
  assert.equal(checked.valid, false); assert.ok(codes(checked).includes('REPORT_MISMATCH')); assert.match(checked.errors.find(e => e.code === 'REPORT_MISMATCH').message, /evidenceMode/);
  const ok = verifyAssessmentCredential(jwt, { now: AT, report: r });
  assert.equal(ok.valid, true); assert.equal(ok.reportChecked, true);
  for (const [k, v] of [['decision', 'blocked'], ['subjectDigest', digest('x')], ['coverage', 0.5]]) {
    const bad = verifyAssessmentCredential(resign(jwt, (h, p) => { p.credentialSubject[k] = v; if (k === 'subjectDigest') p.credentialSubject.id = `urn:kya:subject:sha256:${v}`; }), { now: AT, report: r });
    assert.ok(codes(bad).includes('REPORT_MISMATCH'), k);
  }
  const tampered = clone(r); tampered.score = { ...r.score, earned: 3 };
  assert.ok(codes(verifyAssessmentCredential(jwt, { now: AT, report: tampered })).includes('REPORT_INVALID'));
});
