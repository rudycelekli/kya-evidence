// verify-credential (contract version 2) of the second implementation, written from "Credential verification" in
// docs/SPECIFICATION.md. Team-built, NOT independent.
import { createPublicKey, verify as edVerify } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { Refusal, canonical, digest, sha256hex, parseStrict, isObj, isTs, ms, HEX64, validPolicy, strictPublicKey } from './kya2.mjs';
import { checkBlockerCodes } from './ops.mjs';

// One RFC 1952 member and nothing after it. node's gunzipSync joins concatenated members and drops trailing zero bytes, which other
// decoders refuse, so it is not used. Written here from the specification text, not shared with the reference.
const CRC_T = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crcOf = buf => { let c = 0xffffffff; for (const x of buf) c = CRC_T[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function gunzipOne(b, max) {
  if (b.length < 18 || b[0] !== 0x1f || b[1] !== 0x8b || b[2] !== 8 || (b[3] & 0xe0)) throw Error('gzip header');
  let p = 10;
  if (b[3] & 4) { if (p + 2 > b.length) throw Error('gzip'); p += 2 + b.readUInt16LE(p); }
  for (const f of [8, 16]) if (b[3] & f) { const z = b.indexOf(0, p); if (z < 0) throw Error('gzip'); p = z + 1; }
  if (b[3] & 2) { if (p + 2 > b.length || (crcOf(b.subarray(0, p)) & 0xffff) !== b.readUInt16LE(p)) throw Error('gzip'); p += 2; }
  if (p > b.length - 8) throw Error('gzip');
  const body = b.subarray(p), r = inflateRawSync(body, { info: true, maxOutputLength: max });
  if (body.length - r.engine.bytesWritten !== 8) throw Error('gzip trailing');
  const t = body.subarray(r.engine.bytesWritten);
  if (t.readUInt32LE(0) !== crcOf(r.buffer) || t.readUInt32LE(4) !== r.buffer.length % 4294967296) throw Error('gzip trailer');
  return r.buffer;
}

const refuse = m => { throw new Refusal(m); };
const RESULT = 'kya.impl-result/v1';
const CTX = 'https://www.w3.org/ns/credentials/v2';
const FIXTURE_LIMITATION = 'Includes synthetic fixture evidence; not a real product benchmark';
const L = 2n ** 252n + 27742317777372353535851937790883648493n; // Ed25519 group order
const B64U = /^[A-Za-z0-9_-]*$/;
const b64uDecode = s => (B64U.test(s) && Buffer.from(s, 'base64url').toString('base64url') === s ? Buffer.from(s, 'base64url') : null);
const has = (o, k) => Object.hasOwn(o, k);
const fail = code => ({ code });
const utf8 = bytes => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
const parseObject = bytes => { try { const v = parseStrict(utf8(bytes)); return isObj(v) ? v : null; } catch { return null; } };

// ---------------------------------------------------------------- did:key
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s) {
  let n = 0n;
  for (const c of s) { const d = B58.indexOf(c); if (d < 0) return null; n = n * 58n + BigInt(d); }
  let z = 0; while (z < s.length && s[z] === '1') z++;
  const hex = n === 0n ? '' : n.toString(16);
  const body = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
  // re-encode to prove the spelling is the canonical one
  let m = n, enc = '';
  for (; m > 0n; m /= 58n) enc = B58[Number(m % 58n)] + enc;
  return '1'.repeat(z) + enc === s ? Buffer.concat([Buffer.alloc(z), body]) : null;
}
// returns { der } for a canonical Ed25519 did:key, else null
function didKey(issuer) {
  if (typeof issuer !== 'string' || !issuer.startsWith('did:key:z')) return null;
  const text = issuer.slice(9);
  if (text.length < 1 || text.length > 512) return null;
  const bytes = b58decode(text);
  if (!bytes || bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) return null;
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes.subarray(2)]);
  const pem = '-----BEGIN PUBLIC KEY-----\n' + der.toString('base64') + '\n-----END PUBLIC KEY-----\n';
  const k = strictPublicKey(pem);
  return k.problem ? null : { der: k.der };
}

// ---------------------------------------------------------------- opening a vc+jwt
function open(token, now, expectedIssuers) {
  if (!isTs(now)) return fail('TIME_INVALID');
  if (token.length === 0 || token.length > 1048576) return fail('MALFORMED');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1]) return fail('MALFORMED');
  const hb = b64uDecode(parts[0]), pb = b64uDecode(parts[1]), sig = b64uDecode(parts[2]);
  if (!hb || !pb || !sig) return fail('MALFORMED');
  const header = parseObject(hb);
  if (!header) return fail('MALFORMED');
  if (header.alg !== 'EdDSA') return fail('ALG_NOT_ALLOWED');
  if (Object.keys(header).some(k => !['alg', 'typ', 'cty', 'kid'].includes(k))) return fail('HEADER_MEMBER_NOT_ALLOWED');
  if (header.typ !== 'vc+jwt' || (has(header, 'cty') && header.cty !== 'vc')) return fail('TYP_NOT_ALLOWED');
  if (typeof header.kid !== 'string') return fail('MALFORMED');
  const payload = parseObject(pb);
  if (!payload) return fail('MALFORMED');
  if (has(payload, 'vc') || has(payload, 'vp')) return fail('PAYLOAD_INVALID');
  const iss = payload.issuer;
  const issuer = typeof iss === 'string' ? iss : (isObj(iss) && typeof iss.id === 'string' ? iss.id : null);
  if (issuer === null) return fail('PAYLOAD_INVALID');
  const key = didKey(issuer);
  if (!key) return fail('ISSUER_INVALID');
  if (header.kid !== issuer + '#' + issuer.slice(8)) return fail('KID_MISMATCH');
  let ok = false;
  if (sig.length === 64) {
    let s = 0n; for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
    if (s < L) {
      try { ok = edVerify(null, Buffer.from(parts[0] + '.' + parts[1], 'ascii'), createPublicKey({ key: key.der, format: 'der', type: 'spki' }), sig); } catch { ok = false; }
    }
  }
  if (!ok) return fail('SIGNATURE_INVALID');
  if (!Array.isArray(payload['@context']) || payload['@context'][0] !== CTX) return fail('PAYLOAD_INVALID');
  if (!Array.isArray(payload.type) || !payload.type.includes('VerifiableCredential')) return fail('PAYLOAD_INVALID');
  if (has(payload, 'iss') && payload.iss !== issuer) return fail('PAYLOAD_INVALID');
  if (!isObj(payload.credentialSubject)) return fail('PAYLOAD_INVALID');
  if (!isTs(payload.validFrom)) return fail('TIME_INVALID');
  if (has(payload, 'validUntil')) {
    if (!isTs(payload.validUntil)) return fail('TIME_INVALID');
    if (ms(payload.validUntil) <= ms(payload.validFrom)) return fail('PAYLOAD_INVALID');
  }
  const nowMs = ms(now);
  if (nowMs < ms(payload.validFrom)) return fail('NOT_YET_VALID');
  if (has(payload, 'validUntil') && nowMs >= ms(payload.validUntil)) return fail('EXPIRED');
  if (has(payload, 'exp') && (typeof payload.exp !== 'number' || nowMs >= payload.exp * 1000)) return fail('EXPIRED');
  if (has(payload, 'nbf') && (typeof payload.nbf !== 'number' || nowMs < payload.nbf * 1000)) return fail('NOT_YET_VALID');
  if (expectedIssuers.length && !expectedIssuers.includes(issuer)) return fail('ISSUER_NOT_EXPECTED');
  return { issuer, trust: expectedIssuers.length ? 'expected' : 'unchecked', der: key.der, payload };
}

// ---------------------------------------------------------------- claims
const same = (a, b) => (a === undefined || b === undefined ? a === b : canonical(a) === canonical(b));
function claimErrors(p) {
  const errs = [];
  const s = p.credentialSubject;
  if (!p.type.includes('KyaAssessmentCredential') || s.type !== 'KyaAssessment') errs.push('PAYLOAD_INVALID');
  for (const k of ['subjectDigest', 'profileDigest', 'policyDigest', 'evaluatorDigest', 'reportDigest']) if (typeof s[k] !== 'string' || !HEX64.test(s[k])) errs.push('PAYLOAD_INVALID');
  const holds = Array.isArray(s.limitations) && s.limitations.includes(FIXTURE_LIMITATION);
  if (!['none', 'mixed', 'runtime', 'fixture', 'declaration'].includes(s.evidenceMode)) errs.push('PAYLOAD_INVALID');
  else if ((s.evidenceMode === 'fixture' || s.evidenceMode === 'mixed') !== holds) errs.push('EVIDENCE_MODE_LIMITATION_MISMATCH');
  if (!Array.isArray(s.limitations) || !s.limitations.length) errs.push('PAYLOAD_INVALID');
  if (s.id !== 'urn:kya:subject:sha256:' + s.subjectDigest) errs.push('PAYLOAD_INVALID');
  const ev = Array.isArray(p.evidence) && p.evidence.length ? p.evidence[0] : undefined;
  if (!isObj(ev) || ev.type !== 'KyaInputDigests' || ['reportDigest', 'subjectDigest', 'profileDigest', 'policyDigest', 'evaluatorDigest'].some(k => !same(ev[k], s[k]))) errs.push('EVIDENCE_REFERENCE_MISMATCH');
  return errs;
}

// ---------------------------------------------------------------- report binding
const WS = /[\u0009-\u000d\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]/;
const statusList = c => (c === undefined || c === null ? [] : Array.isArray(c) ? c : [c]);
function rebuildEntry(e) {
  if (!isObj(e) || typeof e.statusListCredential !== 'string' || !/^https?:\/\//.test(e.statusListCredential) || WS.test(e.statusListCredential)) return null;
  let idx = e.statusListIndex;
  if (typeof idx === 'number') { if (!Number.isSafeInteger(idx) || idx < 0) return null; idx = String(idx); }
  else if (typeof idx !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(idx)) return null;
  if (!has(e, 'statusPurpose')) return null;
  return { type: 'BitstringStatusListEntry', statusPurpose: e.statusPurpose, statusListIndex: idx, statusListCredential: e.statusListCredential };
}
// REPORT_INVALID: schema, checksum and the blockerCodes rules of "Comparison of assessments" only.
const COPIED = ['subjectDigest', 'scopeDigest', 'scopeId', 'profileId', 'profileDigest', 'policyDigest', 'evaluatorDigest', 'reportDigest', 'assessedAt', 'selectedRunId', 'decision', 'score', 'coverage', 'independentCoverage', 'evidenceMode', 'limitations', 'evidenceBundleDigest', 'acceptedEvidenceDigests'];
function reportRefused(r) {
  try {
    if (r.schema !== 'kya.assessment/v1' || typeof r.reportDigest !== 'string' || !HEX64.test(r.reportDigest)) return true;
    const { reportDigest, ...rest } = r;
    if (digest(rest) !== reportDigest) return true;
    checkBlockerCodes(r);
    return false;
  } catch { return true; }
}
function reportBinding(p, report) {
  if (reportRefused(report) || COPIED.some(k => !has(report, k))) return { invalid: true };
  const pick = (o, ks) => Object.fromEntries(ks.filter(k => o[k] !== undefined).map(k => [k, o[k]]));
  const expected = {
    '@context': [CTX, { '@vocab': 'urn:kya:vocab:v1:' }],
    id: 'urn:kya:assessment:sha256:' + report.reportDigest,
    type: ['VerifiableCredential', 'KyaAssessmentCredential'],
    credentialSubject: {
      id: 'urn:kya:subject:sha256:' + report.subjectDigest, type: 'KyaAssessment',
      ...pick(report, ['subjectDigest', 'scopeDigest', 'scopeId', 'profileId', 'profileDigest', 'policyDigest', 'evaluatorDigest', 'reportDigest', 'assessedAt', 'selectedRunId', 'decision', 'score', 'coverage', 'independentCoverage', 'evidenceMode']),
      blockerCodes: report.blockerCodes === undefined ? null : report.blockerCodes,
      ...pick(report, ['limitations']),
      notAsserted: ['human identity', 'authorization grant', 'truthful execution']
    },
    evidence: [{ type: 'KyaInputDigests', ...pick(report, ['subjectDigest', 'profileDigest', 'policyDigest', 'evaluatorDigest', 'evidenceBundleDigest', 'acceptedEvidenceDigests', 'reportDigest']) }]
  };
  for (const k of ['issuer', 'validFrom', 'validUntil']) if (has(p, k)) expected[k] = p[k];
  const entries = statusList(p.credentialStatus);
  let statusBad = false;
  if (entries.length) {
    const rebuilt = entries.map(rebuildEntry);
    if (rebuilt.some(x => x === null)) statusBad = true; else expected.credentialStatus = rebuilt;
  }
  const names = new Set();
  for (const k of new Set([...Object.keys(p), ...Object.keys(expected)])) {
    if (k === 'credentialStatus' && statusBad) { names.add(k); continue; }
    if (has(p, k) !== has(expected, k) || !same(p[k], expected[k])) names.add(k);
  }
  const from = ms(p.validFrom), until = has(p, 'validUntil') ? ms(p.validUntil) : NaN;
  const at = typeof report.assessedAt === 'string' ? ms(report.assessedAt) : NaN, ru = typeof report.validUntil === 'string' ? ms(report.validUntil) : NaN;
  if (!(from >= at)) names.add('validFrom');
  if (!(until <= ru)) names.add('validUntil');
  return { mismatch: [...names].sort() };
}

// ---------------------------------------------------------------- status list check
function statusCheck(entry, token, issuer, now) {
  if (!isObj(entry) || entry.type !== 'BitstringStatusListEntry' || typeof entry.statusListIndex !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(entry.statusListIndex)
    || (has(entry, 'statusSize') && entry.statusSize !== 1) || !['revocation', 'suspension'].includes(entry.statusPurpose)) return { code: 'STATUS_ENTRY_INVALID' };
  const o = open(token, now, [issuer]);
  if (o.code) return { code: o.code === 'EXPIRED' ? 'STATUS_LIST_EXPIRED' : 'STATUS_VERIFICATION_ERROR' };
  const p = o.payload, s = p.credentialSubject;
  if (!has(p, 'validUntil')) return { code: 'STATUS_LIST_NO_EXPIRY' };
  if (has(s, 'ttl')) {
    if (typeof s.ttl !== 'number' || !Number.isSafeInteger(s.ttl) || s.ttl <= 0) return { code: 'STATUS_VERIFICATION_ERROR' };
    if (ms(now) >= ms(p.validFrom) + s.ttl) return { code: 'STATUS_LIST_EXPIRED' };
  }
  if (!p.type.includes('BitstringStatusListCredential') || s.type !== 'BitstringStatusList') return { code: 'STATUS_VERIFICATION_ERROR' };
  if (p.id !== entry.statusListCredential) return { code: 'STATUS_VERIFICATION_ERROR' };
  const sp = s.statusPurpose;
  if (!(sp === entry.statusPurpose || (Array.isArray(sp) && sp.includes(entry.statusPurpose)))) return { code: 'STATUS_VERIFICATION_ERROR' };
  const enc = s.encodedList;
  if (typeof enc !== 'string' || enc.length > 1048576 || enc[0] !== 'u') return { code: 'STATUS_LIST_INVALID' };
  const gz = b64uDecode(enc.slice(1));
  if (!gz) return { code: 'STATUS_LIST_INVALID' };
  let bits;
  try { bits = gunzipOne(gz, 2097152); } catch { return { code: 'STATUS_LIST_INVALID' }; }
  if (bits.length < 16384) return { code: 'STATUS_LIST_LENGTH_ERROR' };
  const index = BigInt(entry.statusListIndex);
  if (index >= BigInt(bits.length) * 8n) return { code: 'RANGE_ERROR' };
  const i = Number(index);
  return { set: ((bits[i >> 3] >> (7 - (i & 7))) & 1) === 1 };
}

// ---------------------------------------------------------------- operation
export function verifyCredentialOp(inputs) {
  const keys = ['jwt', 'now', 'expectedIssuers', 'policy', 'statusLists', 'requireStatusCheck', 'report'];
  if (!isObj(inputs) || Object.keys(inputs).length !== keys.length || keys.some(k => !has(inputs, k))) refuse('inputs must hold exactly ' + keys.join(', '));
  const { jwt, now, expectedIssuers, policy, statusLists, requireStatusCheck, report } = inputs;
  if (typeof jwt !== 'string' || typeof now !== 'string') refuse('jwt and now must be strings');
  if (!Array.isArray(expectedIssuers) || expectedIssuers.some(x => typeof x !== 'string' || !x.startsWith('did:key:'))) refuse('expectedIssuers');
  if (policy !== null) validPolicy(policy, null, null, null);
  if (!isObj(statusLists) || Object.values(statusLists).some(v => typeof v !== 'string' || !v)) refuse('statusLists');
  if (typeof requireStatusCheck !== 'boolean') refuse('requireStatusCheck');
  if (report !== null && !isObj(report)) refuse('report');

  const base = { schema: RESULT, operation: 'verify-credential' };
  const o = open(jwt, now, expectedIssuers);
  if (o.code) return { ...base, valid: false, errors: [o.code], authenticated: false, issuer: null, issuerTrust: null, issuerRole: null, reportChecked: false, reportMismatch: [], status: null };

  const p = o.payload, errors = claimErrors(p);
  let reportChecked = false, reportMismatch = [];
  if (report !== null) {
    const b = reportBinding(p, report);
    if (b.invalid) errors.push('REPORT_INVALID');
    else { reportChecked = true; reportMismatch = b.mismatch; if (b.mismatch.length) errors.push('REPORT_MISMATCH'); }
  }
  let trust = o.trust, role = null;
  if (policy !== null) {
    const kid = sha256hex(o.der);
    const anchor = policy.trustedKeys.find(k => k.id === kid);
    if (!anchor || policy.revokedKeyIds.includes(kid)) errors.push('ISSUER_NOT_TRUSTED');
    else { trust = 'anchored'; role = anchor.role; }
  }
  const entries = statusList(p.credentialStatus).map(e => {
    const purpose = isObj(e) && typeof e.statusPurpose === 'string' ? e.statusPurpose : null;
    const url = isObj(e) ? e.statusListCredential : undefined;
    if (typeof url !== 'string' || !has(statusLists, url)) return { purpose, checked: false, set: null, error: null };
    const r = statusCheck(e, statusLists[url], o.issuer, now);
    if (r.code) {
      errors.push(r.code.startsWith('STATUS_') ? r.code : 'STATUS_VERIFICATION_ERROR');
      return { purpose, checked: false, set: null, error: r.code };
    }
    if (r.set) errors.push(purpose === 'revocation' ? 'REVOKED' : 'SUSPENDED');
    return { purpose, checked: true, set: r.set, error: null };
  });
  const checked = entries.length > 0 && entries.every(e => e.checked);
  if (requireStatusCheck && !checked) errors.push('STATUS_NOT_CHECKED');
  return { ...base, valid: errors.length === 0, errors, authenticated: false, issuer: o.issuer, issuerTrust: trust, issuerRole: role, reportChecked, reportMismatch, status: { checked, entries } };
}
