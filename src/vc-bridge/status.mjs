import { createHmac, createPublicKey } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { hash, validatePolicy } from '../identity/domain/services/validation.mjs';
import { b64u } from './encoding.mjs';
import { fail, signCompact, privateKeyObject, VcBridgeError } from './jws.mjs';
import { openCredential, checkTime, VC_CONTEXT } from './open.mjs';
import { didKeyFromPublicKey } from './encoding.mjs';

// W3C Bitstring Status List v1.0 (Recommendation, 15 May 2025): at least 16 KB uncompressed, which is
// 131,072 entries; index 0 is the leftmost bit. The spec sets no decompression ceiling, so this one is ours.
export const MIN_STATUS_ENTRIES = 131_072;
export const DEFAULT_MAX_DECODED_BYTES = 2 * 1024 * 1024;
const MAX_ENCODED_CHARS = 1_048_576;
export const STATUS_PURPOSES = Object.freeze(['revocation', 'suspension']);

export function createBitstring(size = MIN_STATUS_ENTRIES) {
  if (!Number.isSafeInteger(size) || size <= 0 || size % 8 !== 0) fail('STATUS_LIST_INVALID', 'Bitstring size must be a positive multiple of 8');
  return new Uint8Array(size / 8);
}
const check = (bits, i) => { if (!Number.isSafeInteger(i) || i < 0 || i >= bits.length * 8) fail('RANGE_ERROR', 'Status list position is outside the bitstring'); };
export function setBit(bits, i, on = true) { check(bits, i); const m = 0x80 >> (i % 8); bits[i >> 3] = on ? bits[i >> 3] | m : bits[i >> 3] & ~m; }
export function getBit(bits, i) { check(bits, i); return (bits[i >> 3] >> (7 - (i % 8))) & 1; }

/** GZIP, then multibase base64url (prefix u, no padding). */
export function encodeList(bits) { return 'u' + b64u.encode(gzipSync(Buffer.from(bits), { level: 9 })); }

/** Decode with a hard ceiling on decompressed size, so a small gzip bomb cannot exhaust memory. */
export function decodeList(encoded, { maxBytes = DEFAULT_MAX_DECODED_BYTES } = {}) {
  if (typeof encoded !== 'string') fail('STATUS_LIST_INVALID', 'encodedList must be a string');
  if (encoded.length > MAX_ENCODED_CHARS) fail('STATUS_LIST_INVALID', 'encodedList is too large');
  if (encoded[0] !== 'u') fail('STATUS_LIST_INVALID', 'encodedList must use multibase prefix u (base64url)');
  let packed;
  try { packed = b64u.decode(encoded.slice(1)); } catch (e) { return fail('STATUS_LIST_INVALID', 'encodedList has invalid base64url encoding'); }
  try { return Uint8Array.from(gunzipSync(packed, { maxOutputLength: maxBytes })); }
  catch (e) {
    if (e?.code === 'ERR_BUFFER_TOO_LARGE' || /larger than|exceeds/i.test(e?.message ?? '')) fail('STATUS_LIST_INVALID', `Decoded status list exceeds ${maxBytes} bytes`);
    return fail('STATUS_LIST_INVALID', 'encodedList is not valid gzip data');
  }
}

/** Build and sign a BitstringStatusListCredential (vc+jwt). `indices` are the set bits. */
export function buildStatusListCredential({ issuerKey, id, purpose, indices, validFrom, validUntil, ttl, size = MIN_STATUS_ENTRIES }) {
  if (!STATUS_PURPOSES.includes(purpose)) fail('STATUS_LIST_INVALID', 'Unsupported status purpose: only revocation and suspension are built');
  if (size < MIN_STATUS_ENTRIES) fail('STATUS_LIST_INVALID', `Status list must have at least ${MIN_STATUS_ENTRIES} entries for herd privacy`);
  if (typeof id !== 'string' || !/^https?:\/\/\S+$/.test(id)) fail('STATUS_LIST_INVALID', 'id must be the URL where the list will be published (never fetched here)');
  const from = checkTime(validFrom, 'validFrom');
  // A list with no end of validity can never be recognised as stale, so a list that predates a revocation would stay acceptable forever.
  if (validUntil === undefined) fail('STATUS_LIST_INVALID', 'validUntil is required so that a stale list can be refused');
  if (checkTime(validUntil, 'validUntil') <= from) fail('STATUS_LIST_INVALID', 'validUntil must follow validFrom');
  if (ttl !== undefined && !(Number.isSafeInteger(ttl) && ttl > 0)) fail('STATUS_LIST_INVALID', 'ttl must be a positive integer number of milliseconds');
  const bits = createBitstring(size);
  for (const i of indices) setBit(bits, i);
  const issuer = didKeyFromPublicKey(createPublicKey(privateKeyObject(issuerKey)));
  const credential = {
    '@context': [VC_CONTEXT], id, type: ['VerifiableCredential', 'BitstringStatusListCredential'], issuer, validFrom,
    validUntil,
    credentialSubject: { id: `${id}#list`, type: 'BitstringStatusList', statusPurpose: purpose, encodedList: encodeList(bits), ...(ttl === undefined ? {} : { ttl }) }
  };
  return { jwt: signCompact(credential, issuerKey).token, credential, issuer };
}

const wrap = (fn) => { try { return fn(); } catch (e) { if (e instanceof VcBridgeError && e.code.startsWith('STATUS_') || e.code === 'RANGE_ERROR') throw e; throw new VcBridgeError('STATUS_VERIFICATION_ERROR', `Status list failed verification: ${e.message}`); } };

/**
 * Read one status bit. Verifies the list credential (signature, window, optional expected issuers) and
 * applies the spec checks: purpose match, minimum length, range. Network access never happens here: the
 * caller supplies the list credential that `entry.statusListCredential` names.
 */
export function checkStatus(listJwt, entry, { now, expectedIssuerKeys = [], minimumEntries = MIN_STATUS_ENTRIES, maxDecodedBytes = DEFAULT_MAX_DECODED_BYTES, expectedUrl } = {}) {
  if (!entry || entry.type !== 'BitstringStatusListEntry') fail('STATUS_ENTRY_INVALID', 'Status entry type must be BitstringStatusListEntry');
  if (typeof entry.statusListIndex !== 'string' || !/^(0|[1-9]\d{0,15})$/.test(entry.statusListIndex)) fail('STATUS_ENTRY_INVALID', 'statusListIndex must be a base-10 string of a non-negative integer without leading zeros (status list index)');
  if (entry.statusSize !== undefined && entry.statusSize !== 1) fail('STATUS_ENTRY_INVALID', 'Only statusSize 1 is supported');
  if (!STATUS_PURPOSES.includes(entry.statusPurpose)) fail('STATUS_ENTRY_INVALID', 'Unsupported status purpose');
  const index = Number(entry.statusListIndex);
  const opened = wrap(() => {
    try { return openCredential(listJwt, { now, expectedIssuerKeys }); }
    catch (e) {
      if (e.code === 'ISSUER_NOT_EXPECTED') fail('STATUS_VERIFICATION_ERROR', 'Status list issuer is not an expected issuer');
      if (e.code === 'EXPIRED') fail('STATUS_LIST_EXPIRED', 'Status list has expired; a stale list may predate a revocation');
      if (e.code === 'NOT_YET_VALID') fail('STATUS_VERIFICATION_ERROR', 'Status list is outside its validity window');
      throw e;
    }
  });
  const c = opened.credential;
  if (c.validUntil === undefined) fail('STATUS_LIST_NO_EXPIRY', 'Status list has no validUntil; freshness cannot be enforced');
  const ttl = c.credentialSubject?.ttl;
  if (ttl !== undefined && !(Number.isSafeInteger(ttl) && ttl > 0)) fail('STATUS_VERIFICATION_ERROR', 'Status list ttl is malformed');
  if (ttl !== undefined && checkTime(now, 'now') >= Date.parse(c.validFrom) + ttl) fail('STATUS_LIST_EXPIRED', 'Status list ttl has elapsed; refetch a fresh list');
  if (!c.type?.includes?.('BitstringStatusListCredential') || c.credentialSubject?.type !== 'BitstringStatusList') fail('STATUS_VERIFICATION_ERROR', 'Not a BitstringStatusListCredential');
  const url = expectedUrl ?? entry.statusListCredential;
  if (c.id !== url) fail('STATUS_VERIFICATION_ERROR', 'Status list credential id differs from the entry statusListCredential URL');
  const purposes = [].concat(c.credentialSubject.statusPurpose);
  if (!purposes.includes(entry.statusPurpose)) fail('STATUS_VERIFICATION_ERROR', 'Entry purpose is not provided by this status list');
  const bits = wrap(() => decodeList(c.credentialSubject.encodedList, { maxBytes: maxDecodedBytes }));
  if (bits.length * 8 < minimumEntries) fail('STATUS_LIST_LENGTH_ERROR', `Status list has ${bits.length * 8} entries; at least ${minimumEntries} required`);
  if (index >= bits.length * 8) fail('RANGE_ERROR', 'Status list index is outside the list');
  const set = getBit(bits, index) === 1;
  return { purpose: entry.statusPurpose, index, set, valid: !set, entries: bits.length * 8, listIssuer: opened.issuer };
}

/**
 * Deterministic, keyed index assignment. The index for (purpose, credential report digest) is
 * HMAC-SHA256(secret, domain | purpose | reportDigest | counter) mod size, probing the counter upward past
 * indices already held by an earlier ledger entry. Earlier entries never move; the issuer keeps the ledger.
 * Without the secret a list reader cannot map an index to a subject, and the subject digest is not an input.
 */
export function allocateStatusIndices({ secret, reportDigest, ledger, size = MIN_STATUS_ENTRIES }) {
  if (!((typeof secret === 'string' && secret.length >= 32) || (secret instanceof Uint8Array && secret.length >= 32))) fail('STATUS_INDEX_INVALID', 'secret must be at least 32 bytes or characters');
  hash(reportDigest, 'Report digest');
  const existing = ledger.find(e => e.reportDigest === reportDigest);
  if (existing) return { ...existing.indices };
  const out = {};
  for (const purpose of STATUS_PURPOSES) {
    const taken = new Set(ledger.map(e => e.indices?.[purpose]));
    if (taken.size >= size) fail('STATUS_INDEX_INVALID', `Status list is full for ${purpose}`);
    for (let counter = 0; ; counter++) {
      const h = createHmac('sha256', secret).update(`kya.vc.status-index/v1\n${purpose}\n${reportDigest}\n${counter}`).digest();
      const idx = Number(h.readBigUInt64BE(0) % BigInt(size));
      if (!taken.has(idx)) { out[purpose] = idx; break; }
    }
  }
  return out;
}

/** KYA revocation to status bits: a credential is revoked when its subject digest or any evidence ID it selected is revoked by policy. */
export function revokedLedgerEntries(ledger, policy) {
  // A missing or junk policy must never read as "nothing is revoked".
  const { revokedSubjectDigests, revokedEvidenceIds } = validatePolicy(policy);
  if (!Array.isArray(ledger) || !ledger.every(e => e && typeof e === 'object' && /^[a-f0-9]{64}$/.test(e.reportDigest) && /^[a-f0-9]{64}$/.test(e.subjectDigest) && Array.isArray(e.evidenceIds) && e.indices && Number.isSafeInteger(e.indices.revocation) && Number.isSafeInteger(e.indices.suspension))) fail('STATUS_INDEX_INVALID', 'Malformed ledger');
  const subjects = new Set(revokedSubjectDigests), evidence = new Set(revokedEvidenceIds);
  return ledger.filter(e => subjects.has(e.subjectDigest) || e.evidenceIds.some(x => evidence.has(x)));
}
