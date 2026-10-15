import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonical, insist } from '../shared/canonical.mjs';

// Salted per-field commitments (reference helper, design in docs/PRIVACY.md).
// commitment = HMAC-SHA-256(key = salt, message = domain label + length-prefixed recordId, field, canonical(value)).
// Hiding needs a secret high-entropy salt held by the data subject or issuer; binding rests on SHA-256 collision resistance.
// This is not zero-knowledge, not unlinkable (the same commitment reveals equality) and has had no independent review.
export const FIELD_COMMITMENT_SCHEMA = 'kya.field-commitment/v1';
export const FIELD_COMMITMENT_DOMAIN = 'kya.privacy.field-commitment/v1';
const COMMITMENT_ALGORITHM = 'HMAC-SHA-256';
const MIN_SALT_BYTES = 16;
const HEX = /^[a-f0-9]+$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;

function lp(text) {
  const b = Buffer.from(text, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, b]);
}
function mac(saltHex, recordId, field, value) {
  return createHmac('sha256', Buffer.from(saltHex, 'hex'))
    .update(Buffer.concat([lp(FIELD_COMMITMENT_DOMAIN), lp(recordId), lp(field), lp(canonical(value))]))
    .digest('hex');
}
function checkSalt(salt) {
  insist(typeof salt === 'string' && HEX.test(salt) && salt.length % 2 === 0 && salt.length >= MIN_SALT_BYTES * 2 && salt.length <= 128, 'Salt must be lowercase hex of 16 to 64 bytes');
}

// Returns {commitment, opening}. Publish only `commitment`; keep `opening` private and reveal it to open one field.
export function commitField({ recordId, field, value, salt } = {}) {
  insist(typeof recordId === 'string' && NAME.test(recordId), 'recordId must be a coded identifier');
  insist(typeof field === 'string' && NAME.test(field), 'field must be a coded identifier');
  const s = salt === undefined ? randomBytes(32).toString('hex') : salt;
  checkSalt(s);
  const digest = mac(s, recordId, field, value);
  return { commitment: { schema: FIELD_COMMITMENT_SCHEMA, recordId, field, algorithm: COMMITMENT_ALGORITHM, digest }, opening: { salt: s, value } };
}

// Returns {ok:true} or {ok:false, reason}. Never throws on a malformed commitment or opening.
export function openField(commitment, opening) {
  try {
    insist(commitment && typeof commitment === 'object' && commitment.schema === FIELD_COMMITMENT_SCHEMA && Object.is(commitment.algorithm, COMMITMENT_ALGORITHM), 'unsupported commitment');
    insist(typeof commitment.digest === 'string' && /^[a-f0-9]{64}$/.test(commitment.digest), 'malformed digest');
    insist(opening && typeof opening === 'object', 'missing opening');
    insist(typeof commitment.recordId === 'string' && NAME.test(commitment.recordId) && typeof commitment.field === 'string' && NAME.test(commitment.field), 'malformed binding');
    checkSalt(opening.salt);
    const expected = Buffer.from(mac(opening.salt, commitment.recordId, commitment.field, opening.value), 'hex');
    return timingSafeEqual(expected, Buffer.from(commitment.digest, 'hex')) ? { ok: true } : { ok: false, reason: 'opening does not match commitment' };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}
