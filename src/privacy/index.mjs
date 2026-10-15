import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonical, insist } from '../shared/canonical.mjs';

// Salted per-field commitments (reference helper, design in docs/PRIVACY.md).
// commitment = HMAC-SHA-256(key = salt, message = domain label + length-prefixed recordId, field, canonical(value)).
// Hiding needs a secret high-entropy salt held by the data subject or issuer; binding rests on SHA-256 collision resistance.
// Salts are exactly 32 bytes and per field. A caller who wants reproducible commitments passes a 32 byte masterSalt; each
// field salt is HMAC-SHA-256(masterSalt, label || recordId || field), so opening one field never reveals the master or
// another field salt. A field salt is never shared between fields: reuse would let one opened field brute-force the others.
// This is not zero-knowledge, not unlinkable (the same commitment reveals equality) and has had no independent review.
export const FIELD_COMMITMENT_SCHEMA = 'kya.field-commitment/v1';
export const FIELD_COMMITMENT_DOMAIN = 'kya.privacy.field-commitment/v1';
const COMMITMENT_ALGORITHM = 'HMAC-SHA-256';
const SALT_BYTES = 32;
const MIN_DISTINCT_BYTES = 8;
const FIELD_SALT_DOMAIN = 'kya.privacy.field-salt/v1';
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
function checkSalt(salt, what = 'Salt') {
  insist(typeof salt === 'string' && /^[a-f0-9]{64}$/.test(salt), what + ' must be lowercase hex of exactly 32 bytes');
  insist(new Set(Buffer.from(salt, 'hex')).size >= MIN_DISTINCT_BYTES, what + ' is not random enough (constant or repeating bytes)');
}
function fieldSalt(masterSalt, recordId, field) {
  return createHmac('sha256', Buffer.from(masterSalt, 'hex')).update(Buffer.concat([lp(FIELD_SALT_DOMAIN), lp(recordId), lp(field)])).digest('hex');
}

// Returns {commitment, opening}. Publish only `commitment`; keep `opening` private and reveal it to open one field.
// Optional masterSalt (32 random bytes) makes the result reproducible; the public salt parameter was removed.
export function commitField(args) {
  insist(args !== null && typeof args === 'object' && !Array.isArray(args), 'commitField needs an object with recordId, field and value');
  const { recordId, field, value, masterSalt } = args;
  insist(!('salt' in args), 'Salt parameter removed: pass masterSalt, which derives a distinct salt per field');
  insist(typeof recordId === 'string' && NAME.test(recordId), 'recordId must be a coded identifier');
  insist(typeof field === 'string' && NAME.test(field), 'field must be a coded identifier');
  let s;
  if (masterSalt === undefined) s = randomBytes(SALT_BYTES).toString('hex');
  else { checkSalt(masterSalt, 'Salt (masterSalt)'); s = fieldSalt(masterSalt, recordId, field); }
  const digest = mac(s, recordId, field, value);
  return { commitment: { schema: FIELD_COMMITMENT_SCHEMA, recordId, field, algorithm: COMMITMENT_ALGORITHM, digest }, opening: { salt: s, value } };
}

// openField checks only that the opening is self-consistent with the commitment it is given. A verifier must itself compare
// commitment.recordId, commitment.field and commitment.digest against the signed record it relied on, and the expected value.
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
