import { createPrivateKey, createPublicKey, sign, verify, KeyObject } from 'node:crypto';
import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { identifier, hash, timestamp, keyId, publicKeyObject, validatePublicPem } from '../identity/domain/services/validation.mjs';

export const DISCLOSURE_SCHEMA = 'kya.assessor-disclosure/v1';
export const DISCLOSURE_DOMAIN = 'kya.assessor-disclosure/v1\n';
export const DISCLOSURE_KINDS = Object.freeze(['disclosure', 'conflict-declaration', 'withdrawal']);
export const RELATIONSHIPS = Object.freeze(['none', 'financial', 'control', 'authorship', 'employment', 'prior-engagement', 'tooling-dependency']);
export const MAX_RELATIONSHIPS = 8;
export const MAX_VALIDITY_DAYS = 366;
export const MAX_RECORD_BYTES = 4096;
const DAY = 86_400_000;

// Disclosure records carry coded fields and digests only: no names, no narrative. Details stay private, referenced by digest.
export function validateDisclosure(v) {
  v = JSON.parse(canonical(v));
  insist(Buffer.byteLength(canonical(v), 'utf8') <= MAX_RECORD_BYTES, 'Disclosure too large');
  exactKeys(v, ['schema', 'id', 'kind', 'assessorKeyId', 'operatorDigest', 'relationships', 'priorEngagementEndedAt', 'refId', 'refDigest', 'issuedAt', 'expiresAt', 'detailsDigest'], 'Disclosure');
  insist(v.schema === DISCLOSURE_SCHEMA, 'Unsupported disclosure schema'); identifier(v.id, 'Disclosure ID');
  insist(DISCLOSURE_KINDS.includes(v.kind), 'Unknown disclosure kind');
  hash(v.assessorKeyId, 'Assessor key'); hash(v.operatorDigest, 'Operator digest'); hash(v.detailsDigest, 'Details digest');
  insist(Array.isArray(v.relationships) && v.relationships.length <= MAX_RELATIONSHIPS, 'Invalid relationship list');
  insist(v.relationships.every(r => RELATIONSHIPS.includes(r)) && new Set(v.relationships).size === v.relationships.length, 'Unknown or duplicate relationship');
  insist(v.relationships.every((r, i, a) => i === 0 || a[i - 1] < r), 'Relationships must be sorted');
  if (v.relationships.includes('none')) insist(v.relationships.length === 1, 'none cannot combine with other relationships');
  const issued = timestamp(v.issuedAt, 'Issue time'), expires = timestamp(v.expiresAt, 'Expiry time');
  insist(expires > issued && expires - issued <= MAX_VALIDITY_DAYS * DAY, 'Invalid validity window');
  if (v.priorEngagementEndedAt !== null) timestamp(v.priorEngagementEndedAt, 'Prior engagement end');
  insist((v.priorEngagementEndedAt !== null) === v.relationships.includes('prior-engagement'), 'prior-engagement requires an end time and nothing else may carry one');
  if (v.kind === 'disclosure') { insist(v.relationships.length > 0, 'A disclosure must list relationships or none'); insist(v.refId === null && v.refDigest === null, 'A disclosure cannot reference a record'); }
  else if (v.kind === 'conflict-declaration') { insist(v.relationships.length > 0 && !v.relationships.includes('none'), 'A conflict declaration must name a relationship'); insist(v.refId === null && v.refDigest === null, 'A declaration cannot reference a record'); }
  else { insist(v.relationships.length === 0 && v.priorEngagementEndedAt === null, 'A withdrawal carries no relationships'); identifier(v.refId, 'Withdrawn record'); hash(v.refDigest, 'Withdrawn envelope digest'); insist(v.refId !== v.id, 'A record cannot withdraw itself'); }
  return v;
}

export function signDisclosure(payload, privateKey) {
  payload = validateDisclosure(payload);
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  insist(key.type === 'private' && key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 private key');
  const publicKey = createPublicKey(key).export({ format: 'pem', type: 'spki' }).toString();
  const signature = sign(null, Buffer.from(DISCLOSURE_DOMAIN + canonical(payload)), key).toString('base64url');
  return { payload, proof: { algorithm: 'Ed25519', keyId: keyId(publicKey), publicKey, signature } };
}

export function verifyDisclosure(envelope) {
  envelope = JSON.parse(canonical(envelope)); exactKeys(envelope, ['payload', 'proof'], 'Disclosure envelope');
  const payload = validateDisclosure(envelope.payload);
  const p = envelope.proof; exactKeys(p, ['algorithm', 'keyId', 'publicKey', 'signature'], 'Disclosure proof');
  insist(p.algorithm === 'Ed25519', 'Unsupported proof algorithm'); hash(p.keyId, 'Proof key'); validatePublicPem(p.publicKey);
  insist(keyId(p.publicKey) === p.keyId, 'Proof key fingerprint differs');
  insist(typeof p.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(p.signature), 'Invalid signature encoding');
  const bytes = Buffer.from(p.signature, 'base64url'); insist(bytes.length === 64 && bytes.toString('base64url') === p.signature, 'Noncanonical signature encoding');
  insist(verify(null, Buffer.from(DISCLOSURE_DOMAIN + canonical(payload)), publicKeyObject(p.publicKey), bytes), 'Disclosure signature verification failed');
  return { payload, keyId: p.keyId, envelopeDigest: digest(envelope) };
}
