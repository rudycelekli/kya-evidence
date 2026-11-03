import { timestamp, keyId, hash, list, validatePublicPem } from '../identity/domain/services/validation.mjs';
import { canonical, captureArrayItems, exactKeys, insist } from '../shared/canonical.mjs';
import { didKeyFromPublicKey, publicKeyFromDidKey, publicKeyObjectFromRaw } from './encoding.mjs';
import { fail, parseCompact, verifyParsed } from './jws.mjs';

export const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

const toDid = k => (typeof k === 'string' && k.startsWith('did:key:')) ? k : didKeyFromPublicKey(k);

export function checkTime(value, label) {
  try { return timestamp(value, label); } catch (e) { return fail('TIME_INVALID', e.message); }
}

/**
 * Verify a vc+jwt compact token and return the unsecured credential. Signature validity proves key
 * possession only. Throws VcBridgeError with a stable code.
 */
export function openCredential(token, { now, expectedIssuerKeys = [] } = {}) {
  const at = checkTime(now, 'now');
  let expected;
  try { expected = captureArrayItems(expectedIssuerKeys, 256, 'Expected issuer keys'); }
  catch (e) { fail('ISSUER_KEYS_INVALID', e.message); }
  const parsed = parseCompact(token);
  const credential = parsed.payload;
  if (Object.hasOwn(credential, 'vc') || Object.hasOwn(credential, 'vp')) fail('PAYLOAD_INVALID', 'vc and vp claims must not be present; the payload is the credential');
  const issuer = typeof credential.issuer === 'string' ? credential.issuer : credential.issuer?.id;
  if (typeof issuer !== 'string') fail('PAYLOAD_INVALID', 'issuer is required');
  verifyParsed(parsed, issuer);
  if (!Array.isArray(credential['@context']) || credential['@context'][0] !== VC_CONTEXT) fail('PAYLOAD_INVALID', `@context must start with ${VC_CONTEXT}`);
  if (!Array.isArray(credential.type) || !credential.type.includes('VerifiableCredential')) fail('PAYLOAD_INVALID', 'type must include VerifiableCredential');
  if (Object.hasOwn(credential, 'iss') && credential.iss !== issuer) fail('PAYLOAD_INVALID', 'iss conflicts with issuer');
  if (!credential.credentialSubject || typeof credential.credentialSubject !== 'object' || Array.isArray(credential.credentialSubject)) fail('PAYLOAD_INVALID', 'credentialSubject must be one object');
  const from = checkTime(credential.validFrom, 'validFrom');
  const until = credential.validUntil === undefined ? Infinity : checkTime(credential.validUntil, 'validUntil');
  if (until <= from) fail('PAYLOAD_INVALID', 'validUntil must follow validFrom');
  if (at < from) fail('NOT_YET_VALID', 'Credential is not yet valid at the supplied time');
  if (at >= until) fail('EXPIRED', 'Credential validity window has ended at the supplied time');
  if (Object.hasOwn(credential, 'exp') && !(typeof credential.exp === 'number' && at < credential.exp * 1000)) fail('EXPIRED', 'JWT exp has passed');
  if (Object.hasOwn(credential, 'nbf') && !(typeof credential.nbf === 'number' && at >= credential.nbf * 1000)) fail('NOT_YET_VALID', 'JWT nbf is in the future');
  let issuerTrust = 'unchecked';
  if (expected.length) {
    if (!expected.map(toDid).includes(issuer)) fail('ISSUER_NOT_EXPECTED', 'Issuer is not among the expected issuer keys');
    issuerTrust = 'expected';
  }
  return { credential, issuer, kid: parsed.header.kid, issuerTrust };
}

/** Capture only the trust fields consumed here; full KYA policies and partial trust projections both remain supported. */
function capturePolicyTrust(policy) {
  insist(policy && typeof policy === 'object' && !Array.isArray(policy), 'Policy trust projection must be an object');
  const descriptors = Object.getOwnPropertyDescriptors(policy);
  for (const name of ['trustedKeys', 'revokedKeyIds']) {
    const descriptor = Object.hasOwn(descriptors, name) ? descriptors[name] : null;
    insist(descriptor && 'value' in descriptor && descriptor.enumerable, `Policy ${name} must be an own enumerable data member`);
  }
  const raw = { trustedKeys: descriptors.trustedKeys.value, revokedKeyIds: descriptors.revokedKeyIds.value };
  const projection = JSON.parse(canonical(raw));
  insist(Array.isArray(projection.trustedKeys) && projection.trustedKeys.length <= 256, 'Invalid trust anchors');
  list(projection.revokedKeyIds, 'Revoked keys', 4096, hash);
  const ids = new Set();
  for (const anchor of projection.trustedKeys) {
    exactKeys(anchor, ['id', 'publicKey', 'role'], 'Trust anchor');
    hash(anchor.id, 'Key ID'); validatePublicPem(anchor.publicKey);
    insist(keyId(anchor.publicKey) === anchor.id, 'Trust anchor fingerprint differs');
    insist(['self', 'independent', 'capture-issuer'].includes(anchor.role), 'Unknown issuer role');
    insist(!ids.has(anchor.id), 'Duplicate trust anchor'); ids.add(anchor.id);
  }
  return projection;
}

/** Policy-relative trust: the issuer key must be a validated trust anchor of the captured projection and not revoked. */
export function anchorRole(issuer, policy) {
  const projection = capturePolicyTrust(policy);
  const id = keyId(publicKeyObjectFromRaw(publicKeyFromDidKey(issuer)));
  const anchor = projection.trustedKeys.find(k => k.id === id);
  if (!anchor || projection.revokedKeyIds.includes(id)) return null;
  return anchor.role;
}
