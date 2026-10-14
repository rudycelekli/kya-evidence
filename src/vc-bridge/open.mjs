import { timestamp, keyId } from '../identity/domain/services/validation.mjs';
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
  if (expectedIssuerKeys.length) {
    if (!expectedIssuerKeys.map(toDid).includes(issuer)) fail('ISSUER_NOT_EXPECTED', 'Issuer is not among the expected issuer keys');
    issuerTrust = 'expected';
  }
  return { credential, issuer, kid: parsed.header.kid, issuerTrust };
}

/** Policy-relative trust: the issuer key must be a trust anchor of the supplied KYA policy and not revoked. */
export function anchorRole(issuer, policy) {
  const id = keyId(publicKeyObjectFromRaw(publicKeyFromDidKey(issuer)));
  const anchor = policy?.trustedKeys?.find(k => k.id === id);
  if (!anchor || policy.revokedKeyIds?.includes(id)) return null;
  return anchor.role ?? 'unspecified';
}
