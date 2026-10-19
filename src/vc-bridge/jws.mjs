import { createPrivateKey, createPublicKey, sign, verify, KeyObject } from 'node:crypto';
import { canonical, parseJson } from '../shared/canonical.mjs';
import { b64u, didKeyFromPublicKey, publicKeyFromDidKey, publicKeyObjectFromRaw } from './encoding.mjs';

const MAX_TOKEN = 1_048_576;
const ALLOWED_HEADER = new Set(['alg', 'typ', 'cty', 'kid']);

export class VcBridgeError extends Error {
  constructor(code, message) { super(`${code}: ${message}`); this.name = 'VcBridgeError'; this.code = code; }
}
export const fail = (code, message) => { throw new VcBridgeError(code, message); };

export function privateKeyObject(key) {
  const k = key instanceof KeyObject ? key : createPrivateKey(key);
  if (k.type !== 'private' || k.asymmetricKeyType !== 'ed25519') fail('KEY_INVALID', 'Expected an Ed25519 private key');
  return k;
}

/** Sign a JSON payload as a compact JWS (RFC 7515) with alg EdDSA. Serialization is KYA canonical JSON for determinism; it is not RFC 8785. */
export function signCompact(payload, privateKey, { typ = 'vc+jwt', cty = 'vc' } = {}) {
  const key = privateKeyObject(privateKey);
  const did = didKeyFromPublicKey(createPublicKey(key));
  const header = { alg: 'EdDSA', typ, cty, kid: `${did}#${did.slice('did:key:'.length)}` };
  const input = `${b64u.encode(Buffer.from(canonical(header)))}.${b64u.encode(Buffer.from(canonical(payload)))}`;
  return { token: `${input}.${b64u.encode(sign(null, Buffer.from(input), key))}`, issuer: did, kid: header.kid };
}

/** Parse without trusting anything. Throws VcBridgeError with a stable code. */
export function parseCompact(token) {
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN) fail('MALFORMED', 'Token must be a non-empty string within the size limit');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] === '' || parts[1] === '') fail('MALFORMED', 'Compact JWS needs exactly three segments');
  let headerBytes, payloadBytes, signature;
  try { headerBytes = b64u.decode(parts[0]); payloadBytes = b64u.decode(parts[1]); signature = parts[2] === '' ? Buffer.alloc(0) : b64u.decode(parts[2]); }
  catch (e) { fail('MALFORMED', e.message); }
  let header, payload;
  // Ill-formed UTF-8 is refused, never replaced (docs/SPECIFICATION.md, Credential verification). A byte order mark is kept so the strict parser refuses it.
  const utf8 = bytes => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  try { header = parseJson(utf8(headerBytes)); } catch (e) { fail('MALFORMED', 'Header is not strict JSON: ' + e.message); }
  if (!header || typeof header !== 'object' || Array.isArray(header)) fail('MALFORMED', 'Header must be an object');
  // Algorithm is judged before the payload or any key is touched.
  if (header.alg !== 'EdDSA') fail('ALG_NOT_ALLOWED', 'Only alg EdDSA is accepted; none, HMAC and every other algorithm are refused');
  for (const k of Object.keys(header)) if (!ALLOWED_HEADER.has(k)) fail('HEADER_MEMBER_NOT_ALLOWED', `Header member ${k.slice(0, 32)} is not accepted (no embedded keys, URLs or critical extensions)`);
  if (header.typ !== 'vc+jwt' || (Object.hasOwn(header, 'cty') && header.cty !== 'vc')) fail('TYP_NOT_ALLOWED', 'typ must be vc+jwt and cty, if present, vc');
  if (typeof header.kid !== 'string') fail('MALFORMED', 'kid is required');
  try { payload = parseJson(utf8(payloadBytes)); } catch (e) { fail('MALFORMED', 'Payload is not strict JSON: ' + e.message); }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) fail('MALFORMED', 'Payload must be an object');
  return { header, payload, signingInput: Buffer.from(`${parts[0]}.${parts[1]}`), signature };
}

/** Verify the signature against the key named by the issuer did:key. Returns the did and kid. */
export function verifyParsed(parsed, issuerDid) {
  let raw;
  try { raw = publicKeyFromDidKey(issuerDid); } catch (e) { fail('ISSUER_INVALID', e.message); }
  const expectedKid = `${issuerDid}#${issuerDid.slice('did:key:'.length)}`;
  if (parsed.header.kid !== expectedKid) fail('KID_MISMATCH', 'kid does not name the issuer did:key verification method');
  if (parsed.signature.length !== 64) fail('SIGNATURE_INVALID', 'Ed25519 signature must be 64 bytes');
  if (!verify(null, parsed.signingInput, publicKeyObjectFromRaw(raw), parsed.signature)) fail('SIGNATURE_INVALID', 'Signature does not verify under the issuer key');
  return { publicKey: publicKeyObjectFromRaw(raw) };
}
