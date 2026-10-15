import { createPublicKey, KeyObject } from 'node:crypto';
import { insist } from '../shared/canonical.mjs';

/** Strict unpadded base64url: refuses padding, wrong alphabet and non-canonical trailing bits. */
export const b64u = Object.freeze({
  encode(bytes) { return Buffer.from(bytes).toString('base64url'); },
  decode(text) {
    insist(typeof text === 'string' && /^[A-Za-z0-9_-]*$/.test(text), 'Invalid base64url encoding');
    const bytes = Buffer.from(text, 'base64url');
    insist(bytes.toString('base64url') === text, 'Invalid base64url encoding: non-canonical');
    return bytes;
  }
});

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Bitcoin-alphabet base58 (multibase prefix z). Leading zero bytes map to leading 1 characters. */
export function base58btcEncode(bytes) {
  const input = Uint8Array.from(bytes);
  let zeros = 0; while (zeros < input.length && input[zeros] === 0) zeros++;
  let n = 0n; for (const b of input) n = (n << 8n) | BigInt(b);
  let out = ''; while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  return '1'.repeat(zeros) + out;
}

export function base58btcDecode(text) {
  insist(typeof text === 'string' && text.length > 0 && text.length <= 512, 'Invalid base58btc text');
  let zeros = 0; while (zeros < text.length && text[zeros] === '1') zeros++;
  let n = 0n;
  for (const ch of text) { const i = ALPHABET.indexOf(ch); insist(i >= 0, 'Invalid base58btc character'); n = n * 58n + BigInt(i); }
  const hex = n === 0n ? '' : n.toString(16).padStart(Math.ceil(n.toString(16).length / 2) * 2, '0');
  return Uint8Array.from([...new Uint8Array(zeros), ...Buffer.from(hex, 'hex')]);
}

// Multicodec ed25519-pub is code 0xed; as an unsigned varint it is the two bytes 0xed 0x01.
const ED25519_PUB = Uint8Array.from([0xed, 0x01]);

import { assertValidEd25519Point } from '../shared/ed25519-point.mjs';
export { assertValidEd25519Point };

/** Raw 32-byte Ed25519 public key from a KeyObject (or pass raw bytes through). Always validated. */
export function rawEd25519(publicKey) {
  let raw;
  if (publicKey instanceof Uint8Array) raw = Uint8Array.from(publicKey);
  else {
    const obj = publicKey instanceof KeyObject ? publicKey : createPublicKey(publicKey);
    insist(obj.type === 'public' && obj.asymmetricKeyType === 'ed25519', 'Expected Ed25519 public key');
    raw = Uint8Array.from(b64u.decode(obj.export({ format: 'jwk' }).x));
  }
  assertValidEd25519Point(raw);
  return raw;
}

export function didKeyFromPublicKey(publicKey) {
  return 'did:key:z' + base58btcEncode(Uint8Array.from([...ED25519_PUB, ...rawEd25519(publicKey)]));
}

/** Parse a bare did:key (no fragment, no path). Returns the raw 32-byte Ed25519 key. */
export function publicKeyFromDidKey(did) {
  insist(typeof did === 'string' && /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(did), 'Invalid did:key: expected did:key:z followed by base58btc');
  const bytes = base58btcDecode(did.slice('did:key:z'.length));
  insist(bytes[0] === ED25519_PUB[0] && bytes[1] === ED25519_PUB[1], 'Unsupported did:key multicodec: only ed25519-pub (0xed01) is accepted');
  insist(bytes.length === 34, 'Invalid did:key: Ed25519 key must be 32 bytes');
  const raw = bytes.subarray(2);
  insist(didKeyFromPublicKey(raw) === did, 'Invalid did:key: non-canonical encoding');
  return Uint8Array.from(raw);
}

export function publicKeyObjectFromRaw(raw) {
  assertValidEd25519Point(raw);
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64u.encode(raw) }, format: 'jwk' });
}
