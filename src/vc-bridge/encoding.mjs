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

// Ed25519 point validation (RFC 8032 section 5.1.3 decoding plus a cofactor check), computed here with
// BigInt rather than from a remembered list of bad points: curve -x^2 + y^2 = 1 + d x^2 y^2 over p = 2^255 - 19.
const P = (1n << 255n) - 19n;
const mod = a => ((a % P) + P) % P;
const pow = (b, e) => { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = mod(r * b); b = mod(b * b); e >>= 1n; } return r; };
const inv = a => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

function addPoints([x1, y1], [x2, y2]) {
  const t = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + x2 * y1) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
}

/** Reject non-canonical encodings, points off the curve and small-order points (8P is the identity). */
export function assertValidEd25519Point(raw) {
  insist(raw instanceof Uint8Array && raw.length === 32, 'Expected a 32-byte Ed25519 public key');
  let v = 0n; for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(raw[i]);
  const sign = v >> 255n, y = v & ((1n << 255n) - 1n);
  insist(y < P, 'Invalid Ed25519 public key: non-canonical y coordinate');
  const u = mod(y * y - 1n), w = mod(D * y * y + 1n);
  let x = mod(u * pow(w, 3n) * pow(u * pow(w, 7n), (P - 5n) / 8n));
  if (mod(w * x * x) !== u) x = mod(x * SQRT_M1);
  insist(mod(w * x * x) === u, 'Invalid Ed25519 public key: point is not on the curve');
  insist(!(x === 0n && sign === 1n), 'Invalid Ed25519 public key: non-canonical x sign');
  if ((x & 1n) !== sign) x = mod(-x);
  let q = [x, y];
  for (let i = 0; i < 3; i++) q = addPoints(q, q);
  insist(!(q[0] === 0n && q[1] === 1n), 'Invalid Ed25519 public key: small-order point');
}

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
