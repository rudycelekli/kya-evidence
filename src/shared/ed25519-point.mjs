import { insist } from './canonical.mjs';

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
