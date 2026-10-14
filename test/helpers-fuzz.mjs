import test from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

// Dependency-free seeded property/fuzz harness. Deterministic by default.
// KYA_FUZZ_SEED=<int[,int...]> replaces the fixed seed list; KYA_FUZZ_RUNS=<int> replaces the
// base run count (default 100). Each property asks for `weight` cases per seed, scaled by RUNS/100.
export const DEFAULT_SEEDS = Object.freeze([0xC0FFEE, 20261014, 7]);
export const BASE_RUNS = (() => { const n = Number(process.env.KYA_FUZZ_RUNS); return Number.isInteger(n) && n > 0 ? n : 100; })();
export const SEEDS = (() => {
  const raw = process.env.KYA_FUZZ_SEED;
  if (!raw) return [...DEFAULT_SEEDS];
  const out = raw.split(',').map(s => Number(s.trim()));
  if (!out.length || out.some(n => !Number.isInteger(n))) throw new Error('KYA_FUZZ_SEED must be integers separated by commas');
  return out;
})();

export function mulberry32(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const rng = {
    next,
    int: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)),
    bool: (p = 0.5) => next() < p,
    pick: arr => arr[Math.floor(next() * arr.length)],
    shuffle(arr) { const a2 = [...arr]; for (let i = a2.length - 1; i > 0; i--) { const j = Math.floor(next() * (i + 1)); [a2[i], a2[j]] = [a2[j], a2[i]]; } return a2; },
    sample(arr, n) { return rng.shuffle(arr).slice(0, n); },
  };
  return rng;
}

/** Register one node:test test that runs `fn(rng, caseIndex)` for every seed. Failures name seed and case. */
export function property(title, weight, fn) {
  test(title, () => {
    const cases = Math.max(1, Math.round(weight * BASE_RUNS / 100));
    for (const seed of SEEDS) {
      const rng = mulberry32(seed);
      for (let i = 0; i < cases; i++) {
        try { fn(rng, i); }
        catch (error) {
          error.message = `[KYA_FUZZ_SEED=${seed} case=${i} of ${cases}] ${error.message}`;
          throw error;
        }
      }
    }
  });
  return { cases: weight };
}

export const keyPool = Array.from({ length: 6 }, () => {
  const pair = generateKeyPairSync('ed25519');
  return { ...pair, pem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString() };
});

export const hex = (rng, n = 64) => Array.from({ length: n }, () => '0123456789abcdef'[rng.int(0, 15)]).join('');
const ID_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const ID_REST = ID_CHARS + ':._/-';
export const randomId = (rng, max = 40) => ID_CHARS[rng.int(0, ID_CHARS.length - 1)] + Array.from({ length: rng.int(0, max - 1) }, () => ID_REST[rng.int(0, ID_REST.length - 1)]).join('');

// Strings with unicode and escape edge cases. Lone surrogates only when asked for.
const SPECIALS = [0x0, 0x1f, 0x7f, 0x80, 0x2028, 0x2029, 0xfeff, 0xe9, 0x4e2d, 0x1f600, 0x10ffff, 0x22, 0x5c, 0x2f, 0xa, 0x9, 0x8, 0xc, 0xd, 0x20].map(c => String.fromCodePoint(c)).concat(['e' + String.fromCodePoint(0x301), '</script>', '\\u0041']);
export function randomString(rng, { surrogates = false, max = 12 } = {}) {
  let s = '';
  for (let i = rng.int(0, max); i > 0; i--) {
    const r = rng.next();
    if (r < 0.35) s += SPECIALS[rng.int(0, SPECIALS.length - 1)];
    else if (surrogates && r < 0.4) s += String.fromCharCode(rng.int(0xd800, 0xdfff));
    else s += ID_CHARS[rng.int(0, ID_CHARS.length - 1)];
  }
  return s;
}

const FORBIDDEN = new Set(['__proto__', 'prototype', 'constructor']);
export function randomKey(rng, opts) { let k; do { k = randomString(rng, { ...opts, max: 8 }); } while (FORBIDDEN.has(k)); return k; }
export function randomNumber(rng) {
  const r = rng.next();
  if (r < 0.3) return rng.int(-1000, 1000);
  if (r < 0.4) return rng.pick([0, -0, 1, -1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.1, 1e-7, 1.5e300, 5e-324, 123456789.125, 1e20, -1e20]);
  if (r < 0.7) return (rng.next() - 0.5) * 10 ** rng.int(-10, 15);
  return rng.int(-(2 ** 31), 2 ** 31);
}
export function randomJson(rng, depth = 0, opts = {}) {
  const r = rng.next();
  if (depth >= 5 || r < 0.35) {
    const leaf = rng.int(0, 4);
    return leaf === 0 ? null : leaf === 1 ? rng.bool() : leaf === 2 ? safeNumber(rng) : randomString(rng, opts);
  }
  if (r < 0.65) return Array.from({ length: rng.int(0, 5) }, () => randomJson(rng, depth + 1, opts));
  const o = {};
  for (let i = rng.int(0, 5); i > 0; i--) o[randomKey(rng, opts)] = randomJson(rng, depth + 1, opts);
  return o;
}

/** Rebuild the same JSON value with a different key insertion order at every level. */
export function reorderKeys(rng, v) {
  if (Array.isArray(v)) return v.map(x => reorderKeys(rng, x));
  if (v && typeof v === 'object') { const o = {}; for (const k of rng.shuffle(Object.keys(v))) o[k] = reorderKeys(rng, v[k]); return o; }
  return v;
}

export const clone = v => structuredClone(v);
/** A number canonical() must accept: finite, and integers only inside the safe range. */
export function safeNumber(rng) {
  const n = randomNumber(rng);
  return Number.isFinite(n) && (!Number.isInteger(n) || Number.isSafeInteger(n)) ? n : rng.int(-1000, 1000) + 0.5;
}

// Optional coverage statistics: KYA_FUZZ_STATS=1 prints how often interesting branches were reached.
const counters = new Map();
export function stat(name) { counters.set(name, (counters.get(name) ?? 0) + 1); }
if (process.env.KYA_FUZZ_STATS) process.on('exit', () => { for (const [k, v] of [...counters].sort()) console.error(`KYA_FUZZ_STAT ${k}: ${v}`); });
