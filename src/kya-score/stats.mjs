import { createHash } from 'node:crypto';
import { insist } from '../shared/canonical.mjs';

// Deterministic statistics for the KYA Score profile (ADR-0033). Integer-first so that a verifier on another
// machine recomputes identical bytes. Nothing here reads a clock, an environment variable or the network.

/** Seeded generator. Returns next(bound): an unbiased integer in [0, bound) from a 128-bit sfc32 state keyed by SHA-256(seed). */
export function seededRandom(seed) {
  insist(typeof seed === 'string' && seed.length > 0 && seed.length <= 256, 'Invalid seed');
  const h = createHash('sha256').update('kya.score.seed/v1\n').update(seed, 'utf8').digest();
  let a = h.readUInt32BE(0), b = h.readUInt32BE(4), c = h.readUInt32BE(8), d = h.readUInt32BE(12);
  const u32 = () => {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    let t = (a + b) | 0;
    a = b ^ (b >>> 9);
    b = (c + (c << 3)) | 0;
    c = (c << 21) | (c >>> 11);
    d = (d + 1) | 0;
    t = (t + d) | 0;
    c = (c + t) | 0;
    return t >>> 0;
  };
  for (let i = 0; i < 12; i++) u32();
  return bound => {
    insist(Number.isSafeInteger(bound) && bound >= 1 && bound <= 0x100000000, 'Invalid bound');
    const limit = Math.floor(0x100000000 / bound) * bound;
    let x = u32();
    while (x >= limit) x = u32();
    return x % bound;
  };
}

export const MIN_RESAMPLES = 100;
export const MAX_RESAMPLES = 20000;

/**
 * Percentile bootstrap over the sum of a numeric sample, 95 percent two-sided (2.5 and 97.5 percent order statistics).
 * Returns sums so callers holding integers keep exact integer arithmetic. The unit resampled is the item, not the repeat.
 */
export function bootstrapSumQuantiles(data, { seed, resamples } = {}) {
  insist(Array.isArray(data) && data.length > 0, 'Bootstrap data is empty');
  insist(data.every(x => typeof x === 'number' && Number.isFinite(x)), 'Bootstrap data must be finite numbers');
  insist(Number.isSafeInteger(resamples) && resamples >= MIN_RESAMPLES && resamples <= MAX_RESAMPLES, 'Invalid resamples count');
  const next = seededRandom(seed), n = data.length, sums = new Array(resamples);
  for (let r = 0; r < resamples; r++) {
    let s = 0;
    for (let i = 0; i < n; i++) s += data[next(n)];
    sums[r] = s;
  }
  sums.sort((x, y) => x - y);
  const lowIndex = Math.floor(resamples * 25 / 1000);
  return { n, resamples, estimateSum: data.reduce((x, y) => x + y, 0), lowSum: sums[lowIndex], highSum: sums[resamples - 1 - lowIndex] };
}

/** Bootstrap interval for a mean. estimate is the sample mean; low and high are the 2.5 and 97.5 percent resample means. */
export function bootstrapInterval(data, options) {
  const q = bootstrapSumQuantiles(data, options);
  return { n: q.n, resamples: q.resamples, estimate: q.estimateSum / q.n, low: q.lowSum / q.n, high: q.highSum / q.n };
}

/** Wilson score interval, 95 percent (z = 1.96), for k successes in n trials. Same statistic as ADR-0019. */
export function wilsonInterval(k, n) {
  insist(Number.isSafeInteger(k) && Number.isSafeInteger(n) && n >= 1 && k >= 0 && k <= n, 'Invalid count for interval');
  const z = 1.96, p = k / n, z2 = z * z;
  const centre = p + z2 / (2 * n), spread = (z / (2 * n)) * Math.sqrt(4 * n * p * (1 - p) + z2), denom = 1 + z2 / n;
  return { n, k, estimate: p, low: Math.max(0, (centre - spread) / denom), high: Math.min(1, (centre + spread) / denom) };
}
