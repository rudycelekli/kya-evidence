// A GZIP encoder whose output is a pure function of the input bytes. node:zlib is a build of zlib whose
// matcher, hashing (CRC32 or multiplicative, SIMD or scalar) and header OS byte depend on the platform, so
// two machines may emit different valid streams for the same input. This encoder uses one fixed header
// (mtime 0, XFL 0, OS 255), a greedy LZ77 matcher with fixed parameters, and a single fixed-Huffman block
// (RFC 1951 section 3.2.6). Nothing here reads the platform, the clock, locale or zlib.
const WINDOW = 32768, MIN_MATCH = 3, MAX_MATCH = 258, MAX_CHAIN = 64, FAR_LIMIT = 4096, HASH_BITS = 15;

const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_TABLE[n] = c >>> 0; }
export function crc32(bytes) { let c = 0xffffffff; for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

const LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const LEN_CODE = new Uint8Array(MAX_MATCH + 1); for (let c = 0; c < 29; c++) for (let l = LEN_BASE[c]; l <= (c === 28 ? 258 : LEN_BASE[c + 1] - 1); l++) LEN_CODE[l] = c;
const distCode = d => { let c = 29; while (DIST_BASE[c] > d) c--; return c; };

class BitWriter {
  constructor(size) { this.out = new Uint8Array(size); this.pos = 0; this.acc = 0; this.n = 0; }
  bits(value, count) { this.acc |= value << this.n; this.n += count; while (this.n >= 8) { this.out[this.pos++] = this.acc & 0xff; this.acc >>>= 8; this.n -= 8; } }
  // Huffman codes are packed most significant bit first.
  code(value, count) { let r = 0; for (let i = 0; i < count; i++) r |= ((value >>> i) & 1) << (count - 1 - i); this.bits(r, count); }
  flush() { if (this.n > 0) { this.out[this.pos++] = this.acc & 0xff; this.acc = 0; this.n = 0; } }
}
function literalLength(w, sym) {
  if (sym < 144) w.code(0x30 + sym, 8); else if (sym < 256) w.code(0x190 + sym - 144, 9);
  else if (sym < 280) w.code(sym - 256, 7); else w.code(0xc0 + sym - 280, 8);
}

export function gzipDeterministic(input) {
  const data = input instanceof Uint8Array ? input : Uint8Array.from(input), n = data.length;
  // worst case: every byte a 9 bit literal, plus 3 header bits and a 7 bit end of block
  const w = new BitWriter(Math.ceil(n * 9 / 8) + 64);
  w.bits(1, 1); w.bits(1, 2); // BFINAL = 1, BTYPE = 01 (fixed Huffman)
  const head = new Int32Array(1 << HASH_BITS).fill(-1), prev = new Int32Array(Math.max(n, 1)).fill(-1);
  const hashAt = i => ((data[i] << 10) ^ (data[i + 1] << 5) ^ data[i + 2]) & ((1 << HASH_BITS) - 1);
  const insert = i => { if (i + MIN_MATCH <= n) { const h = hashAt(i); prev[i] = head[h]; head[h] = i; } };
  let i = 0;
  while (i < n) {
    let bestLen = 0, bestDist = 0;
    if (i + MIN_MATCH <= n) {
      const limit = Math.min(MAX_MATCH, n - i);
      let cand = head[hashAt(i)], chain = MAX_CHAIN;
      while (cand >= 0 && i - cand <= WINDOW && chain-- > 0) {
        let l = 0; while (l < limit && data[cand + l] === data[i + l]) l++;
        if (l > bestLen) { bestLen = l; bestDist = i - cand; if (l === limit) break; }
        cand = prev[cand];
      }
      if (bestLen < MIN_MATCH || (bestLen === MIN_MATCH && bestDist > FAR_LIMIT)) bestLen = 0;
    }
    if (bestLen === 0) { literalLength(w, data[i]); insert(i); i++; continue; }
    const lc = LEN_CODE[bestLen]; literalLength(w, 257 + lc); if (LEN_EXTRA[lc]) w.bits(bestLen - LEN_BASE[lc], LEN_EXTRA[lc]);
    const dc = distCode(bestDist); w.code(dc, 5); if (DIST_EXTRA[dc]) w.bits(bestDist - DIST_BASE[dc], DIST_EXTRA[dc]);
    for (let k = 0; k < bestLen; k++) insert(i + k);
    i += bestLen;
  }
  literalLength(w, 256); w.flush();
  const body = w.out.subarray(0, w.pos), out = new Uint8Array(10 + body.length + 8);
  out.set([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]); out.set(body, 10);
  const dv = new DataView(out.buffer); dv.setUint32(10 + body.length, crc32(data), true); dv.setUint32(14 + body.length, n >>> 0, true);
  return Buffer.from(out.buffer, out.byteOffset, out.length);
}
