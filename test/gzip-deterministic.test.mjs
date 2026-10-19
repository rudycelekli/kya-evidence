import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { gzipDeterministic, crc32 } from '../src/shared/gzip-deterministic.mjs';
import { encodeList, decodeList, createBitstring, setBit } from '../src/vc-bridge/status.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');
const xorshift = n => { let s = 0x2545f491; const o = Buffer.alloc(n); for (let i = 0; i < n; i++) { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; o[i] = s & 255; } return o; };
const statusList = () => { const l = Buffer.alloc(16384); for (const i of [3, 77, 12499]) l[i] |= 0x80; return l; };
// Same decompression bound as the second implementation (interop/second-impl/credential.mjs).
const second = g => gunzipSync(g, { maxOutputLength: 2097152 });

test('deterministic gzip round trips empty zeros ones and seeded random input through node zlib', () => {
  for (const d of [Buffer.alloc(0), Buffer.alloc(1), Buffer.alloc(100000), Buffer.alloc(100000, 255), xorshift(30000), Buffer.from('kya kya kya kya kya kya')]) {
    assert.deepEqual(gunzipSync(gzipDeterministic(d)), d);
  }
});

test('deterministic gzip round trips repeated phrases that exercise long distances and every length class', () => {
  const words = Buffer.from('alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu ');
  const d = Buffer.concat(Array.from({ length: 3000 }, (_, i) => Buffer.concat([words.subarray(i % 40), xorshift(i % 7)])));
  const g = gzipDeterministic(d);
  assert.deepEqual(gunzipSync(g), d);
  assert.ok(g.length < d.length);
});

test('deterministic gzip writes a fixed header and a correct CRC32 and ISIZE trailer', () => {
  const d = xorshift(5000), g = gzipDeterministic(d);
  assert.equal(g.subarray(0, 10).toString('hex'), '1f8b08000000000000ff');
  assert.equal(g.readUInt32LE(g.length - 8), crc32(d));
  assert.equal(g.readUInt32LE(g.length - 4), 5000);
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
});

test('deterministic gzip of a 16 KiB mostly zero status list round trips and stays tiny', () => {
  const l = statusList(), g = gzipDeterministic(l);
  assert.deepEqual(second(g), l);
  assert.ok(g.length < 200, String(g.length));
});

test('deterministic gzip of the 2097153 byte inflate past the bound case stays well under the encoded limit', () => {
  const g = gzipDeterministic(Buffer.alloc(2097153));
  assert.deepEqual(gunzipSync(g), Buffer.alloc(2097153));
  assert.ok(g.length < 16384, String(g.length));
  assert.ok(('u' + g.toString('base64url')).length < 1048576 / 32);
  assert.throws(() => decodeList('u' + g.toString('base64url')), /exceeds/);
  assert.throws(() => second(g), /larger|exceeds|limit/i);
});

test('deterministic gzip output decodes with an independent python gzip decoder', t => {
  const d = Buffer.concat([statusList(), xorshift(3000), Buffer.alloc(9000, 7)]);
  const r = spawnSync('python3', ['-I', '-c', 'import sys,gzip,hashlib;sys.stdout.write(hashlib.sha256(gzip.decompress(sys.stdin.buffer.read())).hexdigest())'], { input: gzipDeterministic(d), encoding: 'utf8' });
  if (r.error) return t.skip('python3 is not available');
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, sha(d));
});

test('deterministic gzip is repeatable and independent of the input container type', () => {
  const d = xorshift(9000);
  assert.deepEqual(gzipDeterministic(d), gzipDeterministic(d));
  assert.deepEqual(gzipDeterministic(new Uint8Array(d)), gzipDeterministic(d));
  assert.deepEqual(gzipDeterministic([...d]), gzipDeterministic(d));
});

test('deterministic gzip golden bytes pin the exact output so a platform difference fails loudly', () => {
  assert.equal(gzipDeterministic(Buffer.alloc(0)).toString('hex'), '1f8b08000000000000ff03000000000000000000');
  assert.equal(gzipDeterministic(Buffer.from('kya kya kya kya kya kya')).toString('hex'), '1f8b08000000000000ffcbae4c54c082018a1eab4a17000000');
  assert.equal(sha(gzipDeterministic(statusList())), '2a48d148c5992676333b95619169c73a360f07cd956ffff161835c7c84e3c7b6');
  assert.equal(gzipDeterministic(statusList()).length, 138);
  assert.equal(sha(gzipDeterministic(Buffer.alloc(2097153))), '16d5e3a23a20b0eae7446ac58731c47e57942fff246db079ee46aacf835edf92');
  assert.equal(sha(gzipDeterministic(xorshift(20000))), '243efa5e4b873d73110c93998255b30186f558b6bc686cff1d24fd9782329f07');
  assert.equal(sha(gzipDeterministic(Buffer.alloc(4096, 255))), '68fa2b69aa57cefeed1299b550898b54c623806c4a9d9c096801a0b01714a64b');
});

test('encodeList uses the deterministic encoder so exported status list bytes are pinned', () => {
  const b = createBitstring(131072); for (const i of [3, 77, 99999]) setBit(b, i);
  const enc = encodeList(b);
  assert.equal(enc.length, 'u'.length + Math.ceil(gzipDeterministic(b).length * 4 / 3));
  assert.equal(sha(enc), createHash('sha256').update('u' + gzipDeterministic(b).toString('base64url')).digest('hex'));
  assert.equal(gzipDeterministic(b).subarray(0, 10).toString('hex'), '1f8b08000000000000ff');
  assert.deepEqual(decodeList(enc), b);
});
