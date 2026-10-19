import { inflateRawSync } from 'node:zlib';
import { crc32 } from './gzip-deterministic.mjs';

// A GZIP reader that accepts exactly one RFC 1952 member and nothing else. node:gunzipSync decodes concatenated members
// and ignores trailing zero bytes, while other decoders refuse one or both, so the same text would be a valid list for
// one implementation and invalid for another. Here the member must end at the end of the input, the CRC-32 and the
// size trailer must match, and reserved header flags must be clear. Any failure throws Error with a short message.
const bad = message => { throw Error('Invalid gzip: ' + message); };

export function gunzipStrict(input, { maxBytes = 2 * 1024 * 1024 } = {}) {
  const b = Buffer.from(input);
  if (b.length < 18) bad('too short');
  if (b[0] !== 0x1f || b[1] !== 0x8b || b[2] !== 8) bad('not a deflate gzip member');
  const flags = b[3];
  if (flags & 0xe0) bad('reserved header flags');
  let pos = 10;
  if (flags & 4) { if (pos + 2 > b.length) bad('truncated header'); pos += 2 + b.readUInt16LE(pos); }
  for (const bit of [8, 16]) {
    if (!(flags & bit)) continue;
    const end = b.indexOf(0, pos);
    if (end < 0) bad('unterminated header text');
    pos = end + 1;
  }
  if (flags & 2) { if (pos + 2 > b.length) bad('truncated header'); if ((crc32(b.subarray(0, pos)) & 0xffff) !== b.readUInt16LE(pos)) bad('header checksum'); pos += 2; }
  if (pos > b.length - 8) bad('truncated member');
  const body = b.subarray(pos);
  const { buffer, engine } = inflateRawSync(body, { info: true, maxOutputLength: maxBytes });
  if (body.length - engine.bytesWritten !== 8) bad('data after the member or a truncated trailer');
  const trailer = body.subarray(engine.bytesWritten);
  if (trailer.readUInt32LE(0) !== crc32(buffer)) bad('CRC-32 mismatch');
  if (trailer.readUInt32LE(4) !== buffer.length % 4294967296) bad('size mismatch');
  return buffer;
}
