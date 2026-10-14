import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, parseJson } from '../src/shared/canonical.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const srcDir = join(root, 'src');
const doc = readFileSync(join(root, 'docs', 'CRYPTO-AGILITY.md'), 'utf8');

function walk(dir) {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}
const sources = walk(srcDir).filter(p => p.endsWith('.mjs')).map(p => ({ path: relative(root, p).replaceAll('\\', '/'), text: readFileSync(p, 'utf8') }));

// A domain prefix is a string literal such as kya.evidence/v1 followed by a backslash-n escape in the source text.
const PREFIX = /kya\.[a-z0-9.-]+\/v\d+\\n/g;

test('every signing and keyed-hash domain prefix in src is documented in CRYPTO-AGILITY.md', () => {
  const found = new Map();
  for (const { path, text } of sources) for (const m of text.matchAll(PREFIX)) found.set(m[0], path);
  assert.ok(found.size >= 6, `expected at least six domain prefixes, found ${found.size}`);
  for (const [prefix, path] of found) assert.ok(doc.includes('`' + prefix + '`'), `domain prefix ${prefix} (${path}) is not documented`);
});

test('every source file that signs or verifies is domain-separated or explicitly documented as exempt', () => {
  const sites = sources.filter(s => /\b(?:sign|verify)\(null,/.test(s.text));
  assert.ok(sites.length >= 5, 'signing sites were found');
  for (const { path, text } of sites) {
    const separated = PREFIX.test(text); PREFIX.lastIndex = 0;
    if (!separated) assert.ok(doc.includes('`' + path + '`'), `${path} signs without a KYA domain prefix and is not listed as an exemption`);
  }
});

test('every hash and HMAC algorithm and every holdout label used in src is documented', () => {
  const algorithms = new Set();
  const labels = new Set();
  for (const { text } of sources) {
    for (const m of text.matchAll(/create(?:Hash|Hmac)\(\s*'([a-z0-9-]+)'/g)) algorithms.add(m[1]);
    for (const m of text.matchAll(/'(kya\.holdout\.[a-z-]+\/v\d+)'/g)) labels.add(m[1]);
  }
  assert.deepEqual([...algorithms].sort(), ['sha256'], 'a new hash algorithm needs a documented agility entry and an ADR');
  assert.ok(doc.includes('SHA-256') && doc.includes('`sha256`') && doc.includes('HMAC-SHA-256'));
  assert.ok(labels.size >= 4);
  for (const label of labels) assert.ok(doc.includes(label), `holdout label ${label} is not documented`);
});

test('the only proof algorithm accepted in src is Ed25519 and the document says so', () => {
  const ids = new Set();
  for (const { text } of sources) for (const m of text.matchAll(/algorithm\s*={2,3}\s*'([^']+)'/g)) ids.add(m[1]);
  assert.deepEqual([...ids], ['Ed25519']);
  assert.ok(doc.includes('`Ed25519`'));
});

test('RFC 8785 comparison: output is identical for the RFC samples KYA accepts', () => {
  // Appendix B of RFC 8785 (fetched 2026-10-14). Values are parsed from text so the exact digits are those of the RFC.
  const accepted = [
    ['0', '0'], ['-0', '0'], ['5e-324', '5e-324'], ['-5e-324', '-5e-324'], ['9.999999999999997e-7', '9.999999999999997e-7'], ['0.000001', '0.000001'],
    ['333333333.3333332', '333333333.3333332'], ['333333333.33333325', '333333333.33333325'], ['333333333.3333333', '333333333.3333333'],
    ['333333333.3333334', '333333333.3333334'], ['333333333.33333343', '333333333.33333343'], ['-0.0000033333333333333333', '-0.0000033333333333333333']
  ];
  for (const [text, expected] of accepted) assert.equal(canonical(parseJson(text)), expected, text);
  // RFC 8785 section 3.2.3 style ordering by UTF-16 code units: the astral key (surrogate pair D83D DE00) precedes U+FFFF.
  assert.equal(canonical({ '\u{1F600}': 1, '\uFFFF': 2, a: 3 }), '{"a":3,"\u{1F600}":1,"\uFFFF":2}');
  // Control characters use lowercase \u00xx; DEL and U+2028 are written raw; no normalisation is applied.
  assert.equal(canonical('\u0007\u007f\u2028'), '"\\u0007\u007f\u2028"');
  assert.equal(canonical({ '\u00e9': 1, 'e\u0301': 2 }), '{"e\u0301":2,"\u00e9":1}');
});

test('RFC 8785 comparison: documented differences in the accepted input set', () => {
  // Numbers JCS serialises (Appendix B) that KYA rejects: integers beyond the safe range and integral floats at or above 2^53.
  for (const text of ['9007199254740992', '-9007199254740992', '295147905179352830000', '1e+21', '1e+23', '1.7976931348623157e+308']) {
    assert.throws(() => canonical(parseJson(text)), /Unsafe JSON number/, text);
  }
  // NaN and Infinity fail in both.
  assert.throws(() => canonical(NaN)); assert.throws(() => canonical(Infinity));
  // Lone surrogates: JCS must fail, KYA emits an escape.
  assert.equal(canonical('\ud800'), '"\\ud800"');
  // Reserved member names and resource limits are KYA-only.
  assert.throws(() => parseJson('{"__proto__":1}'), /forbidden/i);
  assert.throws(() => parseJson('{"constructor":1}'), /forbidden/i);
  assert.throws(() => canonical([...Array(33)].reduce(v => [v], 1)), /resource limit/i);
  // Duplicate members are rejected by the parser, as I-JSON requires.
  assert.throws(() => parseJson('{"a":1,"a":2}'), /Duplicate/);
});
