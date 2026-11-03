import test from 'node:test';
import assert from 'node:assert/strict';
import { digest, importDeclarations } from '../src/index.mjs';

const input = securitySchemes => ({ name: 'Synthetic declared agent', skills: [], securitySchemes });
const read = value => importDeclarations('a2a-1', value);
const schemes = size => Object.fromEntries(Array.from({ length: size }, (_, i) => [
  `scheme-${String(i).padStart(3, '0')}`, { type: 'synthetic', credential: 'private-fixture-sentinel' }
]));

test('A2A security scheme maps retain bounded names without emitting their definitions', () => {
  for (const size of [0, 1, 128]) {
    const source = input(schemes(size)), r = read(source);
    assert.deepEqual(r.declared.securitySchemeNames, Object.keys(source.securitySchemes).sort());
    assert.ok(!r.unsupportedFields.includes('securitySchemes'));
    assert.equal(r.sourceDigest, digest(source));
    assert.ok(r.unverified.includes('cryptographic proofs and credentials'));
    assert.equal(JSON.stringify(r).includes('private-fixture-sentinel'), false);
    assert.equal(Object.hasOwn(r, 'score'), false);
    assert.equal(Object.hasOwn(r, 'permissions'), false);
  }
});

test('absent A2A security schemes keep the empty declaration behavior', () => {
  const source = { name: 'Synthetic declared agent', skills: [] }, r = read(source);
  assert.deepEqual(r.declared.securitySchemeNames, []);
  assert.ok(!r.unsupportedFields.includes('securitySchemes'));
  assert.equal(r.sourceDigest, digest(source));
  assert.ok(r.unverified.includes('external identity'));
});

test('malformed A2A security scheme shapes invent no names and remain explicitly unsupported', () => {
  for (const value of [[], [{ type: 'synthetic', credential: 'private-fixture-sentinel' }],
    ['private-fixture-sentinel'], null, false, 19, 'private-fixture-sentinel']) {
    const source = input(value), r = read(source);
    assert.deepEqual(r.declared.securitySchemeNames, [], JSON.stringify(value));
    assert.ok(r.unsupportedFields.includes('securitySchemes'), JSON.stringify(value));
    assert.equal(r.sourceDigest, digest(source));
    assert.ok(r.unverified.includes('cryptographic proofs and credentials'));
    assert.equal(JSON.stringify(r).includes('private-fixture-sentinel'), false);
  }
});

test('A2A security scheme name truncation remains visible without changing the source digest', () => {
  const source = input(schemes(129)), r = read(source);
  assert.deepEqual(r.declared.securitySchemeNames, Object.keys(source.securitySchemes).sort().slice(0, 128));
  assert.ok(r.unsupportedFields.includes('securitySchemes'));
  assert.equal(r.sourceDigest, digest(source));
  assert.ok(r.unverified.includes('runtime enforcement'));
  assert.equal(JSON.stringify(r).includes('private-fixture-sentinel'), false);
});
