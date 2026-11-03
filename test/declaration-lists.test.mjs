import test from 'node:test';
import assert from 'node:assert/strict';
import { digest, importDeclarations } from '../src/index.mjs';

const fields = [['permittedDomains', 'domains'], ['permittedRegions', 'permittedRegions'], ['forbiddenRegions', 'forbiddenRegions']];
const open = extra => ({
  '@context': ['https://w3id.org/kya/v1'], id: 'urn:synthetic:list-import',
  type: ['VerifiablePresentation', 'KyaManifest'], kyaVersion: 'synthetic', agentId: 'did:example:synthetic',
  verificationMethod: [], authentication: [], assertionMethod: [], capabilityInvocation: [], proof: { unverified: true }, ...extra
});
const card = skills => ({ name: 'Synthetic list importer', skills });
function read(format, source) {
  const r = importDeclarations(format, source);
  assert.equal(r.sourceDigest, digest(source));
  assert.ok(r.unverified.includes('controller consent and legal authority'));
  assert.ok(r.unverified.includes('cryptographic proofs and credentials'));
  assert.ok(r.unverified.includes('runtime enforcement'));
  assert.equal(Object.hasOwn(r, 'score'), false);
  assert.equal(Object.hasOwn(r, 'permissions'), false);
  assert.equal(JSON.stringify(r).includes('dropped-private-sentinel'), false);
  return r;
}
const strings = n => Array.from({ length: n }, (_, i) => `synthetic-${i}`);

test('representable Open-KYA lists preserve empty values, order, duplicates and existing bounds', () => {
  for (const [field, output] of fields) for (const value of [[], ['', 'duplicate', 'duplicate', 'x'.repeat(256)], strings(128)]) {
    const r = read('open-kya-alpha', open({ [field]: value }));
    assert.deepEqual(r.declared[output], value);
    assert.ok(!r.unsupportedFields.includes(field));
  }
  for (const skills of [[], [{ id: 'same', description: 'unmapped metadata' }, { id: 'same' }, { id: 'x'.repeat(128) }], strings(128).map(id => ({ id }))]) {
    const r = read('a2a-1', card(skills));
    assert.deepEqual(r.declared.skillIds, skills.map(x => x.id));
    assert.ok(!r.unsupportedFields.includes('skills'));
    assert.equal(JSON.stringify(r).includes('unmapped metadata'), false);
  }
});

test('absent optional Open-KYA list fields remain empty without unsupported markers', () => {
  const r = read('open-kya-alpha', open({}));
  for (const [field, output] of fields) {
    assert.deepEqual(r.declared[output], []);
    assert.ok(!r.unsupportedFields.includes(field));
  }
});

test('malformed Open-KYA list members retain the existing projection and expose loss', () => {
  for (const [field, output] of fields) for (const value of [null, false, 19, 'dropped-private-sentinel', {},
    ['keep', 19, 'keep'], ['keep', { secret: 'dropped-private-sentinel' }], ['x'.repeat(257)]]) {
    const r = read('open-kya-alpha', open({ [field]: value }));
    assert.deepEqual(r.declared[output], Array.isArray(value) ? value.filter(x => typeof x === 'string' && x.length <= 256) : []);
    assert.ok(r.unsupportedFields.includes(field), field + ': ' + JSON.stringify(value));
  }
});

test('Open-KYA list truncation retains the first 128 members and exposes loss', () => {
  for (const [field, output] of fields) {
    const value = strings(129), r = read('open-kya-alpha', open({ [field]: value }));
    assert.deepEqual(r.declared[output], value.slice(0, 128));
    assert.ok(r.unsupportedFields.includes(field));
  }
});

test('malformed A2A skill IDs retain the existing projection and expose omitted IDs', () => {
  for (const invalid of [{}, { id: '' }, { id: 19 }, { id: null }, null, false, 19, 'dropped-private-sentinel',
    { id: 'x'.repeat(129), secret: 'dropped-private-sentinel' }]) {
    const r = read('a2a-1', card([{ id: 'keep' }, invalid, { id: 'keep' }]));
    assert.deepEqual(r.declared.skillIds, ['keep', 'keep']);
    assert.ok(r.unsupportedFields.includes('skills'), JSON.stringify(invalid));
  }
});

test('A2A skill ID truncation retains the first 128 IDs and exposes loss', () => {
  const ids = strings(129), r = read('a2a-1', card(ids.map(id => ({ id }))));
  assert.deepEqual(r.declared.skillIds, ids.slice(0, 128));
  assert.ok(r.unsupportedFields.includes('skills'));
});
