import test from 'node:test';
import assert from 'node:assert/strict';
import { digest, importDeclarations } from '../src/index.mjs';

const input = authority => ({
  '@context': ['https://w3id.org/kya/v1'], id: 'urn:fixture:manifest',
  type: ['VerifiablePresentation', 'KyaManifest'], kyaVersion: '1.1.0',
  agentId: 'did:example:agent', verificationMethod: [], authentication: [],
  assertionMethod: [], capabilityInvocation: [], proof: [{ unverified: true }],
  governingAuthority: authority
});
const read = value => importDeclarations('open-kya-alpha', value);

test('singleton Open-KYA authority arrays retain the exact unverified controller reference', () => {
  const source = input(['did:example:OwnerMixedCase']);
  const r = read(source);
  assert.equal(r.identity.controllerRef, 'did:example:OwnerMixedCase');
  assert.equal(r.sourceDigest, digest(source));
  assert.ok(!r.unsupportedFields.includes('governingAuthority'));
  assert.ok(r.unverified.includes('controller consent and legal authority'));
  assert.ok(r.unverified.includes('cryptographic proofs and credentials'));
  assert.equal(Object.hasOwn(r, 'score'), false);
  assert.equal(Object.hasOwn(r, 'permissions'), false);
});

test('plural or unrepresentable authority forms are explicitly unsupported and never select one controller', () => {
  for (const authority of [
    ['did:example:first', 'did:example:second'], [], [19], [{}], ['x'.repeat(513)],
    { controller: 'did:example:object' }, 19, null
  ]) {
    const source = input(authority), r = read(source);
    assert.equal(r.identity.controllerRef, null);
    assert.ok(r.unsupportedFields.includes('governingAuthority'), JSON.stringify(authority));
    assert.equal(r.sourceDigest, digest(source));
    assert.ok(r.unverified.includes('controller consent and legal authority'));
  }
});

test('legacy string authorities and absent authorities keep their previous declaration behavior', () => {
  const legacy = read(input('did:example:legacy'));
  assert.equal(legacy.identity.controllerRef, 'did:example:legacy');
  assert.ok(!legacy.unsupportedFields.includes('governingAuthority'));
  const source = input(null); delete source.governingAuthority;
  const absent = read(source);
  assert.equal(absent.identity.controllerRef, null);
  assert.ok(!absent.unsupportedFields.includes('governingAuthority'));
  assert.ok(absent.unverified.includes('external identity'));
});
