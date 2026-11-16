import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { digest, keyId } from 'kya-evidence';
import { passportId, passportPublicKey, signPassportEvent, verifyPassport } from 'kya-evidence/passport';
import { openPassportRegistry } from 'kya-evidence/passport/registry';

const registry = 'https://registry.example';
const manifestDigest = 'ac'.repeat(32);
const [controller, agent, replacement, impostor] = Array.from({ length: 4 }, () => generateKeyPairSync('ed25519').privateKey);
const genesis = {
  schema: 'kya.passport-event/v1', operation: 'register', registry, previous: null,
  agentId: 'agent:fixture', principalId: 'controller:fixture', manifestDigest,
  controllerPublicKey: passportPublicKey(controller), agentPublicKey: passportPublicKey(agent),
};
genesis.passportId = passportId(genesis);
const seal = (event, controllerKey = controller, agentKey = agent) => ({
  event, controllerSignature: signPassportEvent(event, controllerKey),
  agentSignature: agentKey && signPassportEvent(event, agentKey),
});
const registration = seal(genesis);
const rotation = seal({
  ...genesis, operation: 'rotate', previous: digest(registration), agentPublicKey: passportPublicKey(replacement),
}, controller, replacement);
const revocation = seal({
  ...genesis, operation: 'revoke', previous: digest(rotation), agentPublicKey: null,
}, controller, null);

test('registers, verifies, rotates, revokes and finds historical fingerprints across reopen', t => {
  const tmp = mkdtempSync(join(tmpdir(), 'kya-passport-'));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const filename = join(tmp, 'registry.sqlite');
  const store = openPassportRegistry(filename, registry);
  try {
    const active = store.append(registration);
    assert.equal(active.status, 'active');
    assert.equal(active.current.fingerprint, keyId(passportPublicKey(agent)));
    assert.deepEqual(store.append(registration), active);
    assert.equal(store.append(rotation).current.fingerprint, keyId(passportPublicKey(replacement)));
    assert.equal(store.append(revocation).status, 'revoked');
    assert.equal(store.append(rotation).status, 'revoked');
  } finally {
    store.close();
  }
  const reopened = openPassportRegistry(filename, registry);
  t.after(() => reopened.close());
  const found = reopened.read(genesis.passportId);
  assert.equal(found.current, null);
  assert.equal(found.history.length, 3);
  assert.deepEqual(verifyPassport(found.history, registry).fingerprints, found.fingerprints);
  for (const fingerprint of [...found.fingerprints, manifestDigest]) {
    assert.deepEqual(reopened.lookup(fingerprint), [genesis.passportId]);
  }
  assert.throws(() => openPassportRegistry(filename, 'https://other.example'), /registry mismatch/i);
});

test('rejects cross-registry replay, tampering, wrong signers, stale forks and retired keys', () => {
  assert.throws(() => verifyPassport([registration], 'https://other.example'), /registry mismatch/i);
  assert.throws(() => verifyPassport([seal(genesis, impostor)], registry), /signature/i);
  assert.throws(() => verifyPassport([seal(genesis, controller, impostor)], registry), /signature/i);
  assert.throws(() => verifyPassport([{ ...registration, event: { ...genesis, manifestDigest: 'bb'.repeat(32) } }], registry), /signature/i);
  assert.throws(() => verifyPassport([registration, rotation, rotation], registry), /history/i);
  const reuse = seal({ ...genesis, operation: 'rotate', previous: digest(rotation) });
  assert.throws(() => verifyPassport([registration, rotation, reuse], registry), /already used/i);
  const reopen = seal({ ...genesis, operation: 'rotate', previous: digest(revocation) });
  assert.throws(() => verifyPassport([registration, rotation, revocation, reopen], registry), /transition/i);
});

test('revises a manifest while retaining the active key', () => {
  const updated = 'bd'.repeat(32);
  const revision = seal({ ...genesis, operation: 'revise', previous: digest(registration), manifestDigest: updated });
  const state = verifyPassport([registration, revision], registry);
  assert.equal(state.current.manifestDigest, updated);
  assert.deepEqual(state.fingerprints, [keyId(passportPublicKey(agent))]);
});

test('reserves the final history slot for revocation', () => {
  const history = [registration];
  for (let revision = 1; revision < 127; revision++) {
    history.push(seal({ ...genesis, operation: 'revise', previous: digest(history.at(-1)),
      manifestDigest: digest(revision) }));
  }
  const previous = digest(history.at(-1));
  assert.throws(() => verifyPassport([...history, seal({
    ...genesis, operation: 'revise', previous, manifestDigest: digest(127),
  })], registry), /final slot/i);
  const revoked = seal({ ...genesis, operation: 'revoke', previous,
    agentPublicKey: null, manifestDigest: history.at(-1).event.manifestDigest }, controller, null);
  assert.equal(verifyPassport([...history, revoked], registry).status, 'revoked');
});

test('competing processes cannot publish two rotations from the same head', async t => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const tmp = mkdtempSync(join(tmpdir(), 'kya-passport-race-'));
  const filename = join(tmp, 'registry.sqlite');
  const store = openPassportRegistry(filename, registry);
  t.after(() => {
    store.close();
    rmSync(tmp, { recursive: true, force: true });
  });
  store.append(registration);
  const fork = seal({ ...rotation.event, agentPublicKey: passportPublicKey(impostor) }, controller, impostor);
  const childCode = `
    import { openPassportRegistry } from 'kya-evidence/passport/registry';
    const { filename, registry, record } = JSON.parse(process.argv[1]);
    const store = openPassportRegistry(filename, registry);
    try {
      const passport = store.append(record);
      process.stdout.write(passport.current.fingerprint);
    } catch (error) {
      if (error.message !== 'Passport history mismatch') throw error;
      process.stdout.write('stale');
    } finally {
      store.close();
    }
  `;
  const publish = record => promisify(execFile)(process.execPath,
    ['--input-type=module', '-e', childCode, JSON.stringify({ filename, registry, record })],
    { cwd: new URL('..', import.meta.url), timeout: 15_000 });
  const results = await Promise.all([publish(rotation), publish(fork)]);
  const current = store.read(genesis.passportId);
  assert.deepEqual(results.map(result => result.stdout).sort(), [current.current.fingerprint, 'stale']);
  assert.equal(current.history.length, 2);
  const candidates = [rotation, fork].map(record => keyId(record.event.agentPublicKey));
  const rejected = candidates.find(key => key !== current.current.fingerprint);
  assert.deepEqual(store.lookup(rejected), []);
});
