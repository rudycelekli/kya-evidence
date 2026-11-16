import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { digest, keyId } from 'kya-evidence';
import { passportId, passportPublicKey, signPassportEvent } from 'kya-evidence/passport';
import { openPassportRegistry } from 'kya-evidence/passport/registry';
import { buildPassportRegistryIndex, verifyPassportRegistryLookup } from 'kya-evidence/passport/registry-proof';
import { registryCheckpointBytes, signRegistryStatement, verifyWitnessedLookup } from 'kya-evidence/passport/registry-checkpoint';
import { openPassportWitness } from 'kya-evidence/passport/witness';

const registry = 'https://registry.example';
const now = '2026-11-16T12:01:00.000Z';
const key = () => generateKeyPairSync('ed25519').privateKey;
const [origin, firstWitness, secondWitness, controller, agent, replacement] = Array.from({ length: 6 }, key);
const trust = {
  registry, originPublicKey: passportPublicKey(origin),
  witnessPublicKeys: [passportPublicKey(firstWitness), passportPublicKey(secondWitness)],
};
const manifestDigest = '34'.repeat(32);

function seal(event, agentKey) {
  return {
    event, controllerSignature: signPassportEvent(event, controller),
    agentSignature: signPassportEvent(event, agentKey),
  };
}

function registration(agentId) {
  const event = {
    schema: 'kya.passport-event/v1', registry, operation: 'register', previous: null,
    agentId, principalId: 'controller:fixture', manifestDigest,
    controllerPublicKey: passportPublicKey(controller), agentPublicKey: passportPublicKey(agent),
  };
  event.passportId = passportId(event);
  return seal(event, agent);
}

function signedIndex(histories, epoch, previous, issuedAt, signer = origin) {
  const index = buildPassportRegistryIndex(histories, registry);
  const checkpoint = {
    schema: 'kya.registry-checkpoint/v1', registry, epoch, previous, root: index.root,
    count: index.count, issuedAt, expiresAt: '2026-11-16T12:04:00.000Z',
  };
  return { index, signed: { checkpoint, signature: signRegistryStatement(registryCheckpointBytes(checkpoint), signer) } };
}

test('witnessed lookup proves a complete shared fingerprint result and rejects tampering and false absence', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-registry-witness-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const store = openPassportRegistry(join(dir, 'origin.sqlite'), registry);
  const witnesses = [firstWitness, secondWitness].map((witnessPrivateKey, i) =>
    openPassportWitness(join(dir, 'witness-' + i + '.sqlite'), { ...trust, witnessPrivateKey, clock: () => now }));
  t.after(() => { store.close(); witnesses.forEach(witness => witness.close()); });
  const records = [registration('agent:first'), registration('agent:second')];
  records.forEach(record => store.append(record));
  const histories = store.snapshotHistories();
  const { index, signed } = signedIndex(histories, 1, null, '2026-11-16T12:00:00.000Z');
  const endorsements = witnesses.map(witness => witness.endorse(signed, histories));
  assert.throws(() => witnesses[0].endorse(signed, histories.slice(1)), /snapshot mismatch/i);
  const query = { kind: 'fingerprint', digest: manifestDigest };
  const proof = index.prove(query);
  assert.deepEqual(verifyWitnessedLookup(query, proof, signed, endorsements, trust, now).value,
    records.map(record => record.event.passportId).sort());
  const truncated = structuredClone(proof);
  truncated.member.leaf.value.pop();
  assert.throws(() => verifyWitnessedLookup(query, truncated, signed, endorsements, trust, now), /proof mismatch/i);
  assert.throws(() => verifyWitnessedLookup(query, proof, signed, [endorsements[0], endorsements[0]], trust, now), /endorsement mismatch/i);
  assert.throws(() => verifyWitnessedLookup(query, proof, signed, endorsements, {
    ...trust, witnessPublicKeys: [trust.originPublicKey, trust.witnessPublicKeys[1]],
  }, now), /distinct/i);
  assert.throws(() => verifyWitnessedLookup(query, proof, signed, endorsements, trust, '2026-11-16T12:04:00.000Z'), /freshness/i);
  assert.throws(() => verifyWitnessedLookup(query, proof, signed, endorsements, { ...trust,
    checkpointPin: { epoch: 2, checkpointDigest: digest('newer observation') },
  }, now), /rolled back/i);
  const displaced = index.prove({ kind: 'fingerprint', digest: '12'.repeat(32) });
  assert.throws(() => verifyWitnessedLookup(query, displaced, signed, endorsements, trust, now), /absence/i);
  assert.throws(() => verifyWitnessedLookup(query, { left: null, right: null }, signed, endorsements, trust, now), /adjacent/i);
  assert.throws(() => verifyWitnessedLookup(query, proof, signed, endorsements.slice(1), trust, now), /incomplete/i);

  for (const [kind, digest] of [['fingerprint', '00'.repeat(32)], ['fingerprint', 'ff'.repeat(32)], ['passport', 'ff'.repeat(32)]]) {
    const absent = { kind, digest };
    assert.equal(verifyWitnessedLookup(absent, index.prove(absent), signed, endorsements, trust, now).value, null);
  }
  const passport = { kind: 'passport', digest: records[0].event.passportId };
  assert.deepEqual(verifyWitnessedLookup(passport, index.prove(passport), signed, endorsements, trust, now).value,
    { head: digest(records[0]), sequence: 1 });
});

test('witness state refuses omission or conflicting heads after reopening', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-witness-state-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const filename = join(dir, 'witness.sqlite');
  const open = () => openPassportWitness(filename, { ...trust, witnessPrivateKey: firstWitness, clock: () => now });
  const first = registration('agent:first');
  const other = registration('agent:second');
  const initial = signedIndex([[first], [other]], 1, null, '2026-11-16T12:00:00.000Z');
  const witness = open();
  const initialEndorsement = witness.endorse(initial.signed, [[first], [other]]);
  witness.close();
  const restarted = open();
  t.after(() => restarted.close());
  assert.deepEqual(restarted.endorse(initial.signed, [[first], [other]]), initialEndorsement);
  const later = '2026-11-16T12:00:30.000Z';
  const omitted = signedIndex([[first]], 2, initialEndorsement.checkpointDigest, later);
  assert.throws(() => restarted.endorse(omitted.signed, [[first]]), /omitted or forked/i);

  const rotate = seal({ ...first.event, operation: 'rotate', previous: digest(first),
    agentPublicKey: passportPublicKey(replacement) }, replacement);
  const histories = [[first, rotate], [other]];
  const next = signedIndex(histories, 2, initialEndorsement.checkpointDigest, later);
  assert.equal(restarted.endorse(next.signed, histories).checkpointDigest, digest(next.signed.checkpoint));
  assert.throws(() => restarted.endorse(initial.signed, [[first], [other]]), /does not extend/i);
  const conflict = signedIndex([[first], [other]], 2, initialEndorsement.checkpointDigest, now);
  assert.throws(() => restarted.endorse(conflict.signed, [[first], [other]]), /does not extend/i);
  const truncated = signedIndex([[first], [other]], 3, digest(next.signed.checkpoint), now);
  assert.throws(() => restarted.endorse(truncated.signed, [[first], [other]]), /omitted or forked/i);
  const oldKey = { kind: 'fingerprint', digest: keyId(passportPublicKey(agent)) };
  assert.equal(verifyPassportRegistryLookup(oldKey, next.index.prove(oldKey), next.index.root, next.index.count).length, 2);
});

test('empty proof and odd-level padding are checked', () => {
  const empty = buildPassportRegistryIndex([], registry);
  const query = { kind: 'fingerprint', digest: manifestDigest };
  assert.equal(verifyPassportRegistryLookup(query, empty.prove(query), empty.root, 0), null);
  assert.throws(() => verifyPassportRegistryLookup(query, empty.prove(query), digest('wrong root'), 0), /empty/i);
  const record = registration('agent:first');
  const index = buildPassportRegistryIndex([[record]], registry);
  const passport = { kind: 'passport', digest: record.event.passportId };
  const proof = index.prove(passport);
  assert.equal(index.count, 3);
  proof.member.siblings[0] = digest('false padding');
  assert.throws(() => verifyPassportRegistryLookup(passport, proof, index.root, index.count), /padding/i);
});
