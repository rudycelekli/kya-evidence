import { createPrivateKey, sign } from 'node:crypto';
import { digest } from '../../src/shared/canonical.mjs';
import { keyId } from '../../src/identity/domain/services/validation.mjs';
import { passportId, passportPublicKey, signPassportEvent } from '../../src/passport/index.mjs';
import { buildPassportRegistryIndex } from '../../src/passport/registry-proof.mjs';
import { registryCheckpointBytes, registryWitnessBytes, signRegistryStatement } from '../../src/passport/registry-checkpoint.mjs';
import { receiptBytes } from '../pairing-gateway/downstream-receipts.mjs';

// Public synthetic seeds. Never reuse these deterministic signing keys.
const fixtureKey = index => createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, index)]),
  format: 'der', type: 'pkcs8',
});
const [controller, agent, replacement, recovery, newController, origin, witnessA, witnessB, receiptKey] =
  Array.from({ length: 9 }, (_, index) => fixtureKey(index + 1));
const registry = 'https://registry.example.test';
const manifestDigest = 'cd'.repeat(32);
const issuedAt = '2026-11-16T12:00:00.000Z';
const expiresAt = '2026-11-16T12:05:00.000Z';
const now = '2026-11-16T12:01:00.000Z';
const id = key => keyId(passportPublicKey(key));

function record(event, controllerKey, agentKey, recoveryKey) {
  return {
    event, controllerSignature: signPassportEvent(event, controllerKey),
    agentSignature: agentKey ? signPassportEvent(event, agentKey) : null,
    ...(event.schema === 'kya.passport-event/v2' ? {
      recoverySignature: recoveryKey ? signPassportEvent(event, recoveryKey) : null,
    } : {}),
  };
}

function registration(agentId, version = 1) {
  const event = {
    schema: 'kya.passport-event/v' + version, operation: 'register', registry, previous: null,
    agentId, principalId: 'controller:fixture', controllerPublicKey: passportPublicKey(controller),
    agentPublicKey: passportPublicKey(agent), manifestDigest,
    ...(version === 2 ? { recoveryPublicKey: passportPublicKey(recovery) } : {}),
  };
  event.passportId = passportId(event);
  return record(event, controller, agent, version === 2 ? recovery : null);
}

const first = registration('agent:first');
const second = registration('agent:second', 2);
const rotated = record({ ...first.event, operation: 'rotate', previous: digest(first),
  agentPublicKey: passportPublicKey(replacement) }, controller, replacement);
const revoked = record({ ...first.event, operation: 'revoke', previous: digest(rotated),
  agentPublicKey: null }, controller, null);
const recovered = record({ ...second.event, operation: 'recover', previous: digest(second),
  controllerPublicKey: passportPublicKey(newController), agentPublicKey: passportPublicKey(replacement) },
newController, replacement, recovery);
const retiredController = record({ ...second.event, operation: 'revise', previous: digest(recovered),
  agentPublicKey: passportPublicKey(replacement), manifestDigest: 'ef'.repeat(32) }, controller, replacement);
const vectors = [];
const accept = value => ({ status: 'accept', value });
const reject = { status: 'reject' };
const add = (id, operation, inputs, expected) => vectors.push({ id, operation, inputs, expected });
const historyVector = (name, history, expected) => add(name, 'passport-history', { history, registry }, expected);
const expectedPassport = (first, head, active, fingerprints, extra = {}) => ({
  passportId: first.event.passportId, agentId: first.event.agentId, principalId: first.event.principalId,
  head: digest(head), status: active ? 'active' : 'revoked',
  current: active ? { fingerprint: id(active), manifestDigest } : null, fingerprints: fingerprints.map(id), ...extra,
});
historyVector('history-register-v1', [first], accept(expectedPassport(first, first, agent, [agent])));
historyVector('history-rotate-v1', [first, rotated], accept(expectedPassport(first, rotated, replacement, [agent, replacement])));
historyVector('history-revoke-v1', [first, rotated, revoked], accept(expectedPassport(first, revoked, null, [agent, replacement])));
historyVector('history-v2-recovery', [second, recovered], accept(expectedPassport(second, recovered, replacement, [agent, replacement], {
  controllerFingerprint: id(newController), recoveryEnabled: true,
})));
historyVector('history-wrong-agent-signer', [{ ...first, agentSignature: signPassportEvent(first.event, origin) }], reject);
historyVector('history-wrong-controller-signer', [{ ...first, controllerSignature: signPassportEvent(first.event, origin) }], reject);
historyVector('history-wrong-recovery-signer', [second, {
  ...recovered, recoverySignature: signPassportEvent(recovered.event, origin),
}], reject);
historyVector('history-retired-controller', [second, recovered, retiredController], reject);
historyVector('history-skipped-predecessor', [first, revoked], reject);
const afterRevocation = record({ ...first.event, operation: 'rotate', previous: digest(revoked),
  agentPublicKey: passportPublicKey(origin) }, controller, origin);
historyVector('history-rotate-after-revocation', [first, rotated, revoked, afterRevocation], reject);
add('history-other-registry', 'passport-history', { history: [first], registry: 'https://other.example.test' }, reject);

const index = buildPassportRegistryIndex([[first, rotated, revoked], [second, recovered]], registry);
const checkpoint = { schema: 'kya.registry-checkpoint/v1', registry, epoch: 1, previous: null,
  root: index.root, count: index.count, issuedAt, expiresAt };
const checkpointDigest = digest(checkpoint);
const signed = { checkpoint, signature: signRegistryStatement(registryCheckpointBytes(checkpoint), origin) };
const endorsements = [witnessA, witnessB].map(key => ({ witnessId: id(key), checkpointDigest,
  signature: signRegistryStatement(registryWitnessBytes(checkpoint), key) }));
const trust = { registry, originPublicKey: passportPublicKey(origin),
  witnessPublicKeys: [passportPublicKey(witnessA), passportPublicKey(witnessB)] };
const query = { kind: 'fingerprint', digest: manifestDigest };
const inputs = { query, proof: index.prove(query), signed, endorsements, trust, now };
const lookupVector = (name, changes, expected) => add(name, 'witnessed-lookup', { ...inputs, ...changes }, expected);
lookupVector('lookup-shared-manifest-complete', {}, accept({ checkpointDigest, epoch: 1,
  value: [first.event.passportId, second.event.passportId].sort() }));
const old = { kind: 'fingerprint', digest: id(agent) };
lookupVector('lookup-historical-key', { query: old, proof: index.prove(old) }, accept({ checkpointDigest, epoch: 1,
  value: [first.event.passportId, second.event.passportId].sort() }));
const absent = { kind: 'fingerprint', digest: '00'.repeat(32) };
lookupVector('lookup-verified-absence', { query: absent, proof: index.prove(absent) }, accept({ checkpointDigest, epoch: 1, value: null }));
lookupVector('lookup-false-absence', { proof: { left: null, right: null } }, reject);
const truncated = structuredClone(inputs.proof);
truncated.member.leaf.value.pop();
lookupVector('lookup-truncated-result', { proof: truncated }, reject);
lookupVector('lookup-duplicate-witness', { endorsements: [endorsements[0], endorsements[0]] }, reject);
lookupVector('lookup-missing-witness', { endorsements: [endorsements[0]] }, reject);
lookupVector('lookup-wrong-origin-signature', { signed: {
  checkpoint, signature: signRegistryStatement(registryCheckpointBytes(checkpoint), witnessA),
} }, reject);
lookupVector('lookup-expired-checkpoint', { now: expiresAt }, reject);
lookupVector('lookup-behind-client-pin', { trust: { ...trust, checkpointPin: { epoch: 2, checkpointDigest: '12'.repeat(32) } } }, reject);

const delivery = { operationId: 'aa'.repeat(32), requestDigest: 'bb'.repeat(32), routeRevision: 'cc'.repeat(32) };
const receipt = { schema: 'kya.mcp-receipt/v1', ...delivery, outcome: 'confirmed-applied' };
const receiptEnvelope = (value, key) => ({ receipt: value, signature: sign(null, receiptBytes(value), key).toString('base64url') });
const validReceipt = receiptEnvelope(receipt, receiptKey);
const receiptVector = (name, envelope, expected) => add(name, 'downstream-receipt', {
  envelope, delivery, publicKey: passportPublicKey(receiptKey),
}, expected);
receiptVector('receipt-confirmed-applied', validReceipt, accept({
  operationId: delivery.operationId, outcome: receipt.outcome, receiptDigest: digest(validReceipt),
}));
const negativeReceipt = receiptEnvelope({ ...receipt, outcome: 'confirmed-not-applied' }, receiptKey);
receiptVector('receipt-confirmed-not-applied', negativeReceipt, accept({
  operationId: delivery.operationId, outcome: 'confirmed-not-applied', receiptDigest: digest(negativeReceipt),
}));
receiptVector('receipt-wrong-signer', receiptEnvelope(receipt, origin), reject);
for (const field of ['operationId', 'requestDigest', 'routeRevision']) {
  receiptVector('receipt-different-' + field, receiptEnvelope({ ...receipt, [field]: 'ff'.repeat(32) }, receiptKey), reject);
}
receiptVector('receipt-nonterminal', receiptEnvelope({ ...receipt, outcome: 'unknown' }, receiptKey), reject);
process.stdout.write(JSON.stringify({ schema: 'kya.passport-vectors/v1', vectors }, null, 2) + '\n');
