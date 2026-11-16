import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { digest, parseJson } from '../../src/shared/canonical.mjs';
import { keyId } from '../../src/identity/domain/services/validation.mjs';
import { signPairedAction, signPairingGrant } from '../../src/pairing/index.mjs';
import { signRegistryStatement } from '../../src/passport/registry-checkpoint.mjs';
import { passportPublicKey } from '../../src/passport/index.mjs';
import { witnessRosterBytes, witnessEnrollmentBytes } from '../../src/passport/witness-roster.mjs';

const key = fill => createPrivateKey({ key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, fill),
]), format: 'der', type: 'pkcs8' });
const [principal, agent, unrelated, origin, authority, a, b, replacement] =
  Array.from({ length: 8 }, (_, i) => key(31 + i));
const fp = key => keyId(passportPublicKey(key));
const vectors = [];
const add = (id, operation, inputs, expected) => vectors.push({ id, operation, inputs, expected });
const accept = value => ({ status: 'accept', value });
const reject = { status: 'reject' };
const manifest = parseJson(readFileSync(new URL('../../examples/manifest.json', import.meta.url), 'utf8'));
manifest.issuedAt = '2026-11-16T11:00:00.000Z';
manifest.expiresAt = '2026-11-16T13:00:00.000Z';
const context = {
  manifest, principalId: manifest.principal.id, principalKeyId: fp(principal),
  audience: 'gateway:fixture', permission: 'read', challenge: 'ab'.repeat(32), requestDigest: '21'.repeat(32),
  now: '2026-11-16T12:01:00.000Z', revokedKeyIds: [], revokedGrantDigests: [],
};
const grantPayload = {
  schema: 'kya.pairing-grant/v1', principalId: context.principalId, agentKeyId: fp(agent),
  manifestDigest: digest(manifest), audience: context.audience, permission: context.permission,
  issuedAt: '2026-11-16T12:00:00.000Z', expiresAt: '2026-11-16T12:10:00.000Z',
};
function paired(grantChanges = {}, actionChanges = {}, signer = agent) {
  const grant = signPairingGrant({ ...grantPayload, ...grantChanges }, principal);
  const action = signPairedAction({
    schema: 'kya.paired-action/v1', grantDigest: digest(grant), challenge: context.challenge,
    requestDigest: context.requestDigest, ...actionChanges,
  }, signer);
  return { grant, action };
}
const proof = paired();
const pairCase = (id, proposed, relying, expected = reject) =>
  add(id, 'paired-action', { proof: proposed, context: relying }, expected);
pairCase('pair-valid', proof, context, accept({
  principalId: context.principalId, principalKeyId: context.principalKeyId,
  agentId: manifest.agent.id, agentKeyId: fp(agent),
  manifestDigest: digest(manifest), grantDigest: digest(proof.grant), actionDigest: digest(proof.action),
}));
pairCase('pair-wrong-audience', paired({ audience: 'gateway:other' }), context);
pairCase('pair-wrong-agent-key', paired({}, {}, unrelated), context);
pairCase('pair-untrusted-principal', proof, { ...context, principalKeyId: fp(unrelated) });
pairCase('pair-swapped-grant', paired({}, { grantDigest: '55'.repeat(32) }), context);
pairCase('pair-modified-request', paired({}, { requestDigest: '22'.repeat(32) }), context);
pairCase('pair-different-challenge', proof, { ...context, challenge: '23'.repeat(32) });
pairCase('pair-revoked-grant', proof, { ...context, revokedGrantDigests: [digest(proof.grant)] });
pairCase('pair-revoked-agent-key', proof, { ...context, revokedKeyIds: [fp(agent)] });
pairCase('pair-expiry-is-exclusive', proof, { ...context, now: grantPayload.expiresAt });
pairCase('pair-different-manifest', proof, { ...context, manifest: {
  ...manifest, system: { ...manifest.system, configDigest: '98'.repeat(32) },
} });
pairCase('pair-approval-required', paired({ permission: 'external-message' }), { ...context, permission: 'external-message' });

const registry = 'https://registry.example.test';
const trust = { registry, originPublicKey: passportPublicKey(origin), authorityPublicKey: passportPublicKey(authority) };
const roster = {
  schema: 'kya.witness-roster/v1', registry, originKeyId: fp(origin), generation: 1, previous: null, handoff: null,
  operators: [{ id: 'operator:a', publicKey: passportPublicKey(a) }, { id: 'operator:b', publicKey: passportPublicKey(b) }],
};
const seal = (roster, keys, authorityKey = authority) => ({
  roster, signature: signRegistryStatement(witnessRosterBytes(roster), authorityKey),
  enrollments: roster.operators.map((operator, i) => ({ operatorId: operator.id,
    signature: signRegistryStatement(witnessEnrollmentBytes(roster, operator.id), keys[i]) })),
});
const signed = seal(roster, [a, b]);
const successor = {
  ...roster, generation: 2, previous: digest(roster), handoff: { epoch: 1, checkpointDigest: '61'.repeat(32) },
  operators: [{ ...roster.operators[0], publicKey: passportPublicKey(replacement) }, roster.operators[1]],
};
const signedSuccessor = seal(successor, [replacement, b]);
const rosterCase = (id, chain, expected = reject) => add(id, 'witness-roster-chain', { chain, trust }, expected);
rosterCase('roster-genesis', [signed], accept({ ...roster, rosterDigest: digest(roster), retiredKeys: [] }));
rosterCase('roster-single-key-handoff', [signed, signedSuccessor], accept({
  ...successor, rosterDigest: digest(successor), retiredKeys: [fp(a)],
}));
rosterCase('roster-skipped-genesis', [signedSuccessor]);
rosterCase('roster-untrusted-authority', [seal(roster, [a, b], origin)]);
rosterCase('roster-no-survivor-approval', [signed, seal(successor, [replacement, a])]);
rosterCase('roster-double-replacement', [signed, seal({
  ...successor, operators: [successor.operators[0], { ...roster.operators[1], publicKey: passportPublicKey(unrelated) }],
}, [replacement, unrelated])]);
rosterCase('roster-retired-key-returns', [signed, signedSuccessor, seal({
  ...roster, generation: 3, previous: digest(successor), handoff: { epoch: 2, checkpointDigest: '62'.repeat(32) },
}, [a, b])]);
rosterCase('roster-stale-handoff', [signed, signedSuccessor, seal({
  ...successor, generation: 3, previous: digest(successor),
  operators: [successor.operators[0], { ...roster.operators[1], publicKey: passportPublicKey(unrelated) }],
}, [replacement, unrelated])]);
process.stdout.write(JSON.stringify({ schema: 'kya.passport-vectors/v1', vectors }, null, 2) + '\n');
