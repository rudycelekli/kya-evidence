import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { digest, hashBytes } from '../src/index.mjs';
import { keyId } from '../src/identity/domain/services/validation.mjs';
import * as pairing from '../src/pairing/index.mjs';

const principal = generateKeyPairSync('ed25519');
const agent = generateKeyPairSync('ed25519');
const manifest = JSON.parse(readFileSync(new URL('../examples/manifest.json', import.meta.url)));
manifest.issuedAt = '2026-11-14T13:00:00.000Z';
manifest.expiresAt = '2026-11-14T15:00:00.000Z';
manifest.scope.permissions.push('read:pairing-fixture');
const permission = 'read:pairing-fixture';
const requestDigest = hashBytes('fixture request');
const grant = {
  schema: 'kya.pairing-grant/v1',
  principalId: manifest.principal.id,
  agentKeyId: keyId(agent.publicKey),
  manifestDigest: digest(manifest),
  audience: 'fixture:gateway',
  permission,
  issuedAt: '2026-11-14T13:50:00.000Z',
  expiresAt: '2026-11-14T14:10:00.000Z',
};

function fixture() {
  const signedGrant = pairing.signPairingGrant(grant, principal.privateKey);
  const action = {
    schema: 'kya.paired-action/v1',
    grantDigest: digest(signedGrant),
    challenge: 'ab'.repeat(32),
    requestDigest,
  };
  const proof = {
    grant: signedGrant,
    action: pairing.signPairedAction(action, agent.privateKey),
  };
  const context = {
    manifest,
    principalId: grant.principalId,
    principalKeyId: keyId(principal.publicKey),
    audience: grant.audience,
    permission,
    challenge: action.challenge,
    requestDigest,
    now: '2026-11-14T14:00:00.000Z',
    revokedKeyIds: [],
    revokedGrantDigests: [],
  };
  return { proof, context, action };
}

test('verifies both keys and returns stable tracking identifiers', () => {
  const { proof, context } = fixture();
  const result = pairing.verifyPairedAction(proof, context);
  assert.deepEqual(result, {
    principalId: grant.principalId,
    principalKeyId: context.principalKeyId,
    agentId: manifest.agent.id,
    agentKeyId: grant.agentKeyId,
    manifestDigest: grant.manifestDigest,
    grantDigest: digest(proof.grant),
    actionDigest: digest(proof.action),
  });
});

const mismatches = {
  principalId: 'another-user',
  principalKeyId: grant.agentKeyId,
  audience: 'other:gateway',
  permission: 'write',
  challenge: 'cd'.repeat(32),
  requestDigest: hashBytes('different request'),
  now: grant.expiresAt,
  manifest: { ...manifest, system: { ...manifest.system, configDigest: '12'.repeat(32) } },
  revokedKeyIds: [grant.agentKeyId],
};

for (const [field, value] of Object.entries(mismatches)) {
  test(`rejects changed ${field}`, () => {
    const { proof, context } = fixture();
    assert.throws(() => pairing.verifyPairedAction(proof, { ...context, [field]: value }));
  });
}

test('rejects a revoked grant', () => {
  const { proof, context } = fixture();
  context.revokedGrantDigests = [digest(proof.grant)];
  assert.throws(() => pairing.verifyPairedAction(proof, context), /revoked/i);
});

test('rejects a valid signature from a substituted agent key', () => {
  const { proof, context, action } = fixture();
  const substituted = generateKeyPairSync('ed25519');
  proof.action = pairing.signPairedAction(action, substituted.privateKey);
  assert.throws(() => pairing.verifyPairedAction(proof, context), /agent key/i);
});

test('requires distinct principal and agent keys', () => {
  const { proof, context, action } = fixture();
  proof.grant = pairing.signPairingGrant({ ...grant, agentKeyId: context.principalKeyId }, principal.privateKey);
  proof.action = pairing.signPairedAction({ ...action, grantDigest: digest(proof.grant) }, principal.privateKey);
  assert.throws(() => pairing.verifyPairedAction(proof, context), /agent key/i);
});

test('rejects a valid action from a different signed grant', () => {
  const { proof, context } = fixture();
  proof.grant = pairing.signPairingGrant({ ...grant, expiresAt: '2026-11-14T14:11:00.000Z' }, principal.privateKey);
  assert.throws(() => pairing.verifyPairedAction(proof, context), /grant digest/i);
});

test('rejects tampering with either signed payload', () => {
  const { proof, context } = fixture();
  proof.grant.payload.expiresAt = '2026-11-14T14:11:00.000Z';
  assert.throws(() => pairing.verifyPairedAction(proof, context), /signature/i);
  const second = fixture();
  second.proof.action.payload.requestDigest = hashBytes('swapped bytes');
  assert.throws(() => pairing.verifyPairedAction(second.proof, second.context), /signature/i);
});

test('rejects grants that need separate per-action approval', () => {
  const { proof, context, action } = fixture();
  context.manifest = {
    ...manifest,
    scope: { ...manifest.scope, approvalRequired: [...manifest.scope.approvalRequired, permission] },
  };
  proof.grant = pairing.signPairingGrant({ ...grant, manifestDigest: digest(context.manifest) }, principal.privateKey);
  proof.action = pairing.signPairedAction({ ...action, grantDigest: digest(proof.grant) }, agent.privateKey);
  assert.throws(() => pairing.verifyPairedAction(proof, context), /approval/i);
});

test('rejects policy input accessors without calling them', () => {
  const { proof, context } = fixture();
  let read = false;
  Object.defineProperty(context, 'audience', { enumerable: true, get() { read = true; return grant.audience; } });
  assert.throws(() => pairing.verifyPairedAction(proof, context), /accessor/i);
  assert.equal(read, false);
});

test('replays the frozen wire vector against the packaged entry point', async () => {
  const sdk = await import('kya-evidence/pairing');
  const { proof, context, expected, requestUtf8 } = JSON.parse(
    readFileSync(new URL('../examples/pairing-vector.json', import.meta.url)),
  );
  assert.equal(hashBytes(requestUtf8), context.requestDigest);
  assert.deepEqual(sdk.verifyPairedAction(proof, context), expected);
});
