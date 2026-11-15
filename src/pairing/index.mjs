import { createPrivateKey, createPublicKey, KeyObject, sign, verify } from 'node:crypto';
import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, identifier, keyId, list, publicKeyObject, timestamp, validateManifest, validatePublicPem } from '../identity/domain/services/validation.mjs';

const GRANT = 'kya.pairing-grant/v1';
const ACTION = 'kya.paired-action/v1';

function validateGrant(payload) {
  exactKeys(payload, ['schema', 'principalId', 'agentKeyId', 'manifestDigest', 'audience', 'permission', 'issuedAt', 'expiresAt'], 'Pairing grant');
  insist(payload.schema === GRANT, 'Unsupported pairing grant schema');
  identifier(payload.principalId, 'Principal ID');
  hash(payload.agentKeyId, 'Agent key ID');
  hash(payload.manifestDigest, 'Manifest digest');
  identifier(payload.audience, 'Audience');
  identifier(payload.permission, 'Permission');
  const start = timestamp(payload.issuedAt, 'Grant issuance');
  const end = timestamp(payload.expiresAt, 'Grant expiry');
  insist(end > start && end - start <= 3_600_000, 'Grant lifetime must be positive and at most one hour');
}

function validateAction(payload) {
  exactKeys(payload, ['schema', 'grantDigest', 'challenge', 'requestDigest'], 'Paired action');
  insist(payload.schema === ACTION, 'Unsupported paired action schema');
  hash(payload.grantDigest, 'Grant digest');
  hash(payload.challenge, 'Challenge');
  hash(payload.requestDigest, 'Request digest');
}

function signedBytes(payload) {
  return Buffer.from(payload.schema + '\n' + canonical(payload), 'utf8');
}

function signEnvelope(input, privateKey, validate) {
  const payload = JSON.parse(canonical(input));
  validate(payload);
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  insist(key.type === 'private' && key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 private key');
  const publicKey = createPublicKey(key).export({ format: 'pem', type: 'spki' }).toString();
  validatePublicPem(publicKey);
  return { payload, publicKey, signature: sign(null, signedBytes(payload), key).toString('base64url') };
}

function authenticate(envelope, validate) {
  exactKeys(envelope, ['payload', 'publicKey', 'signature'], 'Pairing envelope');
  validate(envelope.payload);
  validatePublicPem(envelope.publicKey);
  const { signature, payload } = envelope;
  insist(typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), 'Invalid signature encoding');
  const bytes = Buffer.from(signature, 'base64url');
  insist(bytes.length === 64 && bytes.toString('base64url') === signature, 'Noncanonical signature encoding');
  const publicKey = publicKeyObject(envelope.publicKey);
  insist(verify(null, signedBytes(payload), publicKey, bytes), 'Pairing signature verification failed');
  return keyId(publicKey);
}

export function signPairingGrant(payload, privateKey) {
  return signEnvelope(payload, privateKey, validateGrant);
}

export function signPairedAction(payload, privateKey) {
  return signEnvelope(payload, privateKey, validateAction);
}

export function verifyPairedAction(input, relyingContext) {
  const proof = JSON.parse(canonical(input));
  const context = JSON.parse(canonical(relyingContext));
  exactKeys(proof, ['grant', 'action'], 'Paired action proof');
  exactKeys(context, ['manifest', 'principalId', 'principalKeyId', 'audience', 'permission', 'challenge', 'requestDigest', 'now', 'revokedKeyIds', 'revokedGrantDigests'], 'Relying context');

  const manifest = validateManifest(context.manifest);
  hash(context.principalKeyId, 'Trusted principal key');
  list(context.revokedKeyIds, 'Revoked keys', 4096, hash);
  list(context.revokedGrantDigests, 'Revoked grants', 4096, hash);
  const now = timestamp(context.now, 'Relying clock');
  const principalKeyId = authenticate(proof.grant, validateGrant);
  const agentKeyId = authenticate(proof.action, validateAction);
  const grant = proof.grant.payload;
  const action = proof.action.payload;
  const manifestDigest = digest(manifest);
  const grantDigest = digest(proof.grant);

  insist(principalKeyId === context.principalKeyId && grant.principalId === context.principalId
    && grant.principalId === manifest.principal.id, 'Principal binding differs');
  insist(agentKeyId !== principalKeyId && agentKeyId === grant.agentKeyId, 'Agent key binding differs');
  insist(grant.manifestDigest === manifestDigest, 'Manifest digest differs');
  insist(grant.audience === context.audience, 'Audience differs');
  insist(grant.permission === context.permission && manifest.scope.permissions.includes(grant.permission), 'Permission differs or is outside scope');
  insist(!manifest.scope.approvalRequired.includes(grant.permission), 'Permission requires separate action approval');
  insist(action.grantDigest === grantDigest, 'Grant digest differs');
  insist(action.challenge === context.challenge && action.requestDigest === context.requestDigest, 'Action challenge or request digest differs');
  insist(!context.revokedKeyIds.includes(principalKeyId) && !context.revokedKeyIds.includes(agentKeyId)
    && !context.revokedGrantDigests.includes(grantDigest), 'Pairing key or grant revoked');

  const start = timestamp(grant.issuedAt);
  const end = timestamp(grant.expiresAt);
  insist(start >= timestamp(manifest.issuedAt) && end <= timestamp(manifest.expiresAt)
    && now >= start && now < end, 'Pairing grant is outside its validity window');

  return {
    principalId: grant.principalId,
    principalKeyId,
    agentId: manifest.agent.id,
    agentKeyId,
    manifestDigest,
    grantDigest,
    actionDigest: digest(proof.action),
  };
}
