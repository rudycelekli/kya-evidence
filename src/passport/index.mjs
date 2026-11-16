import { createPrivateKey, createPublicKey, KeyObject, sign, verify } from 'node:crypto';
import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, identifier, keyId, publicKeyObject, text, validatePublicPem } from '../identity/domain/services/validation.mjs';

const schema = 'kya.passport-event/v1';
const fields = [
  'schema', 'operation', 'registry', 'passportId', 'previous', 'agentId',
  'principalId', 'controllerPublicKey', 'agentPublicKey', 'manifestDigest',
];
export const maxPassportEvents = 128;

export function passportId({ registry, agentId, principalId, controllerPublicKey }) {
  return digest({ schema: 'kya.passport-id/v1', registry, agentId, principalId, controllerKeyId: keyId(controllerPublicKey) });
}

function eventBytes(event) {
  return Buffer.from('kya.passport-event/v1\n' + canonical(event));
}

export function signPassportEvent(event, privateKey) {
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  insist(key.type === 'private' && key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 private key');
  return sign(null, eventBytes(event), key).toString('base64url');
}

function checkSignature(event, signature, publicKey) {
  insist(typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), 'Invalid passport signature');
  const bytes = Buffer.from(signature, 'base64url');
  insist(bytes.toString('base64url') === signature
    && verify(null, eventBytes(event), publicKeyObject(publicKey), bytes), 'Invalid passport signature');
}

export function verifyPassport(history, expectedRegistry) {
  insist(Array.isArray(history) && history.length > 0 && history.length <= maxPassportEvents, 'Invalid passport history');
  const records = JSON.parse(canonical(history));
  const keys = [];
  let previous = null;
  let initial;
  let current;
  for (const record of records) {
    exactKeys(record, ['event', 'controllerSignature', 'agentSignature'], 'Passport record');
    const { event, controllerSignature, agentSignature } = record;
    exactKeys(event, fields, 'Passport event');
    insist(event.schema === schema && ['register', 'rotate', 'revise', 'revoke'].includes(event.operation), 'Invalid passport operation');
    text(event.registry, 'Registry');
    insist(event.registry === expectedRegistry, 'Registry mismatch');
    hash(event.passportId, 'Passport ID');
    hash(event.manifestDigest, 'Manifest digest');
    identifier(event.agentId, 'Agent ID');
    identifier(event.principalId, 'Principal ID');
    validatePublicPem(event.controllerPublicKey);
    insist(event.passportId === passportId(event), 'Passport identity mismatch');
    insist(event.previous === previous, 'Passport history mismatch');
    checkSignature(event, controllerSignature, event.controllerPublicKey);

    if (initial === undefined) {
      insist(event.operation === 'register', 'Registration required');
      initial = event.passportId;
    } else {
      insist(event.passportId === initial && event.operation !== 'register' && current !== null, 'Invalid passport transition');
    }

    if (event.operation === 'revoke') {
      insist(event.agentPublicKey === null && agentSignature === null
        && event.manifestDigest === current.manifestDigest, 'Invalid revocation');
      current = null;
    } else {
      validatePublicPem(event.agentPublicKey);
      checkSignature(event, agentSignature, event.agentPublicKey);
      const fingerprint = keyId(event.agentPublicKey);
      insist(fingerprint !== keyId(event.controllerPublicKey), 'Controller and agent keys must differ');
      if (event.operation === 'revise') {
        insist(fingerprint === current.fingerprint && event.manifestDigest !== current.manifestDigest, 'Invalid passport revision');
      } else {
        insist(!keys.includes(fingerprint), 'Agent key already used');
        keys.push(fingerprint);
      }
      current = { fingerprint, manifestDigest: event.manifestDigest };
    }
    previous = digest(record);
  }
  insist(records.length < maxPassportEvents || current === null, 'Final slot reserved for revocation');
  return {
    passportId: initial, agentId: records[0].event.agentId, principalId: records[0].event.principalId,
    head: previous, status: current ? 'active' : 'revoked', current, fingerprints: keys,
  };
}

export function passportPublicKey(privateKey) {
  return createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
}
