import { createPrivateKey, createPublicKey, KeyObject, sign, verify } from 'node:crypto';
import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, identifier, keyId, publicKeyObject, text, validatePublicPem } from '../identity/domain/services/validation.mjs';

const schema = 'kya.passport-event/v1';
const recoverySchema = 'kya.passport-event/v2';
const fields = [
  'schema', 'operation', 'registry', 'passportId', 'previous', 'agentId',
  'principalId', 'controllerPublicKey', 'agentPublicKey', 'manifestDigest',
];
export const maxPassportEvents = 128;

export function passportId({ registry, agentId, principalId, controllerPublicKey, recoveryPublicKey }) {
  const identity = { schema: 'kya.passport-id/v1', registry, agentId, principalId, controllerKeyId: keyId(controllerPublicKey) };
  if (recoveryPublicKey === undefined) return digest(identity);
  return digest({ ...identity, schema: 'kya.passport-id/v2', recoveryKeyId: keyId(recoveryPublicKey) });
}

function eventBytes(event) {
  const prefix = event.schema === recoverySchema ? 'kya.passport-event/v2\n' : 'kya.passport-event/v1\n';
  return Buffer.from(prefix + canonical(event));
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
  const controllers = [];
  let previous = null;
  let initial;
  let current;
  for (const record of records) {
    const recoverable = record?.event?.schema === recoverySchema;
    const recordFields = ['event', 'controllerSignature', 'agentSignature'];
    exactKeys(record, recoverable ? [...recordFields, 'recoverySignature'] : recordFields, 'Passport record');
    const { event, controllerSignature, agentSignature, recoverySignature } = record;
    exactKeys(event, recoverable ? [...fields, 'recoveryPublicKey'] : fields, 'Passport event');
    const operations = ['register', 'rotate', 'revise', 'revoke'];
    if (recoverable) operations.push('recover');
    insist((event.schema === schema || recoverable) && operations.includes(event.operation), 'Invalid passport operation');
    text(event.registry, 'Registry');
    insist(event.registry === expectedRegistry, 'Registry mismatch');
    hash(event.passportId, 'Passport ID');
    hash(event.manifestDigest, 'Manifest digest');
    identifier(event.agentId, 'Agent ID');
    identifier(event.principalId, 'Principal ID');
    validatePublicPem(event.controllerPublicKey);
    const controllerKey = keyId(event.controllerPublicKey);
    insist(event.previous === previous, 'Passport history mismatch');
    checkSignature(event, controllerSignature, event.controllerPublicKey);

    if (!initial) {
      insist(event.operation === 'register', 'Registration required');
      if (recoverable) validatePublicPem(event.recoveryPublicKey);
      insist(event.passportId === passportId(event), 'Passport identity mismatch');
      initial = event;
      controllers.push(controllerKey);
    } else {
      insist(event.passportId === initial.passportId && event.operation !== 'register' && current !== null, 'Invalid passport transition');
      insist(event.schema === initial.schema && event.agentId === initial.agentId
        && event.principalId === initial.principalId && event.recoveryPublicKey === initial.recoveryPublicKey,
      'Passport identity mismatch');
      if (event.operation === 'recover') {
        insist(!controllers.includes(controllerKey) && !keys.includes(controllerKey), 'Controller key already used');
        controllers.push(controllerKey);
      } else {
        insist(controllerKey === controllers.at(-1), 'Controller key mismatch');
      }
    }

    if (recoverable) {
      const recoveryKey = keyId(event.recoveryPublicKey);
      insist(recoveryKey !== controllerKey, 'Recovery key must be separate');
      if (event.operation === 'register' || event.operation === 'recover') {
        checkSignature(event, recoverySignature, event.recoveryPublicKey);
      } else {
        insist(recoverySignature === null, 'Unexpected recovery signature');
      }
    }

    if (event.operation === 'revoke') {
      insist(event.agentPublicKey === null && agentSignature === null
        && event.manifestDigest === current.manifestDigest, 'Invalid revocation');
      current = null;
    } else {
      validatePublicPem(event.agentPublicKey);
      checkSignature(event, agentSignature, event.agentPublicKey);
      const fingerprint = keyId(event.agentPublicKey);
      insist(!controllers.includes(fingerprint), 'Controller and agent keys must differ');
      if (recoverable) insist(fingerprint !== keyId(event.recoveryPublicKey), 'Recovery key must be separate');
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
    passportId: initial.passportId, agentId: initial.agentId, principalId: initial.principalId,
    head: previous, status: current ? 'active' : 'revoked', current, fingerprints: keys,
    ...(initial.schema === recoverySchema ? { controllerFingerprint: controllers.at(-1), recoveryEnabled: true } : {}),
  };
}

export function passportPublicKey(privateKey) {
  return createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
}
