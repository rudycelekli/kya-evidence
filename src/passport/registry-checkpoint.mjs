import { createPrivateKey, KeyObject, sign, verify } from 'node:crypto';
import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, keyId, publicKeyObject, text, timestamp, validatePublicPem } from '../identity/domain/services/validation.mjs';
import { verifyPassportRegistryLookup } from './registry-proof.mjs';

const schema = 'kya.registry-checkpoint/v1';

export function registryCheckpointBytes(checkpoint) {
  return Buffer.from('kya.registry-checkpoint/v1\n' + canonical(checkpoint), 'utf8');
}

export function registryWitnessBytes(checkpoint) {
  return Buffer.from('kya.registry-witness/v1\n' + canonical(checkpoint), 'utf8');
}

export function signRegistryStatement(bytes, privateKey) {
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  insist(key.type === 'private' && key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 private key');
  return sign(null, bytes, key).toString('base64url');
}

function authenticate(bytes, signature, pem) {
  validatePublicPem(pem);
  insist(typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), 'Invalid registry signature');
  const raw = Buffer.from(signature, 'base64url');
  insist(raw.toString('base64url') === signature && verify(null, bytes, publicKeyObject(pem), raw),
    'Invalid registry signature');
}

export function verifyRegistryCheckpoint(input, { registry, originPublicKey }, now) {
  const signed = JSON.parse(canonical(input));
  exactKeys(signed, ['checkpoint', 'signature'], 'Signed registry checkpoint');
  const { checkpoint, signature } = signed;
  exactKeys(checkpoint, ['schema', 'registry', 'epoch', 'previous', 'root', 'count', 'issuedAt', 'expiresAt'], 'Registry checkpoint');
  text(registry, 'Registry');
  insist(checkpoint.schema === schema && checkpoint.registry === registry, 'Registry checkpoint mismatch');
  insist(Number.isSafeInteger(checkpoint.epoch) && checkpoint.epoch >= 1, 'Invalid checkpoint epoch');
  if (checkpoint.epoch === 1) insist(checkpoint.previous === null, 'Invalid checkpoint predecessor');
  else hash(checkpoint.previous, 'Checkpoint predecessor');
  hash(checkpoint.root, 'Registry root');
  insist(Number.isInteger(checkpoint.count) && checkpoint.count >= 0 && checkpoint.count <= 1_000_000, 'Invalid registry count');
  const start = timestamp(checkpoint.issuedAt);
  const end = timestamp(checkpoint.expiresAt);
  const time = timestamp(now);
  insist(start <= time && time < end && end - start <= 300_000, 'Checkpoint outside freshness window');
  authenticate(registryCheckpointBytes(checkpoint), signature, originPublicKey);
  return { checkpoint, checkpointDigest: digest(checkpoint) };
}

export function verifyWitnessedLookup(query, proof, signed, endorsements, trust, now) {
  const { checkpoint, checkpointDigest } = verifyRegistryCheckpoint(signed, trust, now);
  const { witnessPublicKeys, checkpointPin } = trust;
  if (checkpointPin !== undefined) {
    exactKeys(checkpointPin, ['epoch', 'checkpointDigest'], 'Registry checkpoint pin');
    hash(checkpointPin.checkpointDigest, 'Pinned checkpoint digest');
    insist(Number.isSafeInteger(checkpointPin.epoch) && checkpointPin.epoch >= 1
      && (checkpoint.epoch > checkpointPin.epoch
        || (checkpoint.epoch === checkpointPin.epoch && checkpointDigest === checkpointPin.checkpointDigest)),
    'Registry checkpoint rolled back or forked');
  }
  insist(Array.isArray(witnessPublicKeys) && witnessPublicKeys.length >= 2 && witnessPublicKeys.length <= 16
    && Array.isArray(endorsements) && endorsements.length === witnessPublicKeys.length, 'Witness set incomplete');
  const pinned = new Map();
  const origin = keyId(trust.originPublicKey);
  for (const pem of witnessPublicKeys) {
    validatePublicPem(pem);
    const id = keyId(pem);
    insist(id !== origin && !pinned.has(id), 'Witness keys must be distinct');
    pinned.set(id, pem);
  }
  const witnessBytes = registryWitnessBytes(checkpoint);
  for (const proof of JSON.parse(canonical(endorsements))) {
    exactKeys(proof, ['witnessId', 'checkpointDigest', 'signature'], 'Registry endorsement');
    const key = pinned.get(proof.witnessId);
    insist(key && proof.checkpointDigest === checkpointDigest, 'Registry endorsement mismatch');
    authenticate(witnessBytes, proof.signature, key);
    pinned.delete(proof.witnessId);
  }
  return { checkpointDigest, epoch: checkpoint.epoch,
    value: verifyPassportRegistryLookup(query, proof, checkpoint.root, checkpoint.count) };
}
