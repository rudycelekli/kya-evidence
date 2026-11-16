import { verify } from 'node:crypto';
import { canonical, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, publicKeyObject, text, timestamp, validatePublicPem } from '../identity/domain/services/validation.mjs';
import { maxPassportEvents, verifyPassport } from './index.mjs';

export function passportCheckpointBytes(checkpoint) {
  return Buffer.from('kya.passport-checkpoint/v1\n' + canonical(checkpoint), 'utf8');
}

export function verifyPassportCheckpoint(input, trust, now) {
  const bundle = JSON.parse(canonical(input));
  exactKeys(bundle, ['checkpoint', 'signature', 'history'], 'Passport checkpoint bundle');
  const { checkpoint, signature, history } = bundle;
  exactKeys(checkpoint, ['schema', 'registry', 'passportId', 'head', 'sequence', 'issuedAt', 'expiresAt'], 'Passport checkpoint');
  insist(checkpoint.schema === 'kya.passport-checkpoint/v1', 'Invalid checkpoint schema');
  text(trust.registry, 'Registry');
  insist(checkpoint.registry === trust.registry, 'Registry mismatch');
  validatePublicPem(trust.publicKey);
  hash(checkpoint.passportId, 'Passport ID');
  hash(checkpoint.head, 'Checkpoint head');
  insist(Number.isInteger(checkpoint.sequence) && checkpoint.sequence > 0
    && checkpoint.sequence <= maxPassportEvents, 'Invalid checkpoint sequence');
  const issued = timestamp(checkpoint.issuedAt);
  const expires = timestamp(checkpoint.expiresAt);
  const time = timestamp(now);
  insist(issued <= time && time < expires && expires - issued <= 300_000, 'Checkpoint outside freshness window');
  insist(typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), 'Invalid checkpoint signature');
  const bytes = Buffer.from(signature, 'base64url');
  insist(bytes.toString('base64url') === signature && verify(null, passportCheckpointBytes(checkpoint),
    publicKeyObject(trust.publicKey), bytes), 'Invalid checkpoint signature');
  const passport = verifyPassport(history, trust.registry);
  insist(passport.passportId === checkpoint.passportId && passport.head === checkpoint.head
    && history.length === checkpoint.sequence, 'Checkpoint history mismatch');
  return { ...bundle, passport };
}
