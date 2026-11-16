import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, identifier, keyId, text, validatePublicPem } from '../identity/domain/services/validation.mjs';
import { verifyRegistrySignature } from './registry-checkpoint.mjs';

export function witnessRosterBytes(roster) {
  return Buffer.from('kya.witness-roster/v1\n' + canonical(roster), 'utf8');
}

export function witnessEnrollmentBytes(roster, operatorId) {
  return Buffer.from('kya.witness-enrollment/v1\n' + canonical({ rosterDigest: digest(roster), operatorId }), 'utf8');
}

// prior is the previously authenticated roster projection from local trust state.
export function verifyWitnessRoster(input, trust, prior = null) {
  const { registry, authorityPublicKey, originPublicKey } = trust;
  text(registry, 'Registry');
  validatePublicPem(authorityPublicKey);
  validatePublicPem(originPublicKey);
  const signed = JSON.parse(canonical(input));
  exactKeys(signed, ['roster', 'signature', 'enrollments'], 'Signed witness roster');
  const { roster, signature, enrollments } = signed;
  exactKeys(roster, ['schema', 'registry', 'originKeyId', 'generation', 'previous', 'operators', 'handoff'], 'Witness roster');
  insist(roster.schema === 'kya.witness-roster/v1' && roster.registry === registry
    && roster.originKeyId === keyId(originPublicKey), 'Witness roster scope mismatch');
  insist(Number.isSafeInteger(roster.generation) && roster.generation === (prior?.generation ?? 0) + 1
    && roster.previous === (prior?.rosterDigest ?? null), 'Witness roster predecessor mismatch');
  insist(Array.isArray(roster.operators) && roster.operators.length === 2
    && Array.isArray(enrollments) && enrollments.length === 2, 'Two witness operators required');
  const keys = new Set([keyId(originPublicKey), keyId(authorityPublicKey)]);
  insist(keys.size === 2, 'Authority and origin keys must differ');
  verifyRegistrySignature(witnessRosterBytes(roster), signature, authorityPublicKey);
  const operatorIds = [];
  for (const [i, operator] of roster.operators.entries()) {
    exactKeys(operator, ['id', 'publicKey'], 'Witness operator');
    identifier(operator.id, 'Operator ID');
    validatePublicPem(operator.publicKey);
    const id = keyId(operator.publicKey);
    insist(!keys.has(id) && (i === 0 || operator.id > operatorIds[i - 1]), 'Witness operators must be distinct and sorted');
    keys.add(id);
    operatorIds.push(operator.id);
    const enrollment = enrollments[i];
    exactKeys(enrollment, ['operatorId', 'signature'], 'Witness enrollment');
    insist(enrollment.operatorId === operator.id, 'Witness enrollment mismatch');
    verifyRegistrySignature(witnessEnrollmentBytes(roster, operator.id), enrollment.signature, operator.publicKey);
  }

  if (prior) {
    exactKeys(roster.handoff, ['epoch', 'checkpointDigest'], 'Witness handoff');
    hash(roster.handoff.checkpointDigest, 'Handoff checkpoint digest');
    insist(Number.isSafeInteger(roster.handoff.epoch) && roster.handoff.epoch >= (prior.handoff?.epoch ?? 0) + 1,
      'Invalid witness handoff epoch');
    insist(prior.operators.every((operator, i) => operator.id === operatorIds[i]), 'Witness operator identity changed');
    const changed = roster.operators.filter((operator, i) => operator.publicKey !== prior.operators[i].publicKey);
    insist(changed.length === 1, 'Replace one witness key at a time');
    const retiredKeys = new Set(prior.retiredKeys);
    insist(!retiredKeys.has(keyId(changed[0].publicKey)), 'Retired witness key');
    const retired = prior.operators.find((operator, i) => operator.publicKey !== roster.operators[i].publicKey);
    return { ...roster, rosterDigest: digest(roster), retiredKeys: [...retiredKeys, keyId(retired.publicKey)] };
  }
  insist(roster.handoff === null, 'Unexpected witness handoff');
  return { ...roster, rosterDigest: digest(roster), retiredKeys: [] };
}

export function witnessLookupTrust(roster, originPublicKey, checkpointPin) {
  insist(roster.originKeyId === keyId(originPublicKey), 'Witness roster scope mismatch');
  return {
    registry: roster.registry, originPublicKey, witnessPublicKeys: roster.operators.map(operator => operator.publicKey),
    ...(checkpointPin ? { checkpointPin } : {}),
    ...(roster.handoff ? { minimumEpoch: roster.handoff.epoch + 1 } : {}),
  };
}
