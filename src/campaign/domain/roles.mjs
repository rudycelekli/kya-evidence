import { insist } from '../../shared/canonical.mjs';
import { validatePolicy } from '../../identity/domain/services/validation.mjs';

/**
 * A capture-issuer anchor may sign campaign plans, ledgers and capture records. It is never an evidence
 * issuer for scoring, never satisfies independence and cannot be the evaluator key (ADR-0021).
 * Returns the capture-issuer key IDs. Throws when the policy and the supplied signers conflict.
 */
export function verifyCaptureIssuerPolicy({ policy, evidenceKeyIds = [], evaluatorKeyId = null, requireIssuer = false } = {}) {
  const valid = validatePolicy(policy);
  const issuers = valid.trustedKeys.filter(k => k.role === 'capture-issuer').map(k => k.id);
  insist(!requireIssuer || issuers.length > 0, 'Policy lists no capture-issuer anchor');
  for (const id of issuers) {
    insist(!evidenceKeyIds.includes(id), 'A capture-issuer key cannot sign scoring evidence');
    insist(evaluatorKeyId !== id, 'A capture-issuer key cannot be the evaluator key');
  }
  return issuers;
}
