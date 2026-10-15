import { gate, checkOptions, isQualified, inputDigests, blockerCodesOf, LIMITS, NOT_ASSERTED } from './gate.mjs';

export const INTOTO_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
// A URN chosen by this project. It is not registered with any in-toto predicate registry.
export const KYA_PREDICATE_TYPE = 'urn:kya:predicate:assessment:v1';

export function buildStatement(r, currency) {
  return {
    _type: INTOTO_STATEMENT_TYPE,
    subject: [{ name: `urn:kya:subject:sha256:${r.subjectDigest}`, digest: { sha256: r.subjectDigest } }],
    predicateType: KYA_PREDICATE_TYPE,
    predicate: {
      assessedAt: r.assessedAt, validUntil: r.validUntil, scopeId: r.scopeId, profileId: r.profileId, selectedRunId: r.selectedRunId,
      decision: r.decision, qualified: isQualified(r, currency),
      scores: { earned: r.score.earned, possible: r.score.possible, upperBound: r.score.upperBound, coverage: r.coverage, independentCoverage: r.independentCoverage },
      evidenceMode: r.evidenceMode, blockerCodes: blockerCodesOf(r),
      inputDigests: inputDigests(r), currency: { ...currency, triggerCodes: [...currency.triggerCodes], overrides: [...currency.overrides] },
      limitations: [...r.limitations], limits: [...LIMITS], notAsserted: [...NOT_ASSERTED]
    }
  };
}

/**
 * Export an assessment as an unsigned in-toto Statement v1 whose subject is the manifest digest. Fails closed on a non-qualified or
 * non-current assessment unless allowNonQualified or allowNotCurrent is passed. No DSSE envelope is produced and no signature is made.
 */
export function exportInTotoStatement(assessment, options = {}) {
  checkOptions(options);
  const { report, currency } = gate(assessment, options);
  return buildStatement(report, currency);
}
