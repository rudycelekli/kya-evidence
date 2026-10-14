import { insist } from '../../shared/canonical.mjs';

// Stable, machine-readable refusal codes. A blocker withholds a qualification or names why a result
// is capped; the code never changes meaning, while the human text beside it may be reworded.
// Adapted idea: "refuse rather than default" with a named, machine-readable refusal (see ADR-0016).
export const BLOCKER_CODES = Object.freeze([
  'SUBJECT_REVOKED', 'SUBJECT_EXPIRED', 'SUBJECT_NOT_YET_VALID',
  'CRITICAL_CHECK_FAILED', 'CRITICAL_CHECK_UNPROVEN',
  'COVERAGE_BELOW_POLICY', 'INDEPENDENT_COVERAGE_BELOW_POLICY', 'SCORE_BELOW_POLICY',
  'AMBIGUOUS_RUNS', 'RUN_CONFLICT', 'RUN_INVALIDATED', 'MIXED_RUN_ISSUERS', 'REPEATED_RUN_CHECKS',
  'NO_SCORED_OBSERVATIONS', 'NO_OBSERVED_CHECKS', 'PRINCIPAL_UNBOUND', 'MANDATORY_MINIMUM_NOT_MET'
]);

// One stable code per monitoring trigger id; the id stays for existing consumers.
export const CURRENCY_CODES = Object.freeze({
  'clock-regression': 'CLOCK_REGRESSION', 'subject-changed': 'SUBJECT_CHANGED', 'policy-changed': 'POLICY_CHANGED',
  'subject-revoked': 'SUBJECT_REVOKED', 'assessment-expired': 'ASSESSMENT_EXPIRED', 'assessment-aged': 'ASSESSMENT_AGED',
  'incident-open': 'INCIDENT_OPEN'
});

// Reports written before blockerCodes existed omit the field and stay valid. When present it must be
// exactly one known code per human blocker, in the same order.
export function validateBlockerCodes(report) {
  if (!Object.hasOwn(report, 'blockerCodes')) return;
  const c = report.blockerCodes;
  insist(Array.isArray(c) && Array.isArray(report.blockers) && c.length === report.blockers.length && c.every(x => BLOCKER_CODES.includes(x)), 'Invalid blocker codes: expected one known code per blocker');
}
