import { gate, checkOptions, isQualified, blockerCodesOf } from './gate.mjs';

/**
 * Attribute table. Names are lowercase dot-separated under the kya. namespace, in the style of OpenTelemetry semantic conventions.
 * Nothing here is registered with or reviewed by the OpenTelemetry project. Types: string, boolean, int, double, string[].
 * Attributes whose source is null (for example a legacy report with no blocker codes) are omitted; there is no null attribute value.
 */
export const OTEL_ATTRIBUTES = Object.freeze([
  { name: 'kya.assessment.digest', type: 'string', source: 'report.reportDigest', note: 'SHA-256 of the canonical report body' },
  { name: 'kya.assessment.authenticated', type: 'boolean', source: 'constant false', note: 'The report checksum is not a signature' },
  { name: 'kya.assessment.valid_until', type: 'string', source: 'report.validUntil', note: 'UTC timestamp' },
  { name: 'kya.subject.digest', type: 'string', source: 'report.subjectDigest', note: 'Manifest digest' },
  { name: 'kya.policy.digest', type: 'string', source: 'report.policyDigest', note: 'Policy digest' },
  { name: 'kya.evaluator.digest', type: 'string', source: 'report.evaluatorDigest', note: 'Evaluator digest' },
  { name: 'kya.decision', type: 'string', source: 'report.decision', note: 'qualified, insufficient-evidence, blocked, expired or revoked' },
  { name: 'kya.qualified', type: 'boolean', source: 'decision qualified and currency current', note: 'False whenever currency was not checked' },
  { name: 'kya.evidence.mode', type: 'string', source: 'report.evidenceMode', note: 'none, mixed, runtime, fixture or declaration' },
  { name: 'kya.score.earned', type: 'int', source: 'report.score.earned', note: 'Points earned' },
  { name: 'kya.score.possible', type: 'int', source: 'report.score.possible', note: 'Points possible' },
  { name: 'kya.score.upper_bound', type: 'int', source: 'report.score.upperBound', note: 'Score if every unknown check passed' },
  { name: 'kya.coverage', type: 'double', source: 'report.coverage', note: '0 to 1' },
  { name: 'kya.coverage.independent', type: 'double', source: 'report.independentCoverage', note: '0 to 1' },
  { name: 'kya.blocker.codes', type: 'string[]', source: 'report.blockerCodes', note: 'Omitted for legacy reports' },
  { name: 'kya.currency.checked', type: 'boolean', source: 'currency.checked', note: 'Whether a currency check ran at export' },
  { name: 'kya.currency.current', type: 'boolean', source: 'currency.current', note: 'Omitted when not checked' },
  { name: 'kya.currency.reliable', type: 'boolean', source: 'currency.reliable', note: 'Omitted when not checked' },
  { name: 'kya.currency.checked_at', type: 'string', source: 'currency.checkedAt', note: 'Omitted when not checked' },
  { name: 'kya.currency.trigger.codes', type: 'string[]', source: 'currency.triggerCodes', note: 'Empty when current' },
  { name: 'kya.currency.digest', type: 'string', source: 'digest of the currency result', note: 'Omitted when not checked' },
  { name: 'kya.gate.overrides', type: 'string[]', source: 'currency.overrides', note: 'allowNonQualified and allowNotCurrent actually used' },
  { name: 'kya.authorization.granted', type: 'boolean', source: 'constant false', note: 'An assessment is not an authorization grant' }
]);
export const OTEL_ATTRIBUTE_NAMES = Object.freeze(OTEL_ATTRIBUTES.map(a => a.name));

export function buildAttributes(r, c) {
  const a = {
    'kya.assessment.digest': r.reportDigest, 'kya.assessment.authenticated': false, 'kya.assessment.valid_until': r.validUntil,
    'kya.subject.digest': r.subjectDigest, 'kya.policy.digest': r.policyDigest, 'kya.evaluator.digest': r.evaluatorDigest,
    'kya.decision': r.decision, 'kya.qualified': isQualified(r, c), 'kya.evidence.mode': r.evidenceMode,
    'kya.score.earned': r.score.earned, 'kya.score.possible': r.score.possible, 'kya.score.upper_bound': r.score.upperBound,
    'kya.coverage': r.coverage, 'kya.coverage.independent': r.independentCoverage,
    'kya.currency.checked': c.checked, 'kya.currency.trigger.codes': [...c.triggerCodes], 'kya.gate.overrides': [...c.overrides],
    'kya.authorization.granted': false
  };
  const codes = blockerCodesOf(r);
  if (codes) a['kya.blocker.codes'] = codes;
  if (c.checked) Object.assign(a, { 'kya.currency.current': c.current, 'kya.currency.reliable': c.reliable, 'kya.currency.checked_at': c.checkedAt, 'kya.currency.digest': c.digest });
  return Object.fromEntries(Object.keys(a).sort().map(k => [k, a[k]]));
}

/** Recover the currency block from an attribute map (used by the report-only cross-check). */
export function currencyFromAttributes(a) {
  const checked = a['kya.currency.checked'];
  return {
    checked, current: checked ? a['kya.currency.current'] : null, reliable: checked ? a['kya.currency.reliable'] : null,
    checkedAt: checked ? a['kya.currency.checked_at'] : null, triggerCodes: a['kya.currency.trigger.codes'], digest: checked ? a['kya.currency.digest'] : null,
    overrides: a['kya.gate.overrides']
  };
}

/** Emit a plain attribute map (no OpenTelemetry package). Fails closed like every export. */
export function exportOtelAttributes(assessment, options = {}) {
  checkOptions(options);
  const { report, currency } = gate(assessment, options);
  return buildAttributes(report, currency);
}
