import { insist } from '../../shared/canonical.mjs';
import { hasUnsafe } from '../../shared/terminal.mjs';
import { identifier } from '../../identity/domain/services/validation.mjs';

export const REPORT_DECISIONS = Object.freeze(['qualified', 'blocked', 'insufficient-evidence', 'expired', 'revoked']);
export const REPORT_EVIDENCE_MODES = Object.freeze(['none', 'mixed', 'runtime', 'fixture', 'declaration']);

const count = (v, label) => insist(Number.isSafeInteger(v) && v >= 0 && v <= 1_000_000, `Report ${label} must be a non-negative integer`);
const ratio = (v, label) => insist(typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1, `Report ${label} must be a number from 0 to 1`);

/**
 * The members that an export copies verbatim must stay inside the vocabulary the assessor produces. A report checksum is not
 * a signature, so a self-digested report can carry any string; an export must not relay free text, control characters or
 * out-of-range numbers into a downstream parser, log or terminal. Throws on the first violation.
 */
export function checkReportFields(r) {
  insist(r && typeof r === 'object' && !Array.isArray(r), 'Report must be an object');
  insist(REPORT_DECISIONS.includes(r.decision), 'Report decision is outside the known vocabulary');
  insist(REPORT_EVIDENCE_MODES.includes(r.evidenceMode), 'Report evidenceMode is outside the known vocabulary');
  identifier(r.scopeId, 'scopeId');
  identifier(r.profileId, 'profileId');
  if (r.selectedRunId !== null) identifier(r.selectedRunId, 'selectedRunId');
  insist(Array.isArray(r.limitations) && r.limitations.length <= 512 && r.limitations.every(s => typeof s === 'string' && s.length <= 2048 && !hasUnsafe(s)), 'Report limitations must be a bounded list of plain text');
  insist(r.score && typeof r.score === 'object' && !Array.isArray(r.score), 'Report score must be an object');
  for (const k of ['earned', 'possible', 'upperBound']) count(r.score[k], `score.${k}`);
  ratio(r.coverage, 'coverage');
  ratio(r.independentCoverage, 'independentCoverage');
}
