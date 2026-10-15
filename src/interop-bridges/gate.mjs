import { canonical, digest, insist } from '../shared/canonical.mjs';
import { verifyAssessment } from '../assessment/application/assess.mjs';
import { checkCurrency } from '../assessment/application/currency.mjs';
import { timestamp } from '../identity/domain/services/validation.mjs';

export class BridgeError extends Error {
  constructor(code, message) { super(`${code}: ${message}`); this.name = 'BridgeError'; this.code = code; }
}
export const fail = (code, message) => { throw new BridgeError(code, message); };

export const NOT_ASSERTED = Object.freeze(['human identity', 'authorization grant', 'truthful execution']);
// Stated on every export. These are properties of the export, not of the target ecosystem.
export const LIMITS = Object.freeze([
  'Not an authorization grant; a relying party decides what an assessment permits',
  'The report checksum is unauthenticated; it detects change, not who produced the report',
  'The export is unsigned; any signature, token or attestation envelope is the caller responsibility',
  'Currency was evaluated once, at the stated check time, against the supplied manifest, policy and incidents; it is not live',
  'No third-party tool has consumed this format; this is not a conformance claim with any outside specification'
]);
export const GATE_FLAGS = Object.freeze(['allowNonQualified', 'allowNotCurrent']);
const SHARED_OPTIONS = ['manifest', 'policy', 'now', 'incidents', ...GATE_FLAGS];

/** Copy only own enumerable string-keyed members into a null-prototype object, so a polluted Object.prototype or an inherited member never counts as an option. */
export function ownOptions(options) {
  const o = Object.create(null);
  if (options === null || typeof options !== 'object') return o;
  for (const k of Object.keys(options)) o[k] = options[k];
  return o;
}

/** Validates the option names and flag types and returns the own-property copy that every later read must use. */
export function checkOptions(options, extra = []) {
  insist(options && typeof options === 'object' && !Array.isArray(options), 'Options must be an object');
  const o = ownOptions(options);
  const allowed = new Set([...SHARED_OPTIONS, ...extra]);
  for (const k of Object.keys(o)) insist(allowed.has(k), `Unknown option ${k}`);
  for (const f of GATE_FLAGS) insist(o[f] === undefined || typeof o[f] === 'boolean', `${f} must be a boolean`);
  return o;
}

/** Report timestamps are validated whether or not currency is checked: a non-ISO or timezone dependent string must never reach an export. */
export function checkReportTimes(r) {
  timestamp(r.assessedAt, 'Assessment time');
  timestamp(r.validUntil, 'Assessment validity');
}

/**
 * Fail-closed gate shared by every export. Verifies the report checksum, then runs checkCurrency when manifest, policy and now are
 * supplied. A decision other than qualified is NOT_QUALIFIED unless allowNonQualified; a missing or reassess-required currency
 * check is CURRENCY_NOT_CHECKED or NOT_CURRENT unless allowNotCurrent. Any override actually used is recorded in currency.overrides.
 * There is no default clock: now is always explicit so output is reproducible.
 */
export function gate(assessment, rawOptions = {}) {
  const options = ownOptions(rawOptions);
  const r = JSON.parse(canonical(assessment));
  verifyAssessment(r);
  checkReportTimes(r);
  const overrides = [];
  if (r.decision !== 'qualified') {
    if (options.allowNonQualified !== true) fail('NOT_QUALIFIED', `Assessment decision is ${r.decision}; pass allowNonQualified to export it anyway`);
    overrides.push('allowNonQualified');
  }
  const have = ['manifest', 'policy', 'now'].map(k => options[k] !== undefined);
  let currency;
  if (have.every(Boolean)) {
    const c = checkCurrency(r, { manifest: options.manifest, policy: options.policy, now: options.now, incidents: options.incidents ?? [] });
    const triggerCodes = c.triggers.map(t => t.code).sort();
    if (!c.current) {
      if (options.allowNotCurrent !== true) fail('NOT_CURRENT', `Currency check fired ${triggerCodes.join(', ')}; reassess, or pass allowNotCurrent`);
      overrides.push('allowNotCurrent');
    }
    currency = { checked: true, current: c.current, reliable: c.reliable, checkedAt: c.checkedAt, triggerCodes, digest: digest(c), overrides: [] };
  } else {
    if (have.some(Boolean)) fail('CURRENCY_INPUTS_INCOMPLETE', 'manifest, policy and now must be supplied together');
    if (options.incidents !== undefined) fail('CURRENCY_INPUTS_INCOMPLETE', 'incidents need manifest, policy and now; they are not used on their own');
    if (options.allowNotCurrent !== true) fail('CURRENCY_NOT_CHECKED', 'No currency inputs supplied; pass manifest, policy and now, or allowNotCurrent');
    overrides.push('allowNotCurrent');
    currency = { checked: false, current: null, reliable: null, checkedAt: null, triggerCodes: [], digest: null, overrides: [] };
  }
  currency.overrides = [...new Set(overrides)].sort();
  return { report: r, currency };
}

// qualified is true only when the decision is qualified and a currency check ran and passed.
export const isQualified = (r, currency) => r.decision === 'qualified' && currency.current === true;

export function inputDigests(r) {
  return {
    subjectDigest: r.subjectDigest, profileDigest: r.profileDigest, policyDigest: r.policyDigest, evaluatorDigest: r.evaluatorDigest,
    evidenceBundleDigest: r.evidenceBundleDigest, acceptedEvidenceDigests: [...r.acceptedEvidenceDigests], reportDigest: r.reportDigest
  };
}
export const blockerCodesOf = r => Object.hasOwn(r, 'blockerCodes') ? [...r.blockerCodes] : null;

export function checkUrl(v, label) {
  const ok = typeof v === 'string' && /^https:\/\/[^\s"<>#/?]+[^\s"<>#]*$/.test(v) && v.length <= 2048 && !/^https:\/\/[^/?]*@/.test(v);
  let host = '';
  if (ok) { try { const u = new URL(v); host = u.hostname; if (u.username || u.password || u.hash) host = ''; } catch { host = ''; } }
  insist(ok && host !== '', `${label} must be an https URL with a host, no userinfo and no fragment`);
  return v;
}

/** Deterministic bytes of any export: KYA canonical JSON (sorted keys), one trailing newline. Not RFC 8785. */
export const serialize = value => canonical(value) + '\n';
