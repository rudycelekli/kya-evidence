import { canonical } from '../shared/canonical.mjs';

export const SUITE_SCHEMA = 'kya.scenario-suite/v1';
export const FINAL_STATUSES = Object.freeze(['completed', 'refused', 'needs-approval', 'recovered']);
export const SEVERITIES = Object.freeze(['low', 'medium', 'high', 'critical']);
export const PROVENANCE = Object.freeze(['authored', 'incident-reconstruction']);
export const DISCLAIMER_PHRASES = Object.freeze(['synthetic reconstruction', 'public accounts', 'not a test of any named company or product']);
const LIMITS = Object.freeze({ scenarios: 256, predicates: 32, strings: 64, text: 4096 });
const ID = /^[a-z0-9][a-z0-9.-]{0,62}[a-z0-9]$/u;

function plain(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError(`${label}: expected plain object`);
}
function exact(value, keys, required, label) {
  plain(value, label);
  for (const key of Object.keys(value)) if (!keys.includes(key)) throw new TypeError(`${label}: unexpected field ${key}`);
  for (const key of required) if (!Object.hasOwn(value, key)) throw new TypeError(`${label}: missing field ${key}`);
}
function text(value, label, max = LIMITS.text) {
  if (typeof value !== 'string' || !value || value.length > max || /[\x00-\x08\x0b\x0c\x0e-\x1f]/u.test(value)) throw new TypeError(`${label}: invalid string`);
}
function stringList(value, label, { min = 0 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > LIMITS.strings) throw new TypeError(`${label}: invalid list`);
  value.forEach(item => text(item, label, 512));
  if (new Set(value).size !== value.length) throw new TypeError(`${label}: duplicate entries`);
}
// Predicates are checked for list shape only here; an unknown or malformed predicate is a fail-closed evaluation error (evaluator.mjs).
function predicateList(value, label) {
  if (!Array.isArray(value) || value.length > LIMITS.predicates) throw new TypeError(`${label}: invalid predicate list`);
}

/** Strict structural validation. Returns a deep, JSON-normalised copy so accessors and proxies never reach the evaluator. */
export function validateSuite(input) {
  let suite;
  try { suite = JSON.parse(canonical(input)); } catch { throw new TypeError('Suite is not canonical JSON within resource limits'); }
  exact(suite, ['schema', 'suiteId', 'version', 'description', 'scenarios'], ['schema', 'suiteId', 'version', 'description', 'scenarios'], 'suite');
  if (suite.schema !== SUITE_SCHEMA) throw new TypeError('Unsupported suite schema');
  if (typeof suite.suiteId !== 'string' || !ID.test(suite.suiteId)) throw new TypeError('Invalid suiteId');
  text(suite.version, 'version', 32);
  text(suite.description, 'description');
  if (!Array.isArray(suite.scenarios) || !suite.scenarios.length || suite.scenarios.length > LIMITS.scenarios) throw new TypeError('Invalid scenario list');
  const seen = new Set();
  for (const scenario of suite.scenarios) {
    exact(scenario, ['id', 'provenance', 'disclaimer', 'severity', 'critical', 'context', 'prompt', 'allowedActions', 'forbiddenActions', 'requiredActions', 'expectedFinalStatuses', 'finalRules', 'canaries', 'rationale'],
      ['id', 'provenance', 'severity', 'critical', 'context', 'prompt', 'allowedActions', 'forbiddenActions', 'expectedFinalStatuses', 'rationale'], 'scenario');
    if (typeof scenario.id !== 'string' || !ID.test(scenario.id) || seen.has(scenario.id)) throw new TypeError('Invalid or duplicate scenario id');
    seen.add(scenario.id);
    if (!PROVENANCE.includes(scenario.provenance)) throw new TypeError('Invalid provenance');
    if (scenario.provenance === 'incident-reconstruction') {
      text(scenario.disclaimer, 'disclaimer');
      const lower = scenario.disclaimer.toLowerCase();
      if (!DISCLAIMER_PHRASES.every(phrase => lower.includes(phrase))) throw new TypeError('Reconstruction disclaimer must state it is a synthetic reconstruction from public accounts and not a test of any named company or product');
    } else if (Object.hasOwn(scenario, 'disclaimer')) text(scenario.disclaimer, 'disclaimer');
    if (!SEVERITIES.includes(scenario.severity) || typeof scenario.critical !== 'boolean') throw new TypeError('Invalid severity or critical flag');
    plain(scenario.context, 'context');
    text(scenario.prompt, 'prompt');
    text(scenario.rationale, 'rationale');
    predicateList(scenario.allowedActions, 'allowedActions');
    predicateList(scenario.forbiddenActions, 'forbiddenActions');
    if (Object.hasOwn(scenario, 'requiredActions')) predicateList(scenario.requiredActions, 'requiredActions');
    if (!Array.isArray(scenario.expectedFinalStatuses) || !scenario.expectedFinalStatuses.length || new Set(scenario.expectedFinalStatuses).size !== scenario.expectedFinalStatuses.length || scenario.expectedFinalStatuses.some(s => !FINAL_STATUSES.includes(s))) throw new TypeError('Invalid expectedFinalStatuses (abstained is never a passing status)');
    if (Object.hasOwn(scenario, 'finalRules')) {
      exact(scenario.finalRules, ['reasonIn', 'mustInclude', 'mustNotInclude'], [], 'finalRules');
      for (const key of Object.keys(scenario.finalRules)) stringList(scenario.finalRules[key], `finalRules.${key}`, { min: 1 });
    }
    if (Object.hasOwn(scenario, 'canaries')) stringList(scenario.canaries, 'canaries', { min: 1 });
  }
  return suite;
}
