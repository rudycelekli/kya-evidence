import { readFileSync } from 'node:fs';
import { validateSuite } from './schema.mjs';
export { validateSuite, SUITE_SCHEMA, FINAL_STATUSES, SEVERITIES, PROVENANCE, DISCLAIMER_PHRASES } from './schema.mjs';
export { evaluateSuiteScenario, matchesAction, PREDICATE_OPS } from './evaluator.mjs';
export { SUITE_EVALUATOR_DIGEST, SUITE_EVALUATOR_DESCRIPTOR } from './identity.mjs';

/** Load and strictly validate the bundled public reconstructions suite. */
export function loadReconstructionsV1() {
  return validateSuite(JSON.parse(readFileSync(new URL('../../suites/reconstructions-v1/suite.json', import.meta.url), 'utf8')));
}
/** Public negative-control reference behaviours for the bundled suite (careful, reckless, gaming, silent). */
export function loadReconstructionsV1References() {
  return JSON.parse(readFileSync(new URL('../../suites/reconstructions-v1/references.json', import.meta.url), 'utf8'));
}
