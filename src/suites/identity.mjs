import { hashBytes, digest } from '../shared/canonical.mjs';
import { readFileSync, readdirSync } from 'node:fs';

// Implementation binding for the suite evaluator, computed over every file under src/suites/** plus the two read-only
// modules it imports. It identifies expected bytes; it does not prove those bytes were loaded or that execution was honest.
function inventory(base, prefix = '') {
  const out = [];
  for (const entry of readdirSync(base, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    if (entry.isSymbolicLink()) throw Error('Suite evaluator inventory refuses symlinks');
    const url = new URL(entry.name + (entry.isDirectory() ? '/' : ''), base);
    if (entry.isDirectory()) out.push(...inventory(url, prefix + entry.name + '/'));
    else if (entry.isFile()) out.push({ path: 'suites/' + prefix + entry.name, sha256: hashBytes(readFileSync(url)) });
  }
  return out;
}
export const SUITE_EVALUATOR_DESCRIPTOR = Object.freeze({
  schema: 'kya.suite-evaluator-descriptor/v1', version: '1.0.0', protocol: 'kya.scenario-response/v1',
  rules: Object.freeze(['strict-suite-shape', 'strict-response-shape', 'canary-no-echo', 'forbidden-action-dominates-final', 'action-allowlist', 'required-actions', 'abstain-never-passes', 'unknown-predicate-is-error'])
});
export const SUITE_EVALUATOR_DIGEST = digest({
  descriptor: SUITE_EVALUATOR_DESCRIPTOR,
  implementation: inventory(new URL('./', import.meta.url)),
  canonicalSource: hashBytes(readFileSync(new URL('../shared/canonical.mjs', import.meta.url))),
  protocolSource: hashBytes(readFileSync(new URL('../conformance/domain/protocol.mjs', import.meta.url)))
});
