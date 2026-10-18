#!/usr/bin/env node
// KYA implementation contract, JavaScript reference adapter. Reads ONE kya.impl-input/v1 object on stdin and
// writes ONE kya.impl-result/v1 object on stdout. A refusal or crash is a non-zero exit with nothing on stdout.
// It uses only the public package API, so it proves the harness and defines the result shape; it is not an independent implementation.
import { assess, checkCurrency, digest } from '../../src/index.mjs';
import { parseJson } from '../../src/shared/canonical.mjs';
import { V2_OPERATIONS } from './js-operations.mjs';

function assessResult(r) {
  return { schema: 'kya.impl-result/v1', operation: 'assess', decision: r.decision, evidenceMode: r.evidenceMode, ambiguousRuns: r.ambiguousRuns, selectedRunId: r.selectedRunId, score: r.score, coverage: r.coverage, independentCoverage: r.independentCoverage, blockerCodes: r.blockerCodes, validUntil: r.validUntil,
    checks: r.checks.map(c => ({ id: c.id, status: c.status, evidenceId: c.evidenceId, independence: c.independence })),
    rejectedEvidence: r.rejectedEvidence.map(x => ({ index: x.index, id: x.id, reason: x.reason })), reportDigest: r.reportDigest };
}
function currencyResult(r) {
  return { schema: 'kya.impl-result/v1', operation: 'currency', current: r.current, reliable: r.reliable, action: r.action, checkedAt: r.checkedAt, assessmentDigest: r.assessmentDigest,
    triggers: r.triggers.map(t => ({ id: t.id, code: t.code })),
    incidents: { considered: r.incidents.considered, open: r.incidents.open, resolved: r.incidents.resolved, appealed: r.incidents.appealed, observed: r.incidents.observed, ignored: r.incidents.ignored.map(x => ({ id: x.id, reason: x.reason })) },
    resultDigest: digest(r) };
}

const chunks = []; let size = 0;
for await (const c of process.stdin) { size += c.length; if (size > 8 * 1024 * 1024) { console.error('input too large'); process.exit(3); } chunks.push(c); }
try {
  const input = parseJson(Buffer.concat(chunks).toString('utf8'));
  if (input?.schema !== 'kya.impl-input/v1' || typeof input.inputs !== 'object' || input.inputs === null) throw Error('Not a kya.impl-input/v1 object');
  let out;
  if (input.operation === 'assess') out = assessResult(assess(input.inputs));
  else if (input.operation === 'currency') { const { assessment, ...rest } = input.inputs; out = currencyResult(checkCurrency(assessment, rest)); }
  else if (typeof input.operation === 'string' && Object.hasOwn(V2_OPERATIONS, input.operation)) out = V2_OPERATIONS[input.operation](input.inputs);
  else out = { schema: 'kya.impl-result/v1', operation: String(input.operation), unsupported: true };
  process.stdout.write(JSON.stringify(out) + '\n');
} catch (e) { console.error('refused: ' + e.message); process.exit(2); }
