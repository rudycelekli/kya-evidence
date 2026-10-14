import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { canonical, digest, hashBytes, exactKeys, insist } from '../../shared/canonical.mjs';
import { timestamp, keyId } from '../../identity/domain/services/validation.mjs';
import { signEvidence, verifyEvidence } from '../../evidence/index.mjs';
import { assess } from '../../assessment/index.mjs';
import { ASSESSOR_SOURCE_DIGEST } from '../../research/index.mjs';
import { CORE_PROFILE, EVALUATOR_DIGEST, createReferenceAdapter, runConformance } from '../../conformance/index.mjs';
import { BENCHMARK_CATALOG, CATALOG_DIGEST, deepFreeze } from '../domain/catalog.mjs';

const snapshot = value => JSON.parse(canonical(value));
const iso = milliseconds => new Date(milliseconds).toISOString();
const projection = report => ({
  decision: report.decision, coverage: report.coverage,
  checkPopulation: report.checks.map(check => check.id),
  checkStatuses: report.checks.map(check => ({ id: check.id, status: check.status })),
  rejectionReasons: [...new Set(report.rejectedEvidence.map(receipt => receipt.reason))].sort(),
});
function matches(expected, actual) {
  return actual !== null && ['decision', 'coverage', 'checkPopulation', 'checkStatuses'].every(key => canonical(expected[key]) === canonical(actual[key]))
    && expected.requiredRejectionReasons.every(reason => actual.rejectionReasons.includes(reason));
}
function summary(cases) {
  return { total: BENCHMARK_CATALOG.cases.length, possible: BENCHMARK_CATALOG.cases.length,
    passed: cases.filter(c => c.outcome === 'pass').length, failed: cases.filter(c => c.outcome === 'fail').length,
    errors: cases.filter(c => c.outcome === 'error').length, allPassed: cases.every(c => c.outcome === 'pass') };
}
function makeFixture(now, keys) {
  const at = timestamp(now);
  insist(at >= 120_000 && at <= 8_640_000_000_000_000 - 86_400_000, 'Benchmark time is outside fixture range');
  const manifest = { schema: 'kya.manifest/v1', agent: { id: 'fixture:benchmark', name: 'Offline reference control', version: '1' }, principal: { id: 'controller:synthetic' },
    system: { harness: 'kya-offline-fixture', harnessVersion: '1', model: 'deterministic-no-model', artifactDigest: hashBytes('owned benchmark fixture v1'), configDigest: hashBytes('fixed offline fixture configuration v1'), tools: [{ id: 'read', version: '1', permissions: ['read'] }] },
    scope: { id: 'synthetic:benchmark', purpose: 'Frozen offline KYA gate controls', permissions: ['read', 'external-message'], forbidden: ['delete', 'external-write'], approvalRequired: ['external-message'] },
    issuedAt: iso(at - 120_000), expiresAt: iso(at + 86_400_000) };
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const policy = { schema: 'kya.policy/v1', id: 'benchmark-fixture-policy', profileDigest: digest(CORE_PROFILE), scopeId: manifest.scope.id,
    minCoverage: 1, minScore: 900, minIndependentCoverage: 0, allowedSources: ['fixture'], maxEvidenceAgeSeconds: 7200,
    trustedKeys: [{ id: keyId(publicKey), publicKey, role: 'self' }], revokedKeyIds: [], revokedEvidenceIds: [], revokedSubjectDigests: [] };
  return { manifest, profile: snapshot(CORE_PROFILE), policy, evaluatorDigest: EVALUATOR_DIGEST, now };
}
function payloads(inputs) {
  return CORE_PROFILE.checks.map((check, index) => ({ schema: 'kya.evidence/v1', id: `fixture:receipt:${index}`, subjectDigest: digest(inputs.manifest), scopeId: inputs.manifest.scope.id,
    profileDigest: digest(CORE_PROFILE), evaluatorDigest: EVALUATOR_DIGEST, runId: 'fixture:whole-run', checkId: check.id, outcome: 'pass', observedAt: inputs.now,
    expiresAt: iso(Date.parse(inputs.now) + 3_600_000), artifactDigest: hashBytes(`owned offline control ${check.id}`), source: 'fixture' }));
}
async function caseInputs(definition, base, keys) {
  const inputs = snapshot(base);
  let unsigned = payloads(inputs);
  if (definition.suiteId === 'behavioral-core') {
    const run = await runConformance({ adapter: createReferenceAdapter({ mode: definition.mode }), manifest: inputs.manifest, now: inputs.now });
    unsigned = run.evidence;
  }
  if (definition.id === 'integrity.declaration-laundering') {
    unsigned.forEach(receipt => { receipt.source = 'declaration'; });
    inputs.policy.allowedSources.push('declaration');
  }
  if (definition.id === 'integrity.critical-failure') unsigned[0].outcome = 'fail';
  inputs.evidence = unsigned.map(receipt => signEvidence(receipt, keys.privateKey));
  switch (definition.id) {
    case 'integrity.untrusted-key': inputs.policy.trustedKeys = []; break;
    case 'integrity.signature-tamper': inputs.evidence[0].payload.outcome = 'fail'; break;
    case 'integrity.revoked-key': inputs.policy.revokedKeyIds.push(keyId(keys.publicKey)); break;
    case 'integrity.expired-manifest': inputs.manifest.expiresAt = iso(Date.parse(inputs.now) - 1); break;
    case 'integrity.missing-check': inputs.evidence.shift(); break;
    case 'integrity.duplicate-receipt': inputs.evidence.push(snapshot(inputs.evidence[0])); break;
    case 'integrity.changed-config': inputs.manifest.system.configDigest = hashBytes('different configuration'); break;
    case 'integrity.wrong-evaluator': inputs.evaluatorDigest = hashBytes('different evaluator'); break;
    case 'integrity.revoked-newer-failure': {
      const old = unsigned.map(receipt => ({ ...receipt, observedAt: iso(Date.parse(inputs.now) - 30_000), runId: 'fixture:older-run' }));
      const newer = { ...unsigned[0], id: 'fixture:newer-failure', runId: 'fixture:newer-run', outcome: 'fail' };
      inputs.evidence = [...old, newer].map(receipt => signEvidence(receipt, keys.privateKey));
      inputs.policy.revokedEvidenceIds.push(newer.id); break;
    }
  }
  return inputs;
}

// Replay alone does not prove the claimed challenge was tested. Bind each input
// to its fixed challenge as well, allowing only ephemeral public keys/run IDs.
function verifyChallengeInputs(definition, inputs, now, publicKey) {
  const base = makeFixture(now, { publicKey: createPublicKey(publicKey) });
  const expected = snapshot(base); let receipts = payloads(base);
  if (definition.id === 'integrity.declaration-laundering') { expected.policy.allowedSources.push('declaration'); receipts.forEach(p => { p.source = 'declaration'; }); }
  if (definition.id === 'integrity.critical-failure' || definition.id === 'integrity.signature-tamper') receipts[0].outcome = 'fail';
  switch (definition.id) {
    case 'integrity.untrusted-key': expected.policy.trustedKeys = []; break;
    case 'integrity.revoked-key': expected.policy.revokedKeyIds.push(keyId(publicKey)); break;
    case 'integrity.expired-manifest': expected.manifest.expiresAt = iso(Date.parse(now) - 1); break;
    case 'integrity.missing-check': receipts.shift(); break;
    case 'integrity.duplicate-receipt': receipts.push(snapshot(receipts[0])); break;
    case 'integrity.changed-config': expected.manifest.system.configDigest = hashBytes('different configuration'); break;
    case 'integrity.wrong-evaluator': expected.evaluatorDigest = hashBytes('different evaluator'); break;
    case 'integrity.revoked-newer-failure': {
      const old = receipts.map(p => ({ ...p, observedAt: iso(Date.parse(now) - 30_000), runId: 'fixture:older-run' }));
      const newer = { ...receipts[0], id: 'fixture:newer-failure', runId: 'fixture:newer-run', outcome: 'fail' };
      receipts = [...old, newer]; expected.policy.revokedEvidenceIds.push(newer.id); break;
    }
  }
  for (const name of ['manifest', 'profile', 'policy', 'evaluatorDigest', 'now']) insist(canonical(inputs[name]) === canonical(expected[name]), 'Benchmark challenge inputs differ');
  insist(Array.isArray(inputs.evidence) && inputs.evidence.length === receipts.length, 'Benchmark challenge receipt population differs');
  const behavioral = definition.suiteId === 'behavioral-core';
  const runId = behavioral ? inputs.evidence[0].payload.runId : null;
  if (behavioral) insist(/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(runId), 'Invalid fixture run ID');
  inputs.evidence.forEach((envelope, index) => {
    const expectedPayload = receipts[index];
    insist(envelope.proof.publicKey === publicKey && envelope.proof.keyId === keyId(publicKey), 'Benchmark fixture issuer differs');
    if (behavioral) {
      expectedPayload.runId = runId; expectedPayload.id = `${runId}:${expectedPayload.checkId}`;
      expectedPayload.outcome = definition.expected.checkStatuses[index].status;
      // The signed observation hash includes measured duration and the random
      // run ID; it is an integrity reference, not an execution attestation.
      expectedPayload.artifactDigest = envelope.payload.artifactDigest;
    }
    insist(canonical(envelope.payload) === canonical(expectedPayload), 'Benchmark challenge payload differs');
    if (definition.id === 'integrity.signature-tamper' && index === 0) {
      const original = snapshot(envelope); original.payload.outcome = 'pass'; verifyEvidence(original);
    } else verifyEvidence(envelope);
  });
}

/** Owned deterministic controls only. Importing this module never launches a process. */
export async function runOfflineBenchmarks(options) {
  options = snapshot(options);
  exactKeys(options, ['now'], 'Offline benchmark options'); timestamp(options.now);
  const keys = generateKeyPairSync('ed25519'), base = makeFixture(options.now, keys), cases = [];
  for (const definition of BENCHMARK_CATALOG.cases) {
    const started = performance.now(); let inputs = null, assessment = null, actual = null, outcome = 'error', error = null;
    try {
      inputs = await caseInputs(definition, base, keys); assessment = assess(inputs); actual = projection(assessment);
      outcome = matches(definition.expected, actual) ? 'pass' : 'fail';
    } catch { error = 'BENCHMARK_EXECUTION_ERROR'; }
    cases.push({ id: definition.id, suiteId: definition.suiteId, source: 'fixture', outcome, expected: snapshot(definition.expected), actual,
      inputs, inputDigest: inputs === null ? null : digest(inputs), assessment, artifactDigest: assessment?.reportDigest ?? null,
      durationMs: Math.round((performance.now() - started) * 1000) / 1000, costUsd: null, error });
  }
  const body = { schema: 'kya.benchmark-run/v1', catalogDigest: CATALOG_DIGEST, evaluatorDigest: EVALUATOR_DIGEST,
    assessorSourceDigest: ASSESSOR_SOURCE_DIGEST, now: options.now, fixtureOnly: true, commercialRuntimesMeasured: false, newProviderCalls: 0,
    evidenceInputDigest: digest(cases.map(c => c.inputDigest)), cases, summary: summary(cases),
    limitations: ['Unsigned local replay record; no authenticated observer or execution attestation.', 'Fixture controls measure local gate behavior, not commercial runtime quality or OS isolation.', 'Monetary cost is unmeasured; elapsed case duration is a local observation.', 'Ephemeral self-signing keys provide fixture integrity, not independent assessment.'] };
  return deepFreeze({ ...body, runDigest: digest(body) });
}

/** Strict structural verification plus replay. A checksum is not proof of execution. */
export function verifyBenchmarkRun(value) {
  const run = snapshot(value);
  exactKeys(run, ['schema', 'catalogDigest', 'evaluatorDigest', 'assessorSourceDigest', 'now', 'fixtureOnly', 'commercialRuntimesMeasured', 'newProviderCalls', 'evidenceInputDigest', 'cases', 'summary', 'limitations', 'runDigest'], 'Benchmark run');
  const { runDigest, ...body } = run;
  insist(run.schema === 'kya.benchmark-run/v1' && digest(body) === runDigest, 'Benchmark run digest differs');
  insist(run.catalogDigest === CATALOG_DIGEST && run.evaluatorDigest === EVALUATOR_DIGEST && run.assessorSourceDigest === ASSESSOR_SOURCE_DIGEST, 'Benchmark implementation binding differs');
  timestamp(run.now); insist(run.fixtureOnly === true && run.commercialRuntimesMeasured === false && run.newProviderCalls === 0, 'Invalid fixture boundary');
  insist(Array.isArray(run.cases) && run.cases.length === BENCHMARK_CATALOG.cases.length, 'Benchmark population differs');
  const publicKey = run.cases.find(item => item.outcome !== 'error')?.inputs?.evidence?.[0]?.proof?.publicKey ?? null;
  let replayMatched = true;
  run.cases.forEach((item, index) => {
    const definition = BENCHMARK_CATALOG.cases[index];
    exactKeys(item, ['id', 'suiteId', 'source', 'outcome', 'expected', 'actual', 'inputs', 'inputDigest', 'assessment', 'artifactDigest', 'durationMs', 'costUsd', 'error'], 'Benchmark case');
    insist(item.id === definition.id && item.suiteId === definition.suiteId && item.source === 'fixture', 'Benchmark case identity or order differs');
    insist(canonical(item.expected) === canonical(definition.expected), 'Benchmark expected contract differs');
    insist(typeof item.durationMs === 'number' && Number.isFinite(item.durationMs) && item.durationMs >= 0 && item.costUsd === null, 'Invalid benchmark cost or duration');
    insist(['pass', 'fail', 'error'].includes(item.outcome), 'Invalid benchmark outcome');
    if (item.outcome === 'error') {
      insist(item.error === 'BENCHMARK_EXECUTION_ERROR' && item.actual === null && item.assessment === null && item.artifactDigest === null, 'Invalid benchmark error record');
      insist(item.inputs === null ? item.inputDigest === null : digest(item.inputs) === item.inputDigest, 'Benchmark error inputs differ');
      replayMatched = false; return;
    }
    insist(item.error === null && item.inputs !== null && digest(item.inputs) === item.inputDigest, 'Benchmark case inputs differ');
    exactKeys(item.inputs, ['manifest', 'profile', 'policy', 'evaluatorDigest', 'now', 'evidence'], 'Benchmark assessment inputs');
    insist(item.inputs.now === run.now && digest(item.inputs.profile) === digest(CORE_PROFILE), 'Benchmark case time or profile differs');
    verifyChallengeInputs(definition, item.inputs, run.now, publicKey);
    const replay = assess(item.inputs);
    insist(canonical(replay) === canonical(item.assessment) && replay.reportDigest === item.artifactDigest, 'Benchmark assessment replay differs');
    insist(canonical(projection(replay)) === canonical(item.actual), 'Benchmark actual contract differs');
    insist(item.outcome === (matches(definition.expected, item.actual) ? 'pass' : 'fail'), 'Benchmark outcome differs');
  });
  insist(run.evidenceInputDigest === digest(run.cases.map(c => c.inputDigest)), 'Benchmark evidence input digest differs');
  insist(canonical(run.summary) === canonical(summary(run.cases)), 'Benchmark summary differs');
  insist(canonical(run.limitations) === canonical([
    'Unsigned local replay record; no authenticated observer or execution attestation.', 'Fixture controls measure local gate behavior, not commercial runtime quality or OS isolation.',
    'Monetary cost is unmeasured; elapsed case duration is a local observation.', 'Ephemeral self-signing keys provide fixture integrity, not independent assessment.',
  ]), 'Benchmark limitations differ');
  return { integrity: true, replayMatched, passed: replayMatched && run.summary.allPassed, runDigest, catalogDigest: CATALOG_DIGEST, assessorSourceDigest: ASSESSOR_SOURCE_DIGEST, authenticated: false };
}
