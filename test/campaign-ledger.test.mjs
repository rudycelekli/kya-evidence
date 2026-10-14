import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPrivateKey, createPublicKey } from 'node:crypto';
import { createPlan, openLedger, appendEntry, verifyLedger as verifyStrict, summarizeCampaign, verifyCaptureIssuerPolicy } from '../src/campaign/index.mjs';
import { signEntry } from '../src/campaign/domain/records.mjs';
import { assess, digest, hashBytes, keyId, signEvidence, validatePolicy } from '../src/index.mjs';
import { manifest, profile, policy, payload, evaluatorDigest, NOW } from './helpers.mjs';

const issuer = generateKeyPairSync('ed25519');
const issuerPem = issuer.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const stranger = generateKeyPairSync('ed25519');
const T0 = '2026-10-14T09:00:00.000Z', T1 = '2026-10-14T09:01:00.000Z', T2 = '2026-10-14T09:02:00.000Z', T3 = '2026-10-14T09:03:00.000Z';
const subject = hashBytes('subject-a');
const scenarioSetDigest = hashBytes('scenarios');
const adapter = { source: 'fixture', id: 'reference-careful', mode: 'careful' };
const attempts = ['a-1', 'a-2', 'a-3'].map(attemptId => ({ attemptId, subjectDigest: subject, scenarioSetDigest, seed: null }));
const planInput = (patch = {}) => ({ campaignId: 'campaign:pilot-1', useCase: 'Synthetic pilot campaign over the frozen core profile', profileDigest: hashBytes('profile'), scenarioSetDigest, evaluatorDigest: hashBytes('evaluator'), policyDigest: hashBytes('policy'), adapter, attempts, createdAt: T0, privateKey: issuer.privateKey, ...patch });
const opened = () => openLedger({ plan: createPlan(planInput()), privateKey: issuer.privateKey, now: T0 });
const add = (ledger, entry, key = issuer.privateKey) => appendEntry({ ledger, privateKey: key, entry });
const run = (ledger, id, at, kind = 'completed') => {
  ledger = add(ledger, { kind: 'started', attemptId: id, at });
  if (kind === 'completed') return add(ledger, { kind, attemptId: id, at, runId: `run-${id}`, evidenceBundleDigest: hashBytes(`bundle-${id}`) });
  return add(ledger, { kind: 'errored', attemptId: id, at, errorCode: 'TIMEOUT', evidenceBundleDigest: null });
};
// Structural tests opt out of the signer-trust requirement explicitly; trust tests pass a policy.
const verifyLedger = (ledger, options = {}) => verifyStrict(ledger, options.policy ? options : { trustPlanSigner: true, ...options });
const codes = result => result.problems.map(p => p.code);

test('campaign plan commits to attempts, digests and issuer before any attempt', () => {
  const plan = createPlan(planInput());
  assert.equal(plan.payload.schema, 'kya.campaign-plan/v1');
  assert.deepEqual(plan.payload.attempts.map(a => a.attemptId), ['a-1', 'a-2', 'a-3']);
  assert.deepEqual(plan.payload.subjects, [subject]);
  assert.equal(plan.payload.createdAt, T0);
  assert.equal(plan.proof.keyId, keyId(issuerPem));
  const ledger = openLedger({ plan, privateKey: issuer.privateKey, now: T0 });
  assert.equal(ledger.schema, 'kya.campaign-ledger/v1');
  const result = verifyLedger(ledger);
  assert.equal(result.valid, true, JSON.stringify(result.problems));
  assert.equal(ledger.entries.length, 3);
  assert.ok(ledger.entries.every(e => e.payload.kind === 'planned'));
  assert.throws(() => openLedger({ plan, privateKey: stranger.privateKey, now: T0 }), /issuer/i);
});

test('campaign plan rejects malformed attempts and duplicate attempt IDs', () => {
  assert.throws(() => createPlan(planInput({ attempts: [attempts[0], attempts[0]] })), /duplicate/i);
  assert.throws(() => createPlan(planInput({ attempts: [] })), /attempts/i);
  assert.throws(() => createPlan(planInput({ attempts: [{ ...attempts[0], seed: -1 }] })), /seed/i);
  assert.throws(() => createPlan(planInput({ attempts: [{ ...attempts[0], subjectDigest: 'nope' }] })), /SHA-256/);
  assert.throws(() => createPlan(planInput({ createdAt: '2026-10-14' })), /timestamp/i);
  assert.throws(() => createPlan(planInput({ extra: 1 })), /unexpected/i);
  assert.equal(createPlan(planInput({ attempts: [{ ...attempts[0], seed: 42 }] })).payload.attempts[0].seed, 42);
});

test('campaign ledger rejects out-of-order transitions and duplicate attempt IDs', () => {
  const ledger = opened();
  assert.throws(() => add(ledger, { kind: 'completed', attemptId: 'a-1', at: T1, runId: 'run-x', evidenceBundleDigest: hashBytes('x') }), /transition/i);
  assert.throws(() => add(ledger, { kind: 'started', attemptId: 'unknown', at: T1 }), /not planned/i);
  assert.throws(() => add(ledger, { kind: 'planned', attemptId: 'a-9', at: T1 }), /plan/i);
  const started = add(ledger, { kind: 'started', attemptId: 'a-1', at: T1 });
  assert.throws(() => add(started, { kind: 'started', attemptId: 'a-1', at: T2 }), /transition/i);
  const done = run(ledger, 'a-2', T1);
  assert.throws(() => add(done, { kind: 'abandoned', attemptId: 'a-2', at: T2, reasonCode: 'operator-abandon' }), /transition/i);
  assert.throws(() => add(done, { kind: 'started', attemptId: 'a-2', at: T2 }), /transition/i);
  assert.throws(() => add(ledger, { kind: 'amended', attemptId: 'a-1', retryOf: 'a-1', subjectDigest: subject, scenarioSetDigest, seed: null, at: T1 }), /duplicate|retry/i);
});

test('campaign ledger rejects entries before the plan commitment and time regression', () => {
  const ledger = opened();
  assert.throws(() => add(ledger, { kind: 'started', attemptId: 'a-1', at: '2026-10-14T08:59:59.000Z' }), /before/i);
  const later = add(ledger, { kind: 'started', attemptId: 'a-1', at: T2 });
  assert.throws(() => add(later, { kind: 'abandoned', attemptId: 'a-2', at: T1, reasonCode: 'operator-abandon' }), /before/i);
  assert.throws(() => openLedger({ plan: createPlan(planInput()), privateKey: issuer.privateKey, now: '2026-10-13T00:00:00.000Z' }), /before/i);
  const forged = structuredClone(later);
  forged.entries[3].payload.at = T0;
  assert.ok(codes(verifyLedger(forged)).length > 0);
});

test('campaign ledger detects edited removed and reordered history', () => {
  const ledger = run(run(opened(), 'a-1', T1), 'a-2', T2);
  assert.equal(verifyLedger(ledger).valid, true);
  const edited = structuredClone(ledger);
  edited.entries[4].payload.runId = 'run-forged';
  assert.ok(codes(verifyLedger(edited)).includes('bad-entry-signature'));
  assert.throws(() => add(edited, { kind: 'started', attemptId: 'a-3', at: T3 }), /ledger/i);
  const removed = structuredClone(ledger);
  removed.entries.splice(3, 1);
  assert.equal(verifyLedger(removed).valid, false);
  assert.ok(codes(verifyLedger(removed)).includes('chain-broken'));
  const reordered = structuredClone(ledger);
  [reordered.entries[3], reordered.entries[4]] = [reordered.entries[4], reordered.entries[3]];
  assert.equal(verifyLedger(reordered).valid, false);
  const next = { prevDigest: hashBytes('not the previous entry'), seq: ledger.entries.length };
  const { runId, evidenceBundleDigest, ...last } = ledger.entries.at(-1).payload;
  const lie = structuredClone(ledger);
  lie.entries.push(signEntry({ ...last, kind: 'abandoned', attemptId: 'a-3', at: T3, ...next, reasonCode: 'operator-abandon' }, issuer.privateKey));
  assert.ok(codes(verifyLedger(lie)).includes('chain-broken'), 'a correctly signed entry that does not commit to its predecessor is rejected');
  const truncatedPlanned = structuredClone(ledger);
  truncatedPlanned.entries = truncatedPlanned.entries.slice(1);
  assert.equal(verifyLedger(truncatedPlanned).valid, false);
  const swappedPlan = structuredClone(ledger);
  swappedPlan.plan = createPlan(planInput({ campaignId: 'campaign:other' }));
  assert.equal(verifyLedger(swappedPlan).valid, false);
});

test('campaign ledger rejects a foreign signer and requires the capture issuer role under policy', () => {
  const base = policy();
  const asIssuer = { ...base, trustedKeys: [{ id: keyId(issuerPem), publicKey: issuerPem, role: 'capture-issuer' }] };
  const ledger = openLedger({ plan: createPlan(planInput({ policyDigest: digest(asIssuer) })), privateKey: issuer.privateKey, now: T0 });
  assert.throws(() => add(ledger, { kind: 'started', attemptId: 'a-1', at: T1 }, stranger.privateKey), /issuer/i);
  assert.equal(verifyLedger(ledger, { policy: asIssuer }).valid, true);
  const asSelf = { ...base, trustedKeys: [{ id: keyId(issuerPem), publicKey: issuerPem, role: 'self' }] };
  assert.ok(codes(verifyLedger(ledger, { policy: asSelf })).includes('untrusted-signer'));
  const revoked = { ...asIssuer, revokedKeyIds: [keyId(issuerPem)] };
  assert.ok(codes(verifyLedger(ledger, { policy: revoked })).includes('untrusted-signer'));
  const wrongKey = { ...base, trustedKeys: [] };
  assert.ok(codes(verifyLedger(ledger, { policy: wrongKey })).includes('untrusted-signer'));
});

test('campaign summary keeps unaccounted attempts in the denominator', () => {
  let ledger = opened();
  const { headDigest, entryCount, ...counts } = summarizeCampaign(ledger);
  assert.equal(entryCount, 3); assert.match(headDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(counts, { campaignId: 'campaign:pilot-1', planned: 3, completed: 0, errored: 0, abandoned: 0, unaccounted: 3, unaccountedAttemptIds: ['a-1', 'a-2', 'a-3'], amendments: 0, closed: false });
  ledger = run(ledger, 'a-1', T1);
  ledger = run(ledger, 'a-2', T2, 'errored');
  ledger = add(ledger, { kind: 'started', attemptId: 'a-3', at: T3 });
  let s = summarizeCampaign(ledger);
  assert.equal(s.planned, 3); assert.equal(s.completed, 1); assert.equal(s.errored, 1); assert.equal(s.abandoned, 0);
  assert.equal(s.unaccounted, 1, 'a started attempt without a terminal entry stays unaccounted');
  assert.equal(s.closed, false);
  ledger = add(ledger, { kind: 'abandoned', attemptId: 'a-3', at: T3, reasonCode: 'campaign-closed' });
  s = summarizeCampaign(ledger);
  assert.deepEqual([s.planned, s.completed, s.errored, s.abandoned, s.unaccounted, s.closed], [3, 1, 1, 1, 0, true]);
  assert.equal(verifyLedger(ledger, { requireClosed: true }).valid, true);
  assert.ok(codes(verifyLedger(opened(), { requireClosed: true })).includes('unaccounted-attempt'));
  assert.equal(verifyLedger(opened()).valid, true);
  assert.throws(() => summarizeCampaign({ ...ledger, entries: ledger.entries.slice(0, 2) }), /ledger/i);
});

test('campaign completed entry requires run ID and bundle digest and rejects stored prompts or outputs', () => {
  const ledger = add(opened(), { kind: 'started', attemptId: 'a-1', at: T1 });
  assert.throws(() => add(ledger, { kind: 'completed', attemptId: 'a-1', at: T2 }), /unexpected|missing/i);
  assert.throws(() => add(ledger, { kind: 'completed', attemptId: 'a-1', at: T2, runId: 'run-1', evidenceBundleDigest: 'abc' }), /SHA-256/);
  assert.throws(() => add(ledger, { kind: 'completed', attemptId: 'a-1', at: T2, runId: 'bad id', evidenceBundleDigest: hashBytes('b') }), /identifier|invalid/i);
  for (const leak of ['prompt', 'response', 'output', 'rawOutput']) {
    assert.throws(() => add(ledger, { kind: 'completed', attemptId: 'a-1', at: T2, runId: 'run-1', evidenceBundleDigest: hashBytes('b'), [leak]: 'SYNTHETIC_PRIVATE_TEXT' }), /unexpected/i);
  }
  assert.throws(() => add(ledger, { kind: 'errored', attemptId: 'a-1', at: T2, errorCode: 'Some free text with a prompt', evidenceBundleDigest: null }), /error code/i);
  const done = add(ledger, { kind: 'completed', attemptId: 'a-1', at: T2, runId: 'run-1', evidenceBundleDigest: hashBytes('b') });
  assert.ok(!JSON.stringify(done).includes('SYNTHETIC_PRIVATE_TEXT'));
  assert.equal(done.entries.at(-1).payload.runId, 'run-1');
});

test('campaign retry is a signed amendment that keeps the errored attempt counted', () => {
  let ledger = run(opened(), 'a-1', T1, 'errored');
  assert.throws(() => add(ledger, { kind: 'amended', attemptId: 'a-2', retryOf: 'a-2', subjectDigest: subject, scenarioSetDigest, seed: null, at: T2 }), /retry|duplicate/i);
  assert.throws(() => add(ledger, { kind: 'amended', attemptId: 'a-1b', retryOf: 'a-2', subjectDigest: subject, scenarioSetDigest, seed: null, at: T2 }), /retry/i);
  ledger = add(ledger, { kind: 'amended', attemptId: 'a-1b', retryOf: 'a-1', subjectDigest: subject, scenarioSetDigest, seed: null, at: T2 });
  assert.throws(() => add(ledger, { kind: 'amended', attemptId: 'a-1c', retryOf: 'a-1', subjectDigest: subject, scenarioSetDigest, seed: null, at: T2 }), /retry/i);
  const s = summarizeCampaign(ledger);
  assert.equal(s.planned, 4); assert.equal(s.errored, 1); assert.equal(s.amendments, 1);
  assert.ok(s.unaccountedAttemptIds.includes('a-1b'));
  ledger = run(ledger, 'a-1b', T3);
  assert.equal(summarizeCampaign(ledger).completed, 1);
  assert.equal(summarizeCampaign(ledger).errored, 1, 'the original errored attempt is never removed from the counts');
  assert.equal(verifyLedger(ledger).valid, true);
  const notErrored = opened();
  assert.throws(() => add(notErrored, { kind: 'amended', attemptId: 'a-1b', retryOf: 'a-1', subjectDigest: subject, scenarioSetDigest, seed: null, at: T1 }), /retry/i);
});

test('capture issuer role is accepted by policy validation and legacy policies keep their digest', () => {
  const seed = Buffer.alloc(32, 7);
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const pem = createPublicKey(priv).export({ format: 'pem', type: 'spki' }).toString();
  const legacy = { schema: 'kya.policy/v1', id: 'legacy-policy', profileDigest: 'a'.repeat(64), scopeId: 'scope:test', minCoverage: 1, minScore: 800, minIndependentCoverage: 0, allowedSources: ['fixture'], maxEvidenceAgeSeconds: 3600, trustedKeys: [{ id: keyId(pem), publicKey: pem, role: 'self' }], revokedKeyIds: [], revokedEvidenceIds: [], revokedSubjectDigests: [] };
  assert.equal(digest(legacy), '73dd73df83657ea1d42dee4ca82d675a917b721e9bcf75ecdf571126a84f2ee1');
  assert.equal(digest(validatePolicy(legacy)), digest(legacy));
  const extended = { ...legacy, trustedKeys: [...legacy.trustedKeys, { id: keyId(issuerPem), publicKey: issuerPem, role: 'capture-issuer' }] };
  assert.equal(validatePolicy(extended).trustedKeys[1].role, 'capture-issuer');
  assert.throws(() => validatePolicy({ ...legacy, trustedKeys: [{ id: keyId(pem), publicKey: pem, role: 'calibrator' }] }), /role/i);
  assert.throws(() => validatePolicy({ ...legacy, trustedKeys: [{ id: keyId(pem), publicKey: pem, role: 'anchor-operator' }] }), /role/i);
});

test('capture issuer key cannot be an evidence signer or the evaluator key and never counts as independent', () => {
  const id = keyId(issuerPem);
  const base = { ...policy(), trustedKeys: [{ id: keyId(issuerPem), publicKey: issuerPem, role: 'capture-issuer' }] };
  assert.throws(() => validatePolicy({ ...base, trustedKeys: [base.trustedKeys[0], { ...base.trustedKeys[0], role: 'self' }] }), /duplicate/i);
  assert.doesNotThrow(() => verifyCaptureIssuerPolicy({ policy: base }));
  assert.throws(() => verifyCaptureIssuerPolicy({ policy: base, evidenceKeyIds: [id] }), /evidence/i);
  assert.throws(() => verifyCaptureIssuerPolicy({ policy: base, evaluatorKeyId: id }), /evaluator/i);
  assert.doesNotThrow(() => verifyCaptureIssuerPolicy({ policy: base, evidenceKeyIds: [hashBytes('other')], evaluatorKeyId: hashBytes('other') }));
  assert.throws(() => verifyCaptureIssuerPolicy({ policy: { ...base, trustedKeys: [] }, requireIssuer: true }), /capture-issuer/i);
  // A capture issuer anchor never satisfies independence in the scorer.
  const m = manifest(), p = profile();
  const evidence = p.checks.map((_, i) => signEvidence(payload(m, p, i), issuer.privateKey));
  const report = assess({ manifest: m, profile: p, policy: { ...base, profileDigest: digest(p), minIndependentCoverage: 1 }, evidence, evaluatorDigest, now: NOW });
  assert.equal(report.independentCoverage, 0);
  assert.notEqual(report.decision, 'qualified');
});

test('policy schema describes the capture issuer role', async () => {
  const { readFile } = await import('node:fs/promises');
  const schema = JSON.parse(await readFile(new URL('../schemas/policy.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(schema.properties.trustedKeys.items.properties.role.enum, ['self', 'independent', 'capture-issuer']);
});

test('campaign amendment must keep the original scenario set and seed', () => {
  const errored = run(opened(), 'a-1', T1, 'errored');
  const retry = patch => add(errored, { kind: 'amended', attemptId: 'a-1b', retryOf: 'a-1', subjectDigest: subject, scenarioSetDigest, seed: null, at: T2, ...patch });
  assert.throws(() => retry({ scenarioSetDigest: hashBytes('another scenario set') }), /retry/i);
  assert.throws(() => retry({ seed: 7 }), /retry/i);
  assert.equal(verifyLedger(retry({})).valid, true);
});

test('campaign ledger rejects duplicate run IDs and evidence bundle digests across completions', () => {
  let ledger = run(opened(), 'a-1', T1);
  ledger = add(ledger, { kind: 'started', attemptId: 'a-2', at: T2 });
  const completed = patch => add(ledger, { kind: 'completed', attemptId: 'a-2', at: T2, runId: 'run-a-2', evidenceBundleDigest: hashBytes('bundle-a-2'), ...patch });
  assert.throws(() => completed({ runId: 'run-a-1' }), /duplicate/i);
  assert.throws(() => completed({ evidenceBundleDigest: hashBytes('bundle-a-1') }), /duplicate/i);
  assert.equal(verifyLedger(completed({})).valid, true);
});

test('campaign ledger head digest and entry count expose truncation when pinned', () => {
  const full = run(opened(), 'a-1', T1);
  const result = verifyLedger(full);
  assert.equal(result.entryCount, 5);
  assert.match(result.headDigest, /^[a-f0-9]{64}$/);
  assert.equal(summarizeCampaign(full).headDigest, result.headDigest);
  const truncated = { ...structuredClone(full), entries: full.entries.slice(0, 4) };
  assert.equal(verifyLedger(truncated).valid, true, 'an unpinned rolled-back ledger still verifies');
  assert.notEqual(verifyLedger(truncated).headDigest, result.headDigest);
  assert.ok(codes(verifyLedger(truncated, { expectHead: result.headDigest })).includes('head-mismatch'));
  assert.ok(codes(verifyLedger(truncated, { expectEntries: 5 })).includes('entry-count-mismatch'));
  const forked = run(opened(), 'a-2', T1);
  assert.ok(codes(verifyLedger(forked, { expectHead: result.headDigest })).includes('head-mismatch'));
  assert.equal(verifyLedger(full, { expectHead: result.headDigest, expectEntries: 5 }).valid, true);
});

test('campaign verification requires a capture issuer policy or an explicit trust flag and binds the policy digest', () => {
  const asIssuer = { ...policy(), trustedKeys: [{ id: keyId(issuerPem), publicKey: issuerPem, role: 'capture-issuer' }] };
  const bound = openLedger({ plan: createPlan(planInput({ policyDigest: digest(asIssuer) })), privateKey: issuer.privateKey, now: T0 });
  const bare = verifyStrict(bound);
  assert.equal(bare.valid, false);
  assert.ok(codes(bare).includes('policy-required'));
  const ok = verifyStrict(bound, { policy: asIssuer });
  assert.equal(ok.valid, true);
  assert.equal(ok.signerTrust, 'policy');
  const trusted = verifyStrict(bound, { trustPlanSigner: true });
  assert.equal(trusted.valid, true);
  assert.equal(trusted.signerTrust, 'plan-signer-unverified');
  assert.ok(trusted.warnings.some(w => /capture-issuer/.test(w)));
  const other = { ...asIssuer, id: 'a-different-policy' };
  assert.ok(codes(verifyStrict(bound, { policy: other })).includes('policy-mismatch'));
  assert.ok(codes(verifyStrict(opened(), { policy: asIssuer })).includes('policy-mismatch'));
});
