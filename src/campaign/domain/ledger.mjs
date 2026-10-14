import { canonical, digest, exactKeys, insist } from '../../shared/canonical.mjs';
import { timestamp, validatePolicy, keyId } from '../../identity/domain/services/validation.mjs';
import { MAX_ATTEMPTS, ENTRY_KINDS, entryFields, privateKeyObject, publicPem, signPlan, signEntry, verifyPlan, verifyEntry } from './records.mjs';

const TERMINAL = new Set(['completed', 'errored', 'abandoned']);
const problem = (code, message) => ({ code, message });

export function createPlan({ privateKey, ...fields } = {}) {
  const expected = ['campaignId', 'useCase', 'profileDigest', 'scenarioSetDigest', 'evaluatorDigest', 'policyDigest', 'adapter', 'attempts', 'createdAt'];
  exactKeys(fields, expected, 'Plan input');
  const attempts = JSON.parse(canonical(fields.attempts));
  insist(Array.isArray(attempts), 'Plan attempts: expected a list');
  const subjects = [...new Set(attempts.map(a => a?.subjectDigest))].sort();
  return signPlan({ schema: 'kya.campaign-plan/v1', ...fields, attempts, subjects }, privateKeyObject(privateKey));
}

/**
 * Replay a ledger. Collects problems rather than throwing so verification can report every defect.
 * Returns the per-attempt state; planned/started attempts are "unaccounted" until a terminal entry exists.
 */
function replay(ledger, { policy, requireClosed = false } = {}) {
  const problems = [], attempts = new Map();
  let plan, issuer, planDigest;
  try {
    exactKeys(ledger, ['schema', 'plan', 'entries'], 'Campaign ledger');
    insist(ledger.schema === 'kya.campaign-ledger/v1', 'Unsupported campaign ledger schema');
    insist(Array.isArray(ledger.entries) && ledger.entries.length <= 4096, 'Ledger entries: invalid list');
    const verified = verifyPlan(ledger.plan);
    plan = verified.payload; issuer = { keyId: verified.keyId, publicKey: verified.publicKey };
    planDigest = digest(ledger.plan);
  } catch (error) { return { problems: [problem('bad-plan', `Plan failed verification: ${error.message}`)], attempts, plan: null, issuer: null }; }

  if (policy !== undefined) {
    try {
      const p = validatePolicy(policy), anchor = p.trustedKeys.find(k => k.id === issuer.keyId);
      if (!anchor || anchor.role !== 'capture-issuer' || p.revokedKeyIds.includes(issuer.keyId)) problems.push(problem('untrusted-signer', 'Signer is not a trusted, unrevoked capture-issuer anchor of the policy'));
    } catch (error) { problems.push(problem('untrusted-signer', `Policy invalid: ${error.message}`)); }
  }

  const planned = plan.attempts.length;
  let previous = planDigest, previousAt = Date.parse(plan.createdAt);
  ledger.entries.forEach((envelope, i) => {
    let e;
    try { e = verifyEntry(envelope, issuer); }
    catch (error) {
      const code = /not signed by the campaign/.test(error.message) ? 'signer-mismatch' : /signature/i.test(error.message) ? 'bad-entry-signature' : 'bad-entry';
      problems.push(problem(code, `Entry ${i}: ${error.message}`)); previous = null; return;
    }
    if (e.planDigest !== planDigest || e.campaignId !== plan.campaignId) problems.push(problem('plan-mismatch', `Entry ${i}: does not commit to this plan`));
    if (e.seq !== i || previous === null || e.prevDigest !== previous) problems.push(problem('chain-broken', `Entry ${i}: sequence or previous-entry commitment broken`));
    previous = digest(envelope);
    const at = Date.parse(e.at);
    if (at < Date.parse(plan.createdAt)) problems.push(problem('entry-before-plan', `Entry ${i}: Entry is before the plan commitment`));
    else if (at < previousAt) problems.push(problem('time-regression', `Entry ${i}: Entry is before the previous entry`));
    previousAt = Math.max(previousAt, at);
    transition(e, i);
  });
  if (ledger.entries.length < planned) problems.push(problem('planned-mismatch', 'Ledger lacks a signed planned entry for every planned attempt'));

  function transition(e, i) {
    const state = attempts.get(e.attemptId);
    if (e.kind === 'planned') {
      const expected = plan.attempts[i];
      if (i >= planned || !expected || expected.attemptId !== e.attemptId) problems.push(problem('planned-mismatch', `Entry ${i}: planned entries must list the plan attempts in order, before anything else`));
      else attempts.set(e.attemptId, { status: 'planned', subjectDigest: expected.subjectDigest, scenarioSetDigest: expected.scenarioSetDigest, seed: expected.seed, amended: false, retriedBy: null });
      return;
    }
    if (i < planned) { problems.push(problem('planned-mismatch', `Entry ${i}: planned entries must come first`)); }
    if (e.kind === 'amended') {
      const original = attempts.get(e.retryOf);
      if (state) { problems.push(problem('duplicate-attempt', `Entry ${i}: Duplicate attempt ID`)); return; }
      if (attempts.size >= MAX_ATTEMPTS) { problems.push(problem('attempt-limit', `Entry ${i}: too many attempts`)); return; }
      if (!original || original.status !== 'errored' || original.retriedBy !== null) { problems.push(problem('bad-retry', `Entry ${i}: Invalid retry: the retried attempt must exist, be errored and not already retried`)); return; }
      if (e.subjectDigest !== original.subjectDigest || !plan.subjects.includes(e.subjectDigest)) { problems.push(problem('bad-retry', `Entry ${i}: Invalid retry: a retry keeps the original subject`)); return; }
      original.retriedBy = e.attemptId;
      attempts.set(e.attemptId, { status: 'planned', subjectDigest: e.subjectDigest, scenarioSetDigest: e.scenarioSetDigest, seed: e.seed, amended: true, retriedBy: null, retryOf: e.retryOf });
      return;
    }
    if (!state) { problems.push(problem('not-planned', `Entry ${i}: Attempt is not planned`)); return; }
    const allowed = { started: ['planned'], completed: ['started'], errored: ['started'], abandoned: ['planned', 'started'] }[e.kind];
    if (!allowed.includes(state.status)) { problems.push(problem('bad-transition', `Entry ${i}: Invalid transition ${state.status} to ${e.kind}`)); return; }
    state.status = e.kind === 'started' ? 'started' : e.kind;
    if (e.kind === 'completed') { state.runId = e.runId; state.evidenceBundleDigest = e.evidenceBundleDigest; }
  }

  if (requireClosed) for (const [id, s] of attempts) if (!TERMINAL.has(s.status)) problems.push(problem('unaccounted-attempt', `Attempt ${id} has no terminal entry`));
  return { problems, attempts, plan, issuer };
}

function summarize(plan, attempts) {
  const counts = { completed: 0, errored: 0, abandoned: 0 }, open = [];
  let amendments = 0;
  for (const [id, s] of attempts) {
    if (TERMINAL.has(s.status)) counts[s.status] += 1; else open.push(id);
    if (s.amended) amendments += 1;
  }
  // Unaccounted attempts stay in the denominator: planned is never reduced by non-completion.
  return { campaignId: plan.campaignId, planned: attempts.size, ...counts, unaccounted: open.length, unaccountedAttemptIds: open, amendments, closed: open.length === 0 };
}

export function verifyLedger(ledger, options = {}) {
  try {
    const { problems, attempts, plan } = replay(JSON.parse(canonical(ledger)), options);
    return { valid: problems.length === 0, problems, closed: plan ? summarize(plan, attempts).closed : false, summary: plan && problems.length === 0 ? summarize(plan, attempts) : null };
  } catch (error) {
    return { valid: false, problems: [problem('malformed', `Ledger is malformed: ${error.message}`)], closed: false, summary: null };
  }
}

function checked(ledger, label = 'Ledger') {
  const result = replay(JSON.parse(canonical(ledger)));
  if (result.problems.length) throw new Error(`${label} failed verification: ${result.problems[0].message}`);
  return result;
}
function assertIssuer(issuer, key) {
  insist(keyId(publicPem(key)) === issuer.keyId, 'Signing key is not the campaign capture issuer');
}
function chainHead(ledger) {
  const last = ledger.entries.at(-1);
  return { prevDigest: digest(last ?? ledger.plan), seq: ledger.entries.length };
}
function build(ledger, planDigest, plan, fields, key) {
  const { prevDigest, seq } = chainHead(ledger);
  const payload = { schema: 'kya.campaign-ledger-entry/v1', campaignId: plan.campaignId, planDigest, seq, prevDigest, ...fields };
  return signEntry(payload, key);
}

export function openLedger({ plan, privateKey, now } = {}) {
  const key = privateKeyObject(privateKey), verified = verifyPlan(plan);
  assertIssuer(verified, key);
  timestamp(now, 'Ledger open time');
  insist(Date.parse(now) >= Date.parse(verified.payload.createdAt), 'Ledger opens before the plan commitment');
  const planDigest = digest(plan);
  let ledger = { schema: 'kya.campaign-ledger/v1', plan: JSON.parse(canonical(plan)), entries: [] };
  for (const a of verified.payload.attempts) ledger = { ...ledger, entries: [...ledger.entries, build(ledger, planDigest, verified.payload, { kind: 'planned', attemptId: a.attemptId, at: now }, key)] };
  checked(ledger);
  return ledger;
}

/** Returns a new ledger; never mutates or rewrites history. The existing ledger must verify first. */
export function appendEntry({ ledger, privateKey, entry } = {}) {
  const key = privateKeyObject(privateKey), existing = checked(ledger);
  assertIssuer(existing.issuer, key);
  insist(entry && typeof entry === 'object' && ENTRY_KINDS.includes(entry.kind), 'Unknown ledger entry kind');
  insist(entry.kind !== 'planned', 'Planned entries are written only by openLedger from the signed plan');
  exactKeys(entry, entryFields(entry.kind), 'Ledger entry fields');
  const planDigest = digest(ledger.plan);
  const next = { ...JSON.parse(canonical(ledger)), };
  next.entries = [...next.entries, build(ledger, planDigest, existing.plan, JSON.parse(canonical(entry)), key)];
  const result = replay(next);
  if (result.problems.length) throw new Error(result.problems[0].message.replace(/^Entry \d+: /, ''));
  return next;
}

/** Per-attempt state of a verified ledger, in planning order. Used by the runner. */
export function attemptStates(ledger) {
  const { attempts } = checked(ledger);
  return new Map([...attempts].map(([id, s]) => [id, { ...s }]));
}

export function summarizeCampaign(ledger) {
  const { plan, attempts } = checked(ledger);
  return summarize(plan, attempts);
}
