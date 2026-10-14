import assert from 'node:assert/strict';
import { assess, checkCurrency, signEvidence, signIncident, verifyAssessment, keyId, digest, hashBytes, DIMENSIONS } from '../src/index.mjs';
import { manifest, profile, policy, payload, keys, signerId, publicKey, evaluatorDigest, NOW, FUTURE } from './helpers.mjs';
import { property, keyPool, stat, clone } from './helpers-fuzz.mjs';

const CHECK = '2026-10-13T12:30:00.000Z';
const AT = Date.parse(CHECK);
const TIMES = ['2026-10-13T11:00:00.000Z', '2026-10-13T11:59:59.999Z', NOW, '2026-10-13T12:15:00.000Z', '2026-10-13T12:29:59.999Z', CHECK, '2026-10-13T12:30:00.001Z', '2026-10-13T13:30:00.000Z', '2027-01-01T00:00:00.000Z'];
const IDS = ['i1', 'i2', 'i3'];
const stable = v => JSON.parse(JSON.stringify(v));

// ---------------------------------------------------------------- incidents
function currencySetup(rng) {
  const m = manifest(), p = profile(), pol = policy(p);
  const roles = new Map(); // keyId -> role of pool keys; absent means untrusted
  const revoked = new Set();
  for (const k of keyPool) {
    const role = rng.pick(['self', 'independent', 'independent', 'none']);
    if (role !== 'none') { pol.trustedKeys.push({ id: keyId(k.pem), publicKey: k.pem, role }); roles.set(keyId(k.pem), role); if (rng.bool(0.15)) { pol.revokedKeyIds.push(keyId(k.pem)); revoked.add(keyId(k.pem)); } }
  }
  roles.set(signerId, 'self');
  const report = assess({ manifest: m, profile: p, policy: pol, evidence: [], evaluatorDigest, now: NOW });
  return { m, pol, roles, revoked, report };
}
function randomIncidentRecord(rng, subject) {
  const kind = rng.pick(['report', 'report', 'resolution', 'resolution', 'appeal']);
  const id = rng.pick(IDS);
  const refId = kind === 'report' ? null : rng.pick([...IDS.filter(x => x !== id), 'unknown']);
  const payloadObj = { schema: 'kya.incident/v1', id, subjectDigest: rng.bool(0.1) ? hashBytes('other-subject') : subject, kind, severity: rng.pick(['low', 'medium', 'high', 'critical', 'critical']), refId, reportedAt: rng.pick(TIMES), detailsDigest: hashBytes('d' + rng.int(0, 3)) };
  const keyIndex = rng.int(0, keyPool.length); // the extra slot is the evidence signer key
  const signer = keyIndex === keyPool.length ? keys.privateKey : keyPool[keyIndex].privateKey;
  return { payload: payloadObj, envelope: signIncident(payloadObj, signer) };
}
function junk(rng, sample) {
  const e = clone(sample);
  return rng.pick([() => { e.proof.signature = 'A'.repeat(86); return e; }, () => ({ payload: e.payload }), () => 'text', () => null, () => 7, () => [], () => { e.payload.severity = 'urgent'; return e; }, () => { e.payload.id = 'tampered'; return e; }])();
}
// Independent restatement of the documented rules (checkCurrency comment block in currency.mjs).
function oracle(records, subject, roles, revoked) {
  const seen = new Set(), eligible = [];
  for (const { payload: pl, envelope } of records) {
    const k = envelope.proof.keyId, sig = k + '|' + digest(pl);
    if (seen.has(sig)) continue; seen.add(sig);
    if (!roles.has(k) || revoked.has(k) || pl.subjectDigest !== subject) continue;
    eligible.push({ ...pl, keyId: k, role: roles.get(k), future: Date.parse(pl.reportedAt) > AT });
  }
  const blocking = s => s === 'high' || s === 'critical';
  const live = eligible.filter(e => e.kind === 'report' && (!e.future || blocking(e.severity)));
  const groups = new Map();
  for (const e of eligible.filter(e => e.kind !== 'report')) groups.set(e.keyId + '|' + e.id, [...(groups.get(e.keyId + '|' + e.id) ?? []), e]);
  const resolvedKeys = new Set(), appealed = new Set();
  for (const g of groups.values()) {
    if (g.length > 1) continue;
    const e = g[0]; if (e.future) continue;
    const targets = live.filter(r => r.id === e.refId); if (targets.length !== 1) continue;
    const t = targets[0];
    if (e.kind === 'appeal') appealed.add(t.id);
    else if (e.role === 'independent' && t.keyId !== e.keyId && Date.parse(e.reportedAt) > Date.parse(t.reportedAt)) resolvedKeys.add(t.keyId + '|' + t.id);
  }
  const ids = l => [...new Set(l.map(r => r.id))].sort();
  const blockers = live.filter(r => blocking(r.severity)), isRes = r => resolvedKeys.has(r.keyId + '|' + r.id);
  const open = ids(blockers.filter(r => !isRes(r)));
  return { open, resolved: ids(blockers.filter(isRes)).filter(id => !open.includes(id)), appealed: [...appealed].sort(), observed: ids(live.filter(r => !blocking(r.severity))), eligible };
}
const view = r => ({ open: r.incidents.open, resolved: r.incidents.resolved, appealed: r.incidents.appealed, observed: r.incidents.observed, triggers: r.triggers.map(t => t.id), current: r.current, reliable: r.reliable, action: r.action });
const sortedIgnored = r => r.incidents.ignored.map(x => JSON.stringify(x)).sort();

property('checkCurrency matches the documented incident rules and the stated invariants on random incident sets', 50, (rng) => {
  const { m, pol, roles, revoked, report } = currencySetup(rng);
  const records = Array.from({ length: rng.int(0, 9) }, () => randomIncidentRecord(rng, report.subjectDigest));
  const reportsMade = records.filter(r => r.payload.kind === 'report');
  const indepKeys = keyPool.filter(k => roles.get(keyId(k.pem)) === 'independent');
  if (reportsMade.length && indepKeys.length && rng.bool(0.6)) {
    const target = rng.pick(reportsMade).payload;
    const pl = { ...target, id: rng.pick(IDS.map(x => 'x' + x)), kind: rng.pick(['resolution', 'resolution', 'appeal']), severity: 'low', refId: target.id, reportedAt: rng.bool(0.8) ? (TIMES.find(t => t > target.reportedAt && Date.parse(t) <= AT) ?? target.reportedAt) : rng.pick(TIMES.slice(1, 6)), detailsDigest: hashBytes('pair') };
    records.push({ payload: pl, envelope: signIncident(pl, rng.pick(indepKeys).privateKey) });
  }
  let envelopes = records.map(r => r.envelope);
  for (let n = rng.int(0, 3); n > 0 && records.length; n--) envelopes.push(clone(rng.pick(envelopes)));  // duplicated delivery
  const junkCount = rng.int(0, 2); if (records.length) for (let n = 0; n < junkCount; n++) envelopes.push(junk(rng, records[0].envelope));
  envelopes = rng.shuffle(envelopes);
  const ctx = incidents => ({ manifest: m, policy: pol, now: CHECK, incidents });
  const before = clone(envelopes);
  const r = checkCurrency(report, ctx(envelopes));
  assert.deepEqual(envelopes, before, 'inputs mutated');
  assert.equal(r.incidents.considered, envelopes.length);

  // oracle
  const o = oracle(records, report.subjectDigest, roles, revoked);
  assert.deepEqual({ open: r.incidents.open, resolved: r.incidents.resolved, appealed: r.incidents.appealed, observed: r.incidents.observed }, { open: o.open, resolved: o.resolved, appealed: o.appealed, observed: o.observed });

  for (const k of ['open', 'resolved', 'appealed', 'observed']) if (r.incidents[k].length) stat('incidents.' + k);
  if (r.incidents.ignored.length) stat('incidents.ignored');
  // trigger invariants
  const fired = r.triggers.length > 0;
  assert.equal(r.current, !fired); assert.equal(r.action, fired ? 'reassess' : 'none'); assert.equal(r.reliable, !fired && report.decision === 'qualified');
  assert.equal(r.triggers.some(t => t.id === 'incident-open'), o.open.length > 0);
  if (o.open.length) { assert.equal(r.current, false); assert.equal(r.action, 'reassess'); assert.equal(r.reliable, false); }

  // an unresolved trusted blocking report with a unique ID and no valid independent resolution is always open
  for (const e of o.eligible.filter(x => x.kind === 'report' && ['high', 'critical'].includes(x.severity))) {
    // F-1 (docs/lane-d-findings.md): a future-dated non-blocking copy of the ID is dropped before ambiguity is judged, so only copies that are live count here.
    const sameId = o.eligible.filter(x => x.kind === 'report' && x.id === e.id && (!x.future || ['high', 'critical'].includes(x.severity))).length;
    const candidates = o.eligible.filter(x => x.kind === 'resolution' && x.refId === e.id && x.role === 'independent' && x.keyId !== e.keyId && Date.parse(x.reportedAt) > Date.parse(e.reportedAt) && !x.future);
    if (sameId > 1 || !candidates.length) assert.ok(r.incidents.open.includes(e.id), `report ${e.id} must stay open (copies=${sameId}, candidates=${candidates.length})`);
  }

  // permutation invariance (including duplicated delivery): everything except the order of the ignored list
  const shuffled = checkCurrency(report, ctx(rng.shuffle(envelopes)));
  assert.deepEqual(view(shuffled), view(r));
  assert.equal(shuffled.incidents.considered, r.incidents.considered);
  assert.deepEqual(sortedIgnored(shuffled), sortedIgnored(r));

  // adding records that must be inert: untrusted key, other subject, malformed
  const strangers = [];
  const strangerKey = keyPool.find(k => !roles.has(keyId(k.pem)));
  if (strangerKey) { const x = randomIncidentRecord(rng, report.subjectDigest).payload; strangers.push(signIncident(x, strangerKey.privateKey)); }
  const otherSubject = randomIncidentRecord(rng, hashBytes('someone else')).payload; otherSubject.subjectDigest = hashBytes('someone else ' + rng.int(0, 9));
  strangers.push(signIncident(otherSubject, rng.pick([keys.privateKey, ...keyPool.map(k => k.privateKey)])));
  const augmented = checkCurrency(report, ctx(rng.shuffle([...envelopes, ...strangers])));
  assert.deepEqual(view(augmented), view(r), 'an inert record changed the outcome');
  assert.equal(augmented.incidents.considered, envelopes.length + strangers.length);
});

property('equal timestamps, future dates and shared IDs never let a resolution close a report it should not', 40, (rng) => {
  const { m, pol, roles, revoked, report } = currencySetup(rng);
  const subject = report.subjectDigest;
  const indep = keyPool.filter(k => roles.get(keyId(k.pem)) === 'independent' && !revoked.has(keyId(k.pem)));
  if (indep.length < 1) return;
  const usable = keyPool.filter(k => roles.has(keyId(k.pem)) && !revoked.has(keyId(k.pem))), reporter = usable.length && rng.bool(0.75) ? rng.pick(usable) : rng.pick(keyPool);
  const others = indep.filter(k => k !== reporter), resolver = others.length && rng.bool(0.85) ? rng.pick(others) : rng.pick(indep);
  const t = rng.pick(TIMES.slice(0, 5));
  const rep = { schema: 'kya.incident/v1', id: 'i1', subjectDigest: subject, kind: 'report', severity: rng.pick(['high', 'critical']), refId: null, reportedAt: t, detailsDigest: hashBytes('r') };
  const delta = rng.pick([0, -1, 1, 1000]);
  const res = { ...rep, kind: rng.pick(['resolution', 'appeal']), severity: 'low', refId: 'i1', id: 'r1', reportedAt: new Date(Date.parse(t) + delta).toISOString(), detailsDigest: hashBytes('x') };
  const envs = [signIncident(rep, reporter.privateKey), signIncident(res, resolver.privateKey)];
  const r = checkCurrency(report, { manifest: m, policy: pol, now: CHECK, incidents: rng.shuffle(envs) });
  const reporterTrusted = roles.has(keyId(reporter.pem)) && !revoked.has(keyId(reporter.pem));
  const sameKey = keyId(reporter.pem) === keyId(resolver.pem);
  const shouldClose = reporterTrusted && res.kind === 'resolution' && !sameKey && delta > 0 && Date.parse(res.reportedAt) <= AT;
  stat('pair.' + (shouldClose ? 'closes' : 'stays-open-or-untrusted'));
  if (!reporterTrusted) assert.deepEqual(r.incidents.open, []);
  else assert.equal(r.incidents.open.length === 0, shouldClose, `delta=${delta} kind=${res.kind} sameKey=${sameKey}`);
  assert.equal(r.current, r.incidents.open.length === 0);
});

// ---------------------------------------------------------------- assess
function randomProfile(rng) {
  const n = rng.int(1, 10);
  return { schema: 'kya.profile/v1', id: 'fuzz-profile', version: '1', title: 'Fuzzed profile', checks: Array.from({ length: n }, (_, i) => ({ id: `c${i}`, dimension: rng.pick(DIMENSIONS), title: `check ${i}`, weight: rng.pick([1, 1, 2, 3, 7, 10, 100, 999, 1000, 100_000, rng.int(1, 5000)]), critical: rng.bool(0.3) })) };
}
function randomAssessCase(rng, { singleRun = false, conflictFree = false } = {}) {
  const m = manifest(), p = randomProfile(rng), pol = policy(p);
  pol.minCoverage = rng.pick([0, 0.5, 1, rng.next()]); pol.minScore = rng.pick([0, 500, 800, 1000, rng.int(0, 1000)]); pol.minIndependentCoverage = rng.pick([0, 0, 0.5]);
  pol.allowedSources = ['fixture', 'runtime']; pol.maxEvidenceAgeSeconds = rng.pick([3600, 7200, 86_400]);
  pol.trustedKeys.push({ id: keyId(keyPool[0].pem), publicKey: keyPool[0].pem, role: 'independent' });
  if (rng.bool(0.05)) pol.revokedSubjectDigests.push(digest(m));
  if (rng.bool(0.1)) pol.requirePrincipalBinding = true;
  const signers = [keys.privateKey, keyPool[0].privateKey];
  const runIds = singleRun ? ['run-1'] : ['run-1', 'run-2', 'run-3'];
  const stamps = ['2026-10-13T11:00:00.000Z', '2026-10-13T11:30:00.000Z', '2026-10-13T11:59:59.999Z', NOW];
  const evidence = [], used = new Set();
  const loneSigner = rng.pick(signers);
  const near = rng.bool(0.4), count = near ? p.checks.length : rng.int(0, p.checks.length * (singleRun ? 1 : 2));
  if (near) { pol.minCoverage = rng.pick([0, 0.5, 1]); pol.minScore = rng.pick([0, 500, 800]); pol.minIndependentCoverage = 0; delete pol.requirePrincipalBinding; }
  for (let n = 0; n < count; n++) {
    const i = near ? n : rng.int(0, p.checks.length - 1), runId = near ? 'run-1' : rng.pick(runIds);
    if (conflictFree && used.has(i)) continue; used.add(i);
    const patch = { runId, outcome: near && rng.bool(0.92) ? 'pass' : rng.pick(['pass', 'pass', 'pass', 'fail', 'abstain', 'error']), source: near ? 'fixture' : rng.pick(['fixture', 'runtime']), observedAt: near ? NOW : rng.pick(stamps), id: conflictFree || rng.bool(0.9) ? `e-${n}` : `e-${rng.int(0, 2)}` };
    evidence.push(signEvidence(payload(m, p, i, patch), singleRun || conflictFree || near ? loneSigner : rng.pick(signers)));
  }
  if (!conflictFree && rng.bool(0.15)) evidence.push(rng.pick([null, 5, 'x', {}, { payload: {}, proof: {} }, [1]]));
  return { manifest: m, profile: p, policy: pol, evidence, evaluatorDigest, now: NOW };
}

property('assess keeps a fixed denominator and bounded scores for random evidence', 60, (rng) => {
  const i = randomAssessCase(rng);
  const snapshot = clone(i);
  const r = assess(i);
  stat('assess.' + r.decision);
  assert.deepEqual(i, snapshot, 'assess mutated its input');
  assert.equal(r.checks.length, i.profile.checks.length);
  assert.deepEqual(r.checks.map(c => [c.id, c.weight, c.critical, c.dimension]), i.profile.checks.map(c => [c.id, c.weight, c.critical, c.dimension]));
  assert.ok(r.checks.every(c => ['pass', 'fail', 'abstain', 'error', 'unknown'].includes(c.status)));
  assert.equal(r.score.possible, 1000);
  assert.ok(Number.isInteger(r.score.earned) && r.score.earned >= 0 && r.score.earned <= r.score.upperBound && r.score.upperBound <= 1000, JSON.stringify(r.score));
  assert.ok(r.coverage >= 0 && r.coverage <= 1 && r.independentCoverage >= 0 && r.independentCoverage <= r.coverage + 1e-6);
  assert.equal(r.dimensions.reduce((s, d) => s + d.weight, 0), i.profile.checks.reduce((s, c) => s + c.weight, 0));
  for (const d of r.dimensions) assert.ok(d.earned >= 0 && d.earned <= d.upperBound && d.upperBound <= d.possible);
  const unknownWeight = r.checks.filter(c => !['pass', 'fail'].includes(c.status)).reduce((s, c) => s + c.weight, 0), total = r.checks.reduce((s, c) => s + c.weight, 0);
  const exact = num => Number(BigInt(num) * 1000n / BigInt(total)), passWeight = r.checks.filter(c => c.status === 'pass').reduce((s, c) => s + c.weight, 0);
  assert.equal(r.score.earned, exact(passWeight), 'earned must be exact integer arithmetic');
  assert.equal(r.score.upperBound, exact(passWeight + unknownWeight), 'upperBound must be exact integer arithmetic');
  assert.deepEqual(verifyAssessment(r).reportDigest, r.reportDigest);
  // same inputs, same report; and the report is identical for an empty bundle on the same profile only in its denominator
  assert.deepEqual(assess(i), r);
  const empty = assess({ ...i, evidence: [] });
  assert.equal(empty.checks.length, r.checks.length);
  assert.deepEqual(empty.score, { earned: 0, possible: 1000, upperBound: 1000 });
  assert.notEqual(empty.decision, 'qualified');
});

property('a critical failure or unproven critical check never yields qualified', 60, (rng) => {
  const i = randomAssessCase(rng);
  const r = assess(i), byId = new Map(i.profile.checks.map(c => [c.id, c]));
  const critical = r.checks.filter(c => byId.get(c.id).critical);
  if (r.decision === 'qualified') {
    assert.ok(critical.every(c => c.status === 'pass'), 'qualified with a non passing critical check');
    assert.ok(r.coverage >= i.policy.minCoverage - 1e-6 && r.score.earned >= i.policy.minScore && r.checks.some(c => ['pass', 'fail'].includes(c.status)));
    assert.ok(r.independentCoverage >= i.policy.minIndependentCoverage - 1e-6);
    assert.equal(r.ambiguousRuns, false);
  }
  if (critical.some(c => c.status === 'fail')) assert.equal(r.decision, i.policy.revokedSubjectDigests.length ? 'revoked' : 'blocked');
  if (i.policy.revokedSubjectDigests.length) assert.equal(r.decision, 'revoked');
  assert.equal(r.blockers.length > 0, r.decision !== 'qualified');
});

property('removing evidence from a conflict free single run never raises earned score or creates a qualification', 60, (rng) => {
  const i = randomAssessCase(rng, { singleRun: true, conflictFree: true });
  if (!i.evidence.length) return;
  const r = assess(i);
  const drop = rng.int(0, i.evidence.length - 1);
  const smaller = assess({ ...i, evidence: i.evidence.filter((_, k) => k !== drop) });
  assert.ok(smaller.score.earned <= r.score.earned, `earned rose ${r.score.earned} -> ${smaller.score.earned}`);
  assert.ok(smaller.coverage <= r.coverage + 1e-9);
  assert.equal(smaller.checks.length, r.checks.length);
  // Bound but invalid evidence (stale, expired, revoked, disallowed source) vetoes qualification by design, so omitting
  // it can lift the veto; that omission limit is O-4 in docs/lane-d-findings.md. Without any rejected record none exists.
  if (r.decision !== 'qualified' && r.rejectedEvidence.length === 0) assert.notEqual(smaller.decision, 'qualified', `removing evidence turned ${r.decision} (${r.blockers.join('; ')}) into qualified; dropped #${drop} of ${i.evidence.length}`);
  // dropping everything is the floor
  assert.equal(assess({ ...i, evidence: [] }).score.earned, 0);
});

property('assessment outcome does not depend on the order of the evidence bundle', 40, (rng) => {
  const i = randomAssessCase(rng);
  const a = assess(i), b = assess({ ...i, evidence: rng.shuffle(i.evidence) });
  // Tied duplicate observations of one check (same outcome and time) are resolved by bundle order. That only moves
  // role/issuer fields, never the decision or score: a repeated check already forces insufficient-evidence unless a higher precedence decision applies (docs/lane-d-findings.md, O-2).
  const seenPairs = new Set(); let tied = false;
  for (const e of i.evidence) { const k = e && e.payload && e.payload.runId === a.selectedRunId ? e.payload.checkId : null; if (k !== null) { if (seenPairs.has(k)) tied = true; seenPairs.add(k); } }
  const core = r => ({ decision: r.decision, score: r.score, coverage: r.coverage, independentCoverage: tied ? null : r.independentCoverage, selectedRunId: r.selectedRunId, ambiguousRuns: r.ambiguousRuns, statuses: r.checks.map(c => [c.id, c.status, tied ? null : c.independence]), dimensions: r.dimensions, validUntil: r.validUntil, blockers: [...r.blockers].sort() });
  assert.deepEqual(core(b), core(a));
});
