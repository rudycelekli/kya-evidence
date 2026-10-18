import test from 'node:test';
import assert from 'node:assert/strict';
import { assess, checkCurrency, signEvidence, signIncident, canonical, digest, hashBytes, keyId } from '../src/index.mjs';
import { manifest, profile, policy, payload, keys, signerId, evaluatorDigest, NOW, FUTURE } from './helpers.mjs';
import { property, keyPool, clone } from './helpers-fuzz.mjs';

// Metamorphic tests: relations between two runs of the core that a standard must guarantee, each also tried as an attack.
// Generators are seeded and deterministic (helpers-fuzz.mjs). Small inputs: six checks, at most two runs.
// Known limits, by design and documented, are pinned separately below instead of being hidden by a weak generator.

const MIN = 60_000;
const NOWMS = Date.parse(NOW);
const iso = ms => new Date(ms).toISOString();
const independent = keyPool[0];
const independentId = keyId(independent.pem);
const qualifies = r => r.decision === 'qualified';
const stats = { worlds: 0, qualified: 0 };

// A world: manifest, profile, policy and a small evidence bundle drawn from the rng. About half the worlds are clean.
function world(rng, { unique = false, singleRun = false, oneEach = false } = {}) {
  const m = manifest(), p = profile(), pol = policy(p);
  pol.trustedKeys.push({ id: independentId, publicKey: independent.pem, role: 'independent' });
  pol.minScore = rng.pick([0, 500, 800, 1000]); pol.minCoverage = rng.pick([0, 0.5, 0.8, 1]);
  const clean = rng.bool(0.5), evidence = [];
  if (clean) { pol.minScore = 800; pol.minCoverage = 1; pol.minIndependentCoverage = 0; }
  p.checks.forEach((_, i) => {
    const copies = clean ? 1 : oneEach ? rng.pick([0, 1, 1, 1]) : rng.pick([0, 1, 1, 1, 2]);
    for (let k = 0; k < copies; k++) {
      const second = !singleRun && !clean && rng.bool(0.25);
      const patch = {
        id: unique ? `ev-${i}-${k}` : rng.bool(0.15) ? `ev-${i}` : `ev-${i}-${k}`,
        runId: second ? 'run-2' : 'run-1',
        outcome: clean ? 'pass' : rng.pick(['pass', 'pass', 'pass', 'fail', 'abstain', 'error']),
        observedAt: iso(NOWMS - (second ? 0 : rng.int(1, 3)) * MIN),
        expiresAt: !clean && rng.bool(0.1) ? iso(NOWMS - MIN) : FUTURE,
      };
      if (patch.expiresAt <= patch.observedAt) patch.expiresAt = iso(Date.parse(patch.observedAt) + MIN);
      const key = !clean && rng.bool(0.3) ? independent.privateKey : keys.privateKey;
      evidence.push(signEvidence(payload(m, p, i, patch), key));
    }
  });
  return { manifest: m, profile: p, policy: pol, evidence, evaluatorDigest, now: NOW };
}
const run = x => assess(clone(x));
const note = r => { stats.worlds++; if (qualifies(r)) stats.qualified++; return r; };

// (a) Adding a valid revocation never improves the outcome. Attack variants: revoke the signer, one receipt, the subject,
// or one of two receipts that share an ID (the survivor must not become unique and count).
property('metamorphic a: adding a revocation never improves the decision or raises the earned score', 60, rng => {
  const x = world(rng), base = note(run(x)), y = clone(x);
  const pick = rng.pick(['key', 'evidence', 'subject', 'dup']);
  if (pick === 'key') y.policy.revokedKeyIds.push(rng.pick([signerId, independentId]));
  else if (pick === 'subject') y.policy.revokedSubjectDigests.push(digest(x.manifest));
  else if (pick === 'dup') { const ids = x.evidence.map(e => e.payload.id), d = ids.find((id, i) => ids.indexOf(id) !== i); y.policy.revokedEvidenceIds.push(d ?? ids[0] ?? 'ev-none'); }
  else y.policy.revokedEvidenceIds.push(rng.pick(x.evidence.length ? x.evidence.map(e => e.payload.id) : ['ev-none']));
  const after = run(y);
  assert.ok(!(qualifies(after) && !qualifies(base)), 'revocation produced a qualification');
  assert.ok(after.score.earned <= base.score.earned, 'revocation raised the earned score');
  assert.ok(after.coverage <= base.coverage, 'revocation raised coverage');
});

property('metamorphic a: adding a trusted open incident never makes a reliable assessment more reliable', 25, rng => {
  const x = world(rng), report = note(run(x));
  const ctx = (incidents, extra = {}) => ({ manifest: clone(x.manifest), policy: clone(x.policy), now: iso(NOWMS + MIN), incidents, ...extra });
  const rec = (patch = {}, key = keys.privateKey) => signIncident({ schema: 'kya.incident/v1', id: 'inc:1', subjectDigest: report.subjectDigest, kind: 'report', severity: rng.pick(['high', 'critical']), refId: null, reportedAt: NOW, detailsDigest: hashBytes('detail'), ...patch }, key);
  const before = checkCurrency(report, ctx([]));
  const open = rec(), r1 = checkCurrency(report, ctx([open]));
  assert.ok(!(r1.reliable && !before.reliable) && !(r1.current && !before.current));
  assert.equal(r1.current, false); assert.ok(r1.triggers.some(t => t.id === 'incident-open'));
  // Attacks that try to launder the open incident back to current: delivering it twice, an appeal, a self resolution,
  // a resolution dated before the report, and a resolution from an untrusted key.
  const stranger = keyPool[3];
  const attacks = [[open, open], [open, rec({ id: 'app:1', kind: 'appeal', severity: 'low', refId: 'inc:1' })], [open, rec({ id: 'res:1', kind: 'resolution', severity: 'low', refId: 'inc:1', reportedAt: iso(NOWMS + 30_000) })],
    [open, rec({ id: 'res:1', kind: 'resolution', severity: 'low', refId: 'inc:1', reportedAt: iso(NOWMS - MIN) }, independent.privateKey)],
    [open, rec({ id: 'res:1', kind: 'resolution', severity: 'low', refId: 'inc:1', reportedAt: iso(NOWMS + 30_000) }, stranger.privateKey)]];
  for (const set of attacks) { const r = checkCurrency(report, ctx(rng.shuffle(set))); assert.equal(r.current, false); assert.equal(r.reliable, false); }
});

// (b) Removing evidence never turns not-qualified into qualified. Holds for a single run of unique receipts. The general
// statement is false by design when a check has several receipts or a newer run exists (see the pinned omission limits
// below), so the generator is stated, not weakened silently.
property('metamorphic b: removing a receipt from a single run with one receipt per check never creates a qualification', 60, rng => {
  const x = world(rng, { unique: true, singleRun: true, oneEach: true }), base = note(run(x));
  if (!x.evidence.length) return;
  const y = clone(x); y.evidence.splice(rng.int(0, y.evidence.length - 1), 1);
  const after = run(y);
  if (!qualifies(base)) assert.ok(!qualifies(after), 'removal produced a qualification');
  assert.ok(after.score.earned <= base.score.earned, 'removal raised the earned score');
  assert.ok(after.coverage <= base.coverage, 'removal raised coverage');
});

test('metamorphic b limit: omission can drop a failure or a conflict, so completeness needs a bundle commitment, not the core', () => {
  const x = world({ int: () => 0, bool: () => true, pick: a => a[0], shuffle: a => a, next: () => 0 }, { unique: true, singleRun: true });
  const m = x.manifest, p = x.profile;
  const failing = signEvidence(payload(m, p, 0, { id: 'ev-fail', outcome: 'fail', runId: 'run-2', observedAt: NOW }), keys.privateKey);
  const full = { ...clone(x), evidence: [...clone(x.evidence), failing] }, omitted = { ...clone(x) };
  assert.equal(assess(full).decision, 'blocked');
  assert.notEqual(assess(omitted).evidenceBundleDigest, assess(full).evidenceBundleDigest);
  // Duplicate-ID quarantine can also be undone by omitting one copy.
  const twin = signEvidence(payload(m, p, 1, { id: x.evidence[1].payload.id, artifactDigest: hashBytes('other') }), keys.privateKey);
  const conflicted = { ...clone(x), evidence: [...clone(x.evidence), twin] };
  assert.ok(assess(conflicted).blockerCodes.includes('RUN_CONFLICT'));
  // Two observations of one check in one run (conservative pick, REPEATED_RUN_CHECKS): omitting the failing one qualifies.
  const retry = signEvidence(payload(m, p, 0, { id: 'ev-retry', outcome: 'fail', observedAt: iso(NOWMS - MIN) }), keys.privateKey);
  const repeated = { ...clone(x), evidence: [...clone(x.evidence), retry] };
  assert.equal(assess(repeated).decision, 'blocked');
  assert.equal(assess(clone(x)).decision, 'qualified');
});

// (c) Permuting input order never changes the decision. The report digest commits to the supplied order by design
// (SCORING.md: evidenceBundleDigest is in input order, rejectedEvidence carries the index), so equality is asserted on
// everything except those order-bearing members, and the digest is asserted equal for the identical order.
const orderFree = r => { const { reportDigest, evidenceBundleDigest, rejectedEvidence, ...rest } = r; return { ...rest, rejected: rejectedEvidence.map(e => `${e.id}|${e.reason}`).sort() }; };
property('metamorphic c: permuting the evidence order never changes the decision or any order-free member', 60, rng => {
  const x = world(rng), base = note(run(x)), y = clone(x); y.evidence = rng.shuffle(y.evidence);
  const after = run(y);
  assert.equal(after.decision, base.decision);
  assert.deepEqual(orderFree(after), orderFree(base));
  assert.equal(run(x).reportDigest, base.reportDigest);
  const z = clone(x); z.policy.trustedKeys = rng.shuffle(z.policy.trustedKeys);
  assert.equal(run(z).decision, base.decision);
});

// (d) A later timestamp never revives an expired assessment.
property('metamorphic d: at or after validUntil neither assess nor checkCurrency treats the assessment as live', 40, rng => {
  const x = world(rng), report = note(run(x)), end = Date.parse(report.validUntil);
  const ctx = now => ({ manifest: clone(x.manifest), policy: clone(x.policy), now });
  for (const dt of [0, 1, rng.int(2, 1_000_000), 86_400_000 * rng.int(1, 400)]) {
    const t = iso(end + dt), later = assess({ ...clone(x), now: t });
    assert.ok(!qualifies(later), 'a later time revived a qualification');
    const c = checkCurrency(report, ctx(t)); assert.equal(c.current, false); assert.equal(c.reliable, false); assert.ok(c.triggers.some(k => k.id === 'assessment-expired'));
  }
  if (qualifies(report) && end - 1 >= NOWMS) {
    assert.ok(qualifies(assess({ ...clone(x), now: iso(end - 1) })));
    assert.equal(checkCurrency(report, ctx(iso(end - 1))).reliable, true);
  }
});

// (e) Duplicating an evidence item. By design an eligible duplicate evidence ID is quarantined, so duplication does change
// the score, always downward and never to a qualification. The safe direction is asserted, and the exact behavior pinned.
property('metamorphic e: duplicating a receipt never improves the outcome or raises the score', 60, rng => {
  const x = world(rng), base = note(run(x));
  if (!x.evidence.length) return;
  const y = clone(x); y.evidence.splice(rng.int(0, y.evidence.length), 0, clone(rng.pick(x.evidence)));
  const after = run(y);
  assert.ok(!(qualifies(after) && !qualifies(base)));
  assert.ok(after.score.earned <= base.score.earned);
});

test('metamorphic e pin: a byte identical duplicate receipt quarantines its own ID and drops a qualified run to insufficient evidence', () => {
  const x = world({ int: () => 0, bool: () => true, pick: a => a[0], shuffle: a => a, next: () => 0 });
  assert.equal(assess(clone(x)).decision, 'qualified');
  const y = clone(x); y.evidence.push(clone(y.evidence[0]));
  const r = assess(y);
  assert.equal(r.decision, 'insufficient-evidence'); assert.ok(r.blockerCodes.includes('RUN_CONFLICT'));
});

test('metamorphic e regression: replaying a failing receipt cannot let a sibling pass count toward the score', () => {
  const x = world({ int: () => 0, bool: () => true, pick: a => a[0], shuffle: a => a, next: () => 0 });
  const m = x.manifest, p = x.profile;
  // Check 4 (not critical): a newer pass and an older failure in one run. The conservative pick keeps the failure.
  const fail = signEvidence(payload(m, p, 4, { id: 'ev-4-fail', outcome: 'fail', observedAt: iso(NOWMS - 2 * MIN) }), keys.privateKey);
  const base = { ...clone(x), evidence: [...clone(x.evidence.filter(e => e.payload.checkId !== 'check-4')), fail, clone(x.evidence[4])] };
  const before = assess(clone(base));
  const replayed = { ...clone(base), evidence: [...clone(base.evidence), clone(fail)] };
  const after = assess(replayed);
  assert.equal(before.checks[4].status, 'fail');
  assert.equal(after.checks[4].status, 'unknown');
  assert.ok(after.score.earned <= before.score.earned && after.coverage <= before.coverage);
  assert.notEqual(after.decision, 'qualified');
});

// (f) Raising a required minimum never increases the set of qualified runs. Strictness steps are applied to a looser
// policy; a world qualified under the stricter policy must also be qualified under the looser one.
const stricter = (pol, rng) => {
  const s = clone(pol);
  rng.pick([() => { s.minScore = Math.min(1000, pol.minScore + rng.int(1, 400)); }, () => { s.minCoverage = Math.min(1, pol.minCoverage + 0.25); },
    () => { s.minIndependentCoverage = Math.min(1, pol.minIndependentCoverage + 0.5); }, () => { s.maxEvidenceAgeSeconds = 120; },
    () => { s.mandatoryMinimums = [{ checkId: `check-${rng.int(0, 5)}`, minimum: rng.pick(['pass', 'independent-pass']) }]; }])();
  return s;
};
property('metamorphic f: raising a required minimum never adds a qualified run', 80, rng => {
  const x = world(rng), loose = note(run(x)), y = clone(x); y.policy = stricter(x.policy, rng);
  const strict = run(y);
  assert.ok(!(qualifies(strict) && !qualifies(loose)), 'a stricter policy qualified a world the looser policy did not');
  const z = clone(y); z.policy = stricter(y.policy, rng);
  assert.ok(!(qualifies(run(z)) && !qualifies(strict)), 'a second step of strictness qualified a world the previous step did not');
});

// (g) The decision is a pure function of canonical inputs: same bytes in, same bytes out, repeatedly, and independent of
// object key order and of mutation of the caller inputs.
const reorder = (v, rng) => Array.isArray(v) ? v.map(e => reorder(e, rng)) : v && typeof v === 'object' ? Object.fromEntries(rng.shuffle(Object.keys(v)).map(k => [k, reorder(v[k], rng)])) : v;
property('metamorphic g: assess and checkCurrency are pure functions of canonical inputs', 40, rng => {
  const x = world(rng), a = assess(clone(x)), b = assess(clone(x));
  assert.equal(canonical(a), canonical(b));
  const shuffled = reorder(clone(x), rng);
  assert.equal(canonical(assess(shuffled)), canonical(a));
  const frozen = clone(x), before = canonical(frozen); assess(frozen); assert.equal(canonical(frozen), before, 'assess mutated its input');
  const ctx = { manifest: x.manifest, policy: x.policy, now: iso(NOWMS + 5 * MIN), incidents: [] };
  const c1 = checkCurrency(a, clone(ctx)), c2 = checkCurrency(reorder(clone(a), rng), reorder(clone(ctx), rng));
  assert.equal(canonical(c1), canonical(c2));
  assert.equal(digest(c1), digest(checkCurrency(a, clone(ctx))));
});

test('metamorphic generators are not vacuous: qualified and not qualified worlds were both exercised', () => {
  assert.ok(stats.worlds > 100);
  assert.ok(stats.qualified > 20, 'too few qualified worlds to make the invariants meaningful');
  assert.ok(stats.qualified < stats.worlds - 20, 'too few not-qualified worlds');
});
