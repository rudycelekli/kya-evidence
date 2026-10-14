// checkCurrency semantics (second implementation). See README.md: team-built, NOT independent.
import { Refusal, digest, isTs, isObj, HEX64, exactKeys, isId, ms, validManifest, validPolicy, verifyProof } from './kya2.mjs';

const refuse = m => { throw new Refusal(m); };
const DECISIONS = ['qualified', 'insufficient-evidence', 'blocked', 'expired', 'revoked'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const INCIDENT_KEYS = ['detailsDigest', 'id', 'kind', 'refId', 'reportedAt', 'schema', 'severity', 'subjectDigest'];

// Verify checksum and internal consistency of a stored assessment before using it.
function checkAssessment(a) {
  if (!isObj(a) || a.schema !== 'kya.assessment/v1') refuse('assessment schema');
  const { reportDigest, ...rest } = a;
  if (typeof reportDigest !== 'string' || !HEX64.test(reportDigest)) refuse('assessment checksum field');
  if (digest(rest) !== reportDigest) refuse('assessment checksum does not match');
  for (const k of ['subjectDigest', 'policyDigest']) if (typeof a[k] !== 'string' || !HEX64.test(a[k])) refuse('assessment ' + k);
  if (!isTs(a.assessedAt) || !isTs(a.validUntil)) refuse('assessment times');
  if (ms(a.validUntil) < ms(a.assessedAt)) refuse('assessment validUntil precedes assessedAt');
  if (!DECISIONS.includes(a.decision)) refuse('assessment decision');
  if (!Array.isArray(a.blockers)) refuse('assessment blockers');
  if (a.blockerCodes !== undefined && (!Array.isArray(a.blockerCodes) || a.blockerCodes.length !== a.blockers.length)) refuse('assessment blockerCodes');
  if (a.decision === 'qualified' && a.blockers.length) refuse('qualified assessment carries blockers');
}

function incidentShape(e) {
  if (!exactKeys(e, ['payload', 'proof'])) return 'envelope must hold payload and proof';
  const p = e.payload;
  if (!exactKeys(p, INCIDENT_KEYS) || p.schema !== 'kya.incident/v1') return 'payload keys or schema';
  if (!isId(p.id)) return 'id';
  if (!['report', 'resolution', 'appeal'].includes(p.kind)) return 'kind';
  if (!SEVERITIES.includes(p.severity)) return 'severity';
  if (!HEX64.test(p.detailsDigest) || !HEX64.test(p.subjectDigest)) return 'digest';
  if (!isTs(p.reportedAt)) return 'time';
  if (p.kind === 'report' ? p.refId !== null : (!isId(p.refId) || p.refId === p.id)) return 'refId';
  return null;
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function processIncidents(incidents, a, policy, nowMs) {
  const ignored = [];
  const trusted = new Map(policy.trustedKeys.map(k => [k.id, k]));
  const revoked = new Set(policy.revokedKeyIds);
  const seenEnv = new Set();
  const recs = []; // honoured-so-far records
  for (const env of incidents) {
    let why = isObj(env) ? incidentShape(env) : 'not an object';
    if (!why) why = verifyProof('kya.incident/v1\n', env.payload, env.proof) && 'signature or key';
    if (why) { ignored.push({ id: null, reason: `Invalid incident record: ${why}` }); continue; }
    const key = digest(env);
    if (seenEnv.has(key)) continue; // identical envelope delivered twice
    seenEnv.add(key);
    const p = env.payload, kid = env.proof.keyId, k = trusted.get(kid);
    if (!k || k.role === 'capture-issuer') { ignored.push({ id: p.id, reason: 'Signing key is not a trusted anchor' }); continue; }
    if (revoked.has(kid)) { ignored.push({ id: p.id, reason: 'Signing key is revoked' }); continue; }
    if (p.subjectDigest !== a.subjectDigest) { ignored.push({ id: p.id, reason: 'Incident concerns a different subject' }); continue; }
    const t = ms(p.reportedAt);
    const blocking = p.kind === 'report' && (p.severity === 'high' || p.severity === 'critical');
    if (t > nowMs) {
      if (blocking) ignored.push({ id: p.id, reason: 'Blocking incident is dated in the future (clock skew or misdated); kept open' });
      else { ignored.push({ id: p.id, reason: 'Incident is dated in the future' }); continue; }
    }
    recs.push({ p, kid, role: k.role, t, future: t > nowMs });
  }
  const open = new Set(), resolved = new Set(), appealed = new Set(), observed = new Set();
  const reports = new Map();
  for (const r of recs) if (r.p.kind === 'report') reports.set(r.p.id, [...(reports.get(r.p.id) ?? []), r]);
  // same key and id with different content among non-reports: not honoured
  const byKeyId = new Map();
  for (const r of recs) if (r.p.kind !== 'report') byKeyId.set(r.kid + '\0' + r.p.id, [...(byKeyId.get(r.kid + '\0' + r.p.id) ?? []), r]);
  const dishonoured = new Set();
  for (const g of byKeyId.values()) if (g.length > 1) for (const r of g) { dishonoured.add(r); ignored.push({ id: r.p.id, reason: 'Conflicting records share one key and ID; not honoured' }); }
  for (const [id, g] of reports) {
    if (g.length > 1) ignored.push({ id, reason: 'Conflicting records share an ID; reports kept open, resolutions cannot target them' });
  }
  for (const r of recs) {
    const p = r.p;
    if (p.kind === 'report') {
      if (p.severity === 'high' || p.severity === 'critical') open.add(p.id);
      else observed.add(p.id);
      continue;
    }
    if (dishonoured.has(r)) continue;
    const g = reports.get(p.refId);
    if (!g) { ignored.push({ id: p.id, reason: 'References unknown incident' }); continue; }
    if (g.length > 1) { ignored.push({ id: p.id, reason: 'Ambiguous reference: several reports share this ID' }); continue; }
    const rep = g[0];
    if (p.kind === 'appeal') { appealed.add(p.refId); continue; }
    if (r.kid === rep.kid) { ignored.push({ id: p.id, reason: 'Reporter cannot resolve its own report' }); continue; }
    if (r.role !== 'independent') { ignored.push({ id: p.id, reason: 'Resolution requires an independent trusted key' }); continue; }
    if (!(r.t > rep.t)) { ignored.push({ id: p.id, reason: 'Resolution must be dated after the incident' }); continue; }
    resolved.add(p.refId);
  }
  for (const id of resolved) { open.delete(id); observed.delete(id); }
  // a conflicting-id report group is never resolved (resolutions cannot target them), so it stays as computed above
  ignored.sort((x, y) => (x.id === null ? (y.id === null ? 0 : -1) : y.id === null ? 1 : cmp(x.id, y.id)) || cmp(x.reason, y.reason));
  const sorted = s => [...s].sort(cmp);
  return { considered: incidents.length, open: sorted(open), resolved: sorted(resolved), appealed: sorted(appealed), observed: sorted(observed), ignored };
}

export function currencyResult(inp) {
  if (!isObj(inp) || !exactKeys(inp, ['assessment', 'manifest', 'policy', 'incidents', 'now'])) refuse('currency inputs');
  const { assessment: a, manifest, policy, incidents, now } = inp;
  if (!isTs(now)) refuse('now must be canonical UTC');
  if (!Array.isArray(incidents) || incidents.length > 4096) refuse('incidents array');
  checkAssessment(a);
  validManifest(manifest);
  validPolicy(policy, null, null, null);
  const nowMs = ms(now);
  const triggers = [];
  const fire = (id, code) => triggers.push({ id, code });
  if (nowMs < ms(a.assessedAt)) fire('clock-regression', 'CLOCK_REGRESSION');
  if (digest(manifest) !== a.subjectDigest) fire('subject-changed', 'SUBJECT_CHANGED');
  if (digest(policy) !== a.policyDigest) fire('policy-changed', 'POLICY_CHANGED');
  if (policy.revokedSubjectDigests.includes(a.subjectDigest)) fire('subject-revoked', 'SUBJECT_REVOKED');
  if (nowMs > ms(a.validUntil)) fire('assessment-expired', 'ASSESSMENT_EXPIRED');
  if (policy.maxAssessmentAgeSeconds !== undefined && nowMs - ms(a.assessedAt) > policy.maxAssessmentAgeSeconds * 1000) fire('assessment-aged', 'ASSESSMENT_AGED');
  const inc = processIncidents(incidents, a, policy, nowMs);
  if (inc.open.length) fire('incident-open', 'INCIDENT_OPEN');
  const current = triggers.length === 0;
  // Layout and fixed strings per docs/SPECIFICATION.md "Currency result layout and reason vocabulary".
  const DETAIL = {
    'clock-regression': 'Check time precedes the assessment time',
    'subject-changed': 'Manifest no longer matches the assessed subject digest',
    'policy-changed': 'Relying policy differs from the assessed policy',
    'subject-revoked': 'Subject digest is revoked by the supplied policy',
    'assessment-expired': 'Assessment validity interval has ended',
    'assessment-aged': 'Assessment is older than the policy maximum age',
    'incident-open': `${inc.open.length} unresolved high or critical incident record(s) for this subject`
  };
  const full = {
    schema: 'kya.currency/v1', assessmentDigest: a.reportDigest, checkedAt: now, current, reliable: current && a.decision === 'qualified',
    action: current ? 'none' : 'reassess', triggers: triggers.map(t => ({ ...t, detail: DETAIL[t.id] })), incidents: inc, authenticated: false,
    limits: [
      'Detects change against supplied manifest, policy and clock only; it does not observe runtime behavior',
      'Report checksum is unauthenticated; recompute from trusted inputs before reliance',
      'Incident records are trusted only through the supplied policy anchors; an omitted incident is undetectable',
      'A passing check is not an authorization grant'
    ]
  };
  return {
    schema: 'kya.impl-result/v1', operation: 'currency', current: full.current, reliable: full.reliable, action: full.action,
    checkedAt: now, assessmentDigest: a.reportDigest, triggers, incidents: inc, resultDigest: digest(full)
  };
}
