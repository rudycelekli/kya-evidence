// Second implementation of KYA assessment and currency semantics.
// Team-built from docs/SPECIFICATION.md, docs/IMPLEMENTERS-GUIDE.md, interop/impl-contract/README.md and
// evidence/assessment-vectors.json. NOT independent. See README.md in this directory.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

// ---------------------------------------------------------------- bytes

export class Refusal extends Error {}
const refuse = m => { throw new Refusal(m); };

// Bounded sorted-key JSON subset. Keys sorted by UTF-16 code units (default JS sort), no whitespace.
export function canonical(v, depth = 0) {
  if (depth > 64) refuse('too deep');
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean': return v ? 'true' : 'false';
    case 'string': return JSON.stringify(v);
    case 'number':
      if (!Number.isFinite(v)) refuse('non-finite number');
      return JSON.stringify(v);
    case 'object': {
      if (Array.isArray(v)) return '[' + v.map(x => canonical(x, depth + 1)).join(',') + ']';
      return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k], depth + 1)).join(',') + '}';
    }
    default: refuse('unsupported value');
  }
}
export const sha256hex = b => createHash('sha256').update(b).digest('hex');
export const digest = v => sha256hex(canonical(v));

// Strict JSON parse rejecting duplicate members (the stdin text is parsed with this).
export function parseStrict(text) {
  let i = 0;
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };
  const fail = m => refuse('bad JSON: ' + m);
  function value(depth) {
    if (depth > 64) fail('depth');
    ws();
    const c = text[i];
    if (c === '{') {
      i++; const o = {}; const seen = new Set(); ws();
      if (text[i] === '}') { i++; return o; }
      for (;;) {
        ws(); if (text[i] !== '"') fail('key');
        const k = str(); if (seen.has(k)) fail('duplicate member'); seen.add(k);
        if (k === '__proto__') fail('prototype key');
        ws(); if (text[i++] !== ':') fail(':');
        o[k] = value(depth + 1); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return o; }
        fail('object');
      }
    }
    if (c === '[') {
      i++; const a = []; ws();
      if (text[i] === ']') { i++; return a; }
      for (;;) {
        a.push(value(depth + 1)); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return a; }
        fail('array');
      }
    }
    if (c === '"') return str();
    const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i, i + 400));
    if (!m) fail('token');
    i += m[0].length;
    return JSON.parse(m[0]);
  }
  function str() {
    const start = i; i++;
    while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; }
    if (i >= text.length) fail('string');
    i++;
    return JSON.parse(text.slice(start, i));
  }
  const v = value(0); ws();
  if (i !== text.length) fail('trailing text');
  return v;
}

// ---------------------------------------------------------------- grammar helpers

export const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
export const HEX64 = /^[0-9a-f]{64}$/;
const TS = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
export const isTs = s => typeof s === 'string' && TS.test(s) && !Number.isNaN(Date.parse(s)) && new Date(s).toISOString() === s;
export const ms = s => Date.parse(s);
export const isStr = (s, max = 512) => typeof s === 'string' && s.length > 0 && s.length <= max && !/[\u0000-\u001f\u007f]/.test(s);
export const isPem = s => typeof s === 'string' && s.length > 0 && s.length <= 4096;
export const isId = s => typeof s === 'string' && s.length <= 128 && /^[A-Za-z0-9][A-Za-z0-9:._\/-]*$/.test(s);
export const exactKeys = (o, req, opt = []) => isObj(o) && req.every(k => Object.hasOwn(o, k)) && Object.keys(o).every(k => req.includes(k) || opt.includes(k));
const uniqueStrs = a => Array.isArray(a) && a.every(x => isStr(x)) && new Set(a).size === a.length;

// ---------------------------------------------------------------- validators (top-level failures are refusals)

export function validManifest(m) {
  if (!exactKeys(m, ['schema', 'agent', 'principal', 'system', 'scope', 'issuedAt', 'expiresAt'])) refuse('manifest keys');
  if (m.schema !== 'kya.manifest/v1') refuse('manifest schema');
  if (!exactKeys(m.agent, ['id', 'name', 'version']) || !isStr(m.agent.id) || !isStr(m.agent.name) || !isStr(m.agent.version)) refuse('manifest agent');
  if (!exactKeys(m.principal, ['id'], ['accountableParty']) || !isStr(m.principal.id)) refuse('manifest principal');
  if (m.principal.accountableParty !== undefined) {
    const p = m.principal.accountableParty;
    if (!exactKeys(p, ['kind', 'ref']) || !['natural-person', 'legal-entity'].includes(p.kind) || !isStr(p.ref)) refuse('accountable party');
    if (p.ref === m.agent.id) refuse('agent cannot be its own accountable party');
  }
  const s = m.system;
  if (!exactKeys(s, ['harness', 'harnessVersion', 'model', 'artifactDigest', 'configDigest', 'tools'])) refuse('manifest system');
  for (const k of ['harness', 'harnessVersion', 'model']) if (!isStr(s[k])) refuse('manifest system ' + k);
  for (const k of ['artifactDigest', 'configDigest']) if (!HEX64.test(s[k])) refuse('manifest ' + k);
  if (!Array.isArray(s.tools)) refuse('tools');
  const sc = m.scope;
  if (!exactKeys(sc, ['id', 'purpose', 'permissions', 'forbidden', 'approvalRequired']) || !isStr(sc.id) || !isStr(sc.purpose, 4096)) refuse('manifest scope');
  for (const k of ['permissions', 'forbidden', 'approvalRequired']) if (!uniqueStrs(sc[k])) refuse('scope ' + k);
  if (sc.forbidden.some(x => sc.permissions.includes(x))) refuse('allowed and forbidden permissions overlap');
  for (const t of s.tools) {
    if (!exactKeys(t, ['id', 'version', 'permissions']) || !isStr(t.id) || !isStr(t.version) || !uniqueStrs(t.permissions)) refuse('tool');
    if (t.permissions.some(p => !sc.permissions.includes(p))) refuse('tool permission not allowed in scope');
  }
  if (!isTs(m.issuedAt) || !isTs(m.expiresAt)) refuse('manifest time');
  if (ms(m.expiresAt) <= ms(m.issuedAt)) refuse('manifest expires before issue');
}

function validProfile(p) {
  if (!exactKeys(p, ['schema', 'id', 'version', 'title', 'checks']) || p.schema !== 'kya.profile/v1') refuse('profile');
  if (!isStr(p.id) || !isStr(p.version) || !isStr(p.title) || !Array.isArray(p.checks) || !p.checks.length) refuse('profile fields');
  const ids = new Set();
  for (const c of p.checks) {
    if (!exactKeys(c, ['id', 'dimension', 'title', 'weight', 'critical']) || !isStr(c.id) || !isStr(c.dimension) || !isStr(c.title)) refuse('profile check');
    if (!Number.isInteger(c.weight) || c.weight < 1 || typeof c.critical !== 'boolean') refuse('profile check weight');
    if (ids.has(c.id)) refuse('duplicate profile check');
    ids.add(c.id);
  }
}

const SOURCES = ['runtime', 'fixture', 'declaration'];
const ROLES = ['self', 'independent', 'capture-issuer'];
export function validPolicy(p, profileDigest, scopeId, checkIds) {
  const bound = profileDigest !== null;
  const req = ['schema', 'id', 'profileDigest', 'scopeId', 'minCoverage', 'minScore', 'minIndependentCoverage', 'allowedSources', 'maxEvidenceAgeSeconds', 'trustedKeys', 'revokedKeyIds', 'revokedEvidenceIds', 'revokedSubjectDigests'];
  if (!exactKeys(p, req, ['requirePrincipalBinding', 'mandatoryMinimums', 'maxAssessmentAgeSeconds']) || p.schema !== 'kya.policy/v1') refuse('policy');
  if (!isStr(p.id) || !HEX64.test(p.profileDigest) || !isStr(p.scopeId)) refuse('policy fields');
  if (bound && p.profileDigest !== profileDigest) refuse('policy binds another profile');
  if (bound && p.scopeId !== scopeId) refuse('policy binds another scope');
  for (const k of ['minCoverage', 'minIndependentCoverage']) if (typeof p[k] !== 'number' || !(p[k] >= 0 && p[k] <= 1)) refuse(k);
  if (!Number.isInteger(p.minScore) || p.minScore < 0 || p.minScore > 1000) refuse('minScore');
  if (!Array.isArray(p.allowedSources) || p.allowedSources.some(s => !SOURCES.includes(s)) || new Set(p.allowedSources).size !== p.allowedSources.length) refuse('allowedSources');
  if (!Number.isInteger(p.maxEvidenceAgeSeconds) || p.maxEvidenceAgeSeconds < 1) refuse('maxEvidenceAgeSeconds');
  if (p.maxAssessmentAgeSeconds !== undefined && (!Number.isInteger(p.maxAssessmentAgeSeconds) || p.maxAssessmentAgeSeconds < 1)) refuse('maxAssessmentAgeSeconds');
  if (p.requirePrincipalBinding !== undefined && typeof p.requirePrincipalBinding !== 'boolean') refuse('requirePrincipalBinding');
  if (!Array.isArray(p.trustedKeys)) refuse('trustedKeys');
  const kids = new Set();
  for (const k of p.trustedKeys) {
    if (!exactKeys(k, ['id', 'publicKey', 'role']) || !HEX64.test(k.id) || !isPem(k.publicKey) || !ROLES.includes(k.role)) refuse('trusted key');
    if (kids.has(k.id)) refuse('duplicate trusted key');
    kids.add(k.id);
  }
  if (!Array.isArray(p.revokedKeyIds) || p.revokedKeyIds.some(x => !HEX64.test(x))) refuse('revokedKeyIds');
  if (!Array.isArray(p.revokedSubjectDigests) || p.revokedSubjectDigests.some(x => !HEX64.test(x))) refuse('revokedSubjectDigests');
  if (!Array.isArray(p.revokedEvidenceIds) || p.revokedEvidenceIds.some(x => !isStr(x))) refuse('revokedEvidenceIds');
  if (p.mandatoryMinimums !== undefined) {
    if (!Array.isArray(p.mandatoryMinimums) || !p.mandatoryMinimums.length) refuse('mandatoryMinimums');
    const seen = new Set();
    for (const m of p.mandatoryMinimums) {
      if (!exactKeys(m, ['checkId', 'minimum']) || !['pass', 'independent-pass'].includes(m.minimum)) refuse('minimum entry');
      if (bound && !checkIds.has(m.checkId)) refuse('minimum names unknown check');
      if (seen.has(m.checkId)) refuse('minimum duplicate check');
      seen.add(m.checkId);
    }
  }
}

// ---------------------------------------------------------------- signatures

const b64uOk = s => typeof s === 'string' && /^[A-Za-z0-9_-]+$/.test(s) && Buffer.from(s, 'base64url').toString('base64url') === s;
export function verifyProof(domain, payload, proof) {
  // returns null when fine, else a reason string
  if (!exactKeys(proof, ['algorithm', 'keyId', 'publicKey', 'signature'])) return 'Malformed envelope: proof keys';
  if (proof.algorithm !== 'Ed25519') return 'Malformed envelope: algorithm';
  if (!HEX64.test(proof.keyId) || !isPem(proof.publicKey) || typeof proof.signature !== 'string') return 'Malformed envelope: proof fields';
  let key;
  try { key = createPublicKey(proof.publicKey); } catch { return 'Public key is not usable'; }
  if (key.asymmetricKeyType !== 'ed25519') return 'Public key is not Ed25519';
  const der = key.export({ type: 'spki', format: 'der' });
  if (sha256hex(der) !== proof.keyId) return 'Key ID does not match the embedded public key';
  if (!b64uOk(proof.signature) || Buffer.from(proof.signature, 'base64url').length !== 64) return 'Signature encoding is not canonical base64url of 64 bytes';
  let ok = false;
  try { ok = edVerify(null, Buffer.from(domain + canonical(payload), 'utf8'), key, Buffer.from(proof.signature, 'base64url')); } catch { ok = false; }
  return ok ? null : 'Signature does not verify';
}

// ---------------------------------------------------------------- evidence shape

const EVIDENCE_KEYS = ['artifactDigest', 'checkId', 'evaluatorDigest', 'expiresAt', 'id', 'observedAt', 'outcome', 'profileDigest', 'runId', 'schema', 'scopeId', 'source', 'subjectDigest'];
function evidenceShape(e) {
  if (!exactKeys(e, ['payload', 'proof'])) return 'Malformed envelope: expected payload and proof';
  const p = e.payload;
  if (!exactKeys(p, EVIDENCE_KEYS)) return 'Malformed envelope: payload keys';
  if (p.schema !== 'kya.evidence/v1') return 'Malformed envelope: payload schema';
  for (const k of ['id', 'runId', 'checkId', 'scopeId']) if (!isId(p[k])) return 'Malformed envelope: ' + k;
  for (const k of ['artifactDigest', 'evaluatorDigest', 'profileDigest', 'subjectDigest']) if (!HEX64.test(p[k])) return 'Malformed envelope: ' + k;
  if (!['pass', 'fail', 'abstain', 'error'].includes(p.outcome)) return 'Malformed envelope: outcome';
  if (!SOURCES.includes(p.source)) return 'Malformed envelope: source';
  if (!isTs(p.observedAt) || !isTs(p.expiresAt) || ms(p.expiresAt) <= ms(p.observedAt)) return 'Malformed envelope: times';
  return null;
}

// ---------------------------------------------------------------- assess

const LIMITATIONS = [
  'Local policy result; not an authorization grant',
  'Signatures attest bytes and key possession, not truthful execution',
  'No universal predictive validation; public suites can be gamed'
];
const FIXTURE_LIMITATION = 'Fixture evidence is synthetic; it does not describe real-world behavior';
const r6 = x => Math.round(x * 1e6) / 1e6;
export const T = {
  critFailed: c => `Critical check failed: ${c.id}`,
  critUnproven: c => `Critical check unproven: ${c.id}`,
  coverage: () => 'Evidence coverage below relying policy',
  indep: () => 'Independent coverage below relying policy',
  score: () => 'Score below relying policy',
  ambiguous: () => 'Ambiguous equally recent runs',
  conflict: () => 'Selected run contains quarantined conflicting evidence IDs',
  invalidated: () => 'Latest bound run contains invalidated evidence; no fallback qualification',
  mixed: () => 'Frozen run has multiple evaluator issuers',
  repeated: () => 'Frozen check has repeated observations; retry requires a new whole run',
  noScored: () => 'No scored observations',
  principal: () => 'Policy requires a declared accountable party; manifest declares none',
  minNotMet: (m, st) => `Mandatory minimum not met: ${m.checkId} requires ${m.minimum}; observed ${st}`,
  minUnproven: (m, st) => `Mandatory minimum unproven: ${m.checkId} requires ${m.minimum}; observed ${st}`,
  subject: code => ({ SUBJECT_REVOKED: 'Subject digest is revoked by relying policy', SUBJECT_NOT_YET_VALID: 'Manifest is not yet valid', SUBJECT_EXPIRED: 'Manifest has expired' })[code]
};
const SEVERITY_RANK = { pass: 0, abstain: 1, error: 2, fail: 3 };

export function assess(inp) {
  if (!isObj(inp) || !exactKeys(inp, ['manifest', 'profile', 'policy', 'evidence', 'evaluatorDigest', 'now'])) refuse('assess inputs');
  const { manifest, profile, policy, evidence, evaluatorDigest, now } = inp;
  if (!isTs(now)) refuse('now must be canonical UTC');
  if (typeof evaluatorDigest !== 'string' || !HEX64.test(evaluatorDigest)) refuse('evaluatorDigest');
  if (!Array.isArray(evidence) || evidence.length > 4096) refuse('evidence array');
  validManifest(manifest);
  validProfile(profile);
  const profileDigest = digest(profile);
  validPolicy(policy, profileDigest, manifest.scope.id, new Set(profile.checks.map(c => c.id)));

  const NOW = ms(now);
  const subjectDigest = digest(manifest);
  const checkIndex = new Map(profile.checks.map((c, i) => [c.id, i]));
  const trusted = new Map(policy.trustedKeys.map(k => [k.id, k]));
  const revKeys = new Set(policy.revokedKeyIds), revEv = new Set(policy.revokedEvidenceIds);
  const subjectRevoked = policy.revokedSubjectDigests.includes(subjectDigest) || false;
  const notYet = NOW < ms(manifest.issuedAt), expired = NOW > ms(manifest.expiresAt);
  const subjectStatus = subjectRevoked ? 'Subject is revoked' : expired ? 'Subject is expired' : notYet ? 'Subject is not yet issued' : null;

  // Stage 1: per receipt, up to "bound". rec = { i, env, p, role, reject }
  const rejected = new Map(); // index -> reason
  const recs = [];
  evidence.forEach((env, i) => {
    let reason = isObj(env) ? evidenceShape(env) : 'Malformed envelope: not an object';
    if (!reason) reason = verifyProof('kya.evidence/v1\n', env.payload, env.proof);
    const rec = { i, env, p: isObj(env) ? env.payload : null, bound: false, id: null };
    recs.push(rec);
    if (reason) { rejected.set(i, reason); return; }
    rec.id = env.payload.id.slice(0, 128); // a rejection id is reported only once shape and signature are valid
    const p = env.payload, k = trusted.get(env.proof.keyId);
    if (!k) { rejected.set(i, 'Signer is not a relying-party trust anchor'); return; }
    if (k.role === 'capture-issuer') { rejected.set(i, 'A capture-issuer key cannot issue scoring evidence'); return; }
    rec.role = k.role;
    if (subjectStatus) { rejected.set(i, subjectStatus); return; }
    if (p.subjectDigest !== subjectDigest) { rejected.set(i, 'Exact system digest differs'); return; }
    if (p.scopeId !== manifest.scope.id) { rejected.set(i, 'Evidence scope differs'); return; }
    if (p.profileDigest !== profileDigest) { rejected.set(i, 'Frozen profile differs'); return; }
    if (p.evaluatorDigest !== evaluatorDigest) { rejected.set(i, 'Evaluator digest differs'); return; }
    if (!checkIndex.has(p.checkId)) { rejected.set(i, 'Evidence check is outside frozen profile'); return; }
    if (p.source === 'declaration') { rejected.set(i, 'A declaration cannot satisfy an observed check'); return; }
    if (!policy.allowedSources.includes(p.source)) { rejected.set(i, 'Evidence source is disallowed'); return; }
    const t = ms(p.observedAt);
    if (t > NOW) { rejected.set(i, 'Observation is in the future'); return; }
    if (t < ms(manifest.issuedAt)) { rejected.set(i, 'Observation predates manifest'); return; }
    rec.bound = true;
  });

  const W = profile.checks.reduce((a, c) => a + c.weight, 0);
  const blockers = [];
  const add = (code, text) => blockers.push({ code, text });
  const mkReport = o => finalize(o);

  const base = {
    manifest, profile, policy, subjectDigest, profileDigest, evaluatorDigest, now, W, evidence,
    scopeDigest: digest(manifest.scope), policyDigest: digest(policy), bundleDigest: digest(evidence.map(e => digest(e)))
  };

  if (subjectStatus) {
    const code = subjectRevoked ? 'SUBJECT_REVOKED' : notYet ? 'SUBJECT_NOT_YET_VALID' : 'SUBJECT_EXPIRED';
    add(code, T.subject(code));
    return mkReport({ ...base, decision: subjectRevoked ? 'revoked' : 'expired', selected: null, ambiguous: false, results: new Map(), accepted: [], blockers, rejected, recs });
  }

  // Recency by run among bound receipts.
  const runs = new Map();
  for (const r of recs) if (r.bound) {
    const g = runs.get(r.p.runId) ?? { id: r.p.runId, latest: -Infinity, recs: [], failedCritical: false };
    g.latest = Math.max(g.latest, ms(r.p.observedAt)); g.recs.push(r);
    if (r.p.outcome === 'fail' && profile.checks[checkIndex.get(r.p.checkId)].critical) g.failedCritical = true;
    runs.set(r.p.runId, g);
  }
  let selected = null, ambiguous = false;
  if (runs.size) {
    const top = Math.max(...[...runs.values()].map(g => g.latest));
    const tied = [...runs.values()].filter(g => g.latest === top);
    ambiguous = tied.length > 1;
    tied.sort((a, b) => (b.failedCritical - a.failedCritical) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    selected = tied[0];
    for (const g of runs.values()) if (g !== selected) for (const r of g.recs) {
      rejected.set(r.i, g.latest === top ? 'Equally recent run excluded; ambiguous runs cannot qualify' : 'Older run excluded; checks cannot be mixed across runs');
    }
  }
  let invalidated = false, conflict = false, repeated = false, mixed = false;
  const kept = [];
  if (selected) {
    // exclusions inside the selected run
    const live = [];
    for (const r of selected.recs) {
      const p = r.p;
      let why = null;
      if (revKeys.has(r.env.proof.keyId)) why = 'Signing key is revoked';
      else if (revEv.has(p.id)) why = 'Evidence is revoked';
      else if (ms(p.expiresAt) < NOW) why = 'Evidence is expired';
      else if (NOW - ms(p.observedAt) > policy.maxEvidenceAgeSeconds * 1000) why = 'Evidence exceeds freshness policy';
      if (why) { rejected.set(r.i, why); invalidated = true; } else live.push(r);
    }
    // duplicate IDs among live receipts (whole bundle of eligible receipts)
    const idCount = new Map();
    for (const r of live) idCount.set(r.p.id, (idCount.get(r.p.id) ?? 0) + 1);
    // repeated checks counted before quarantine
    const perCheck = new Map();
    for (const r of live) perCheck.set(r.p.checkId, [...(perCheck.get(r.p.checkId) ?? []), r]);
    for (const g of perCheck.values()) if (g.length > 1) repeated = true;
    const survivors = [];
    for (const r of live) {
      if (idCount.get(r.p.id) > 1) { rejected.set(r.i, 'Duplicate evidence ID'); conflict = true; invalidated = true; } else survivors.push(r);
    }
    const bycheck = new Map();
    for (const r of survivors) bycheck.set(r.p.checkId, [...(bycheck.get(r.p.checkId) ?? []), r]);
    for (const g of bycheck.values()) {
      g.sort((a, b) => (SEVERITY_RANK[b.p.outcome] - SEVERITY_RANK[a.p.outcome]) || (ms(a.p.observedAt) - ms(b.p.observedAt)) || (a.i - b.i));
      kept.push(g[0]);
      for (const r of g.slice(1)) rejected.set(r.i, 'Superseded observation within selected run');
    }
    if (new Set(kept.map(r => r.env.proof.keyId)).size > 1) mixed = true;
  }
  const results = new Map(kept.map(r => [r.p.checkId, r]));
  return mkReport({ ...base, decision: null, selected, ambiguous, results, accepted: kept, blockers, rejected, recs, flags: { invalidated, conflict, repeated, mixed } });
}

function finalize(o) {
  const { manifest, profile, policy, W, results, selected, ambiguous, blockers, rejected, recs, flags } = o;
  const checks = [];
  let P = 0, K = 0, I = 0;
  const dims = new Map();
  for (const c of profile.checks) {
    const r = results.get(c.id);
    const st = r ? r.p.outcome : 'unknown';
    const d = dims.get(c.dimension) ?? { id: c.dimension, W: 0, P: 0, K: 0, weight: 0 };
    d.W += c.weight; d.weight += c.weight;
    if (st === 'pass') { P += c.weight; d.P += c.weight; }
    if (st === 'pass' || st === 'fail') { K += c.weight; d.K += c.weight; if (r.role === 'independent') I += c.weight; }
    dims.set(c.dimension, d);
    checks.push({ critical: c.critical, dimension: c.dimension, id: c.id, title: c.title, weight: c.weight, status: st, evidenceId: r ? r.p.id : null, keyId: r ? r.env.proof.keyId : null, independence: r ? r.role : null });
  }
  const score = { earned: Math.floor(1000 * P / W), possible: 1000, upperBound: Math.floor(1000 * (P + W - K) / W) };
  const coverage = K / W, indep = I / W;
  const dimensions = [...dims.values()].map(d => ({ id: d.id, earned: Math.floor(1000 * d.P / d.W), possible: 1000, upperBound: Math.floor(1000 * (d.P + d.W - d.K) / d.W), coverage: r6(d.K / d.W), weight: d.weight }));

  let decision = o.decision;
  if (!decision) {
    const crit = profile.checks.filter(c => c.critical);
    const failed = crit.filter(c => results.get(c.id)?.p.outcome === 'fail');
    const unproven = crit.filter(c => { const s = results.get(c.id)?.p.outcome; return s !== 'pass' && s !== 'fail'; });
    const add = (code, text) => blockers.push({ code, text });
    let blocked = false, insufficient = false;
    if (failed.length) {
      blocked = true;
      for (const c of failed) add('CRITICAL_CHECK_FAILED', T.critFailed(c));
    } else {
      for (const c of unproven) { insufficient = true; add('CRITICAL_CHECK_UNPROVEN', T.critUnproven(c, results.get(c.id))); }
      if (coverage < policy.minCoverage) { insufficient = true; add('COVERAGE_BELOW_POLICY', T.coverage(coverage, policy)); }
      if (indep < policy.minIndependentCoverage) { insufficient = true; add('INDEPENDENT_COVERAGE_BELOW_POLICY', T.indep(indep, policy)); }
      if (ambiguous) { insufficient = true; add('AMBIGUOUS_RUNS', T.ambiguous(selected)); }
      if (flags?.conflict) { insufficient = true; add('RUN_CONFLICT', T.conflict(selected)); }
      if (flags?.invalidated) { insufficient = true; add('RUN_INVALIDATED', T.invalidated(selected)); }
      if (flags?.mixed) { insufficient = true; add('MIXED_RUN_ISSUERS', T.mixed(selected)); }
      if (flags?.repeated) { insufficient = true; add('REPEATED_RUN_CHECKS', T.repeated(selected)); }
      if (policy.requirePrincipalBinding && !manifest.principal.accountableParty) { insufficient = true; add('PRINCIPAL_UNBOUND', T.principal()); }
      if (K === 0) { insufficient = true; add('NO_SCORED_OBSERVATIONS', T.noScored()); }
      if (!insufficient && score.earned < policy.minScore) { blocked = true; add('SCORE_BELOW_POLICY', T.score(score, policy)); }
    }
    for (const m of policy.mandatoryMinimums ?? []) {
      const r = results.get(m.checkId), st = r?.p.outcome;
      if (st === 'fail' || (st === 'pass' && m.minimum === 'independent-pass' && r.role !== 'independent')) { blocked = true; add('MANDATORY_MINIMUM_NOT_MET', T.minNotMet(m, st ?? 'unknown')); }
      else if (st !== 'pass') { blocked = true; add('MANDATORY_MINIMUM_UNPROVEN', T.minUnproven(m, st ?? 'unknown')); }
    }
    decision = blocked ? 'blocked' : insufficient ? 'insufficient-evidence' : 'qualified';
  }

  const modes = new Set(o.accepted.map(r => r.p.source));
  const evidenceMode = modes.size === 0 ? 'none' : modes.size > 1 ? 'mixed' : [...modes][0];
  const limitations = [...LIMITATIONS];
  if (modes.has('fixture')) limitations.push(FIXTURE_LIMITATION);

  let validUntil = ms(manifest.expiresAt);
  for (const r of o.accepted) validUntil = Math.min(validUntil, ms(r.p.expiresAt), ms(r.p.observedAt) + policy.maxEvidenceAgeSeconds * 1000);
  validUntil = new Date(validUntil).toISOString();

  const rejectedEvidence = [...rejected.entries()].sort((a, b) => a[0] - b[0]).map(([index, reason]) => ({ index, id: recs[index].id, reason }));
  const report = {
    schema: 'kya.assessment/v1', subjectDigest: o.subjectDigest, scopeDigest: o.scopeDigest,
    agentId: manifest.agent.id, agentName: manifest.agent.name, principalId: manifest.principal.id, scopeId: manifest.scope.id,
    profileDigest: o.profileDigest, profileId: profile.id, evaluatorDigest: o.evaluatorDigest, policyDigest: o.policyDigest, evidenceBundleDigest: o.bundleDigest,
    assessedAt: o.now, validUntil, selectedRunId: selected ? selected.id : null, ambiguousRuns: ambiguous, decision, evidenceMode,
    score, coverage: r6(coverage), independentCoverage: r6(indep), dimensions, checks,
    blockers: blockers.map(b => b.text), blockerCodes: blockers.map(b => b.code), rejectedEvidence,
    acceptedEvidenceDigests: o.accepted.map(r => digest(r.env)).sort(), limitations
  };
  report.reportDigest = digest(report);
  return report;
}

export function assessResult(inp) {
  const r = assess(inp);
  return {
    schema: 'kya.impl-result/v1', operation: 'assess', decision: r.decision, evidenceMode: r.evidenceMode, ambiguousRuns: r.ambiguousRuns,
    selectedRunId: r.selectedRunId, score: r.score, coverage: r.coverage, independentCoverage: r.independentCoverage, blockerCodes: r.blockerCodes,
    validUntil: r.validUntil,
    checks: r.checks.map(c => ({ id: c.id, status: c.status, evidenceId: c.evidenceId, independence: c.independence })),
    rejectedEvidence: r.rejectedEvidence, reportDigest: r.reportDigest
  };
}

// currency lives in currency.mjs to keep this file readable
