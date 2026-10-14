import { canonical, digest, insist } from '../../shared/canonical.mjs';
import { validateManifest, validatePolicy, timestamp, hash } from '../../identity/domain/services/validation.mjs';
import { verifyAssessment } from './assess.mjs';
import { CURRENCY_CODES } from './codes.mjs';
import { verifyIncident } from '../../evidence/domain/services/incidents.mjs';

// Monitoring triggers. An assessment is a point-in-time result; reliance later needs
// evidence that nothing it depended on has changed. Any fired trigger means: reassess.
const BLOCKING = ['high','critical'];
const SEVERITY = {low:0,medium:1,high:2,critical:3};
const DECISIONS = ['qualified','insufficient-evidence','blocked','expired','revoked'];
// Evaluate signed incident records. Untrusted, revoked and misdirected records are listed as
// ignored, never silently dropped. Records are namespaced by signing key, so one key cannot erase
// or rewrite another key's record by reusing its ID. Conflicting records from the same key fail
// closed: the most severe report is kept and a resolution is never honoured. Only an independent
// trusted key can resolve, and never its own report. Future-dated blocking reports stay open.
function evaluateIncidents(envelopes, assessment, policy, at) {
  insist(Array.isArray(envelopes) && envelopes.length <= 1024,'Incidents must be an array of at most 1024 records');
  const ignored=[], eligible=[], roles=new Map(policy.trustedKeys.map(k=>[k.id,k.role])), seen=new Set();
  for (const raw of envelopes) {
    let v; try { v=verifyIncident(raw); } catch (e) { ignored.push({id:null,reason:'Invalid incident record: '+e.message}); continue; }
    const {payload,keyId,envelopeDigest}=v, skip=reason=>ignored.push({id:payload.id,reason});
    if (seen.has(envelopeDigest)) continue; seen.add(envelopeDigest);
    if (!roles.has(keyId)) skip('Signing key is not a trusted anchor');
    else if (policy.revokedKeyIds.includes(keyId)) skip('Signing key is revoked');
    else if (payload.subjectDigest !== assessment.subjectDigest) skip('Incident concerns a different subject');
    else eligible.push({...payload,keyId,role:roles.get(keyId),future:Date.parse(payload.reportedAt) > at});
  }
  // Every report record is kept: nothing a key signs can hide another report of the same ID. A
  // resolution may target a report only when exactly one report carries that ID, so equivocation
  // and cross-key ID reuse fail closed (reports stay open, resolutions are listed as ambiguous).
  const reports=eligible.filter(e=>e.kind==='report'), counts=new Map();
  for (const e of reports) counts.set(e.id,(counts.get(e.id)??0)+1);
  for (const [id,n] of counts) if (n>1) ignored.push({id,reason:'Conflicting records share an ID; reports kept open, resolutions cannot target them'});
  const groups=new Map(); for (const e of eligible.filter(e=>e.kind!=='report')) { const k=e.keyId+'|'+e.id; groups.set(k,[...(groups.get(k)??[]),e]); }
  const others=[]; for (const g of groups.values()) { if (g.length>1) for (const e of g) ignored.push({id:e.id,reason:'Conflicting records share one key and ID; not honoured'}); else others.push(g[0]); }
  const live=[]; for (const e of reports) {
    if (e.future && !BLOCKING.includes(e.severity)) ignored.push({id:e.id,reason:'Incident is dated in the future'});
    else { if (e.future) ignored.push({id:e.id,reason:'Blocking incident is dated in the future (clock skew or misdated); kept open'}); live.push(e); }
  }
  const resolved=new Set(), appealed=new Set();
  for (const e of others) {
    if (e.future) { ignored.push({id:e.id,reason:'Incident is dated in the future'}); continue; }
    const targets=live.filter(r=>r.id===e.refId);
    // Ambiguity is judged over every eligible report, not only the live ones, so a future-dated duplicate
    // cannot make a reference look unique now and ambiguous later (the result must not flip with the clock).
    if ((counts.get(e.refId)??0)>1) ignored.push({id:e.id,reason:'Ambiguous reference: several reports share this ID'});
    else if (!targets.length) ignored.push({id:e.id,reason:'References unknown incident'});
    else if (e.kind==='appeal') appealed.add(targets[0].id);
    else if (e.role!=='independent') ignored.push({id:e.id,reason:'Resolution requires an independent trusted key'});
    else if (targets[0].keyId===e.keyId) ignored.push({id:e.id,reason:'Reporter cannot resolve its own report'});
    else if (Date.parse(e.reportedAt) <= Date.parse(targets[0].reportedAt)) ignored.push({id:e.id,reason:'Resolution must be dated after the incident'});
    else resolved.add(targets[0].keyId+'|'+targets[0].id);
  }
  const blocking=live.filter(r=>BLOCKING.includes(r.severity)), isResolved=r=>resolved.has(r.keyId+'|'+r.id);
  const idsOf=list=>[...new Set(list.map(r=>r.id))].sort();
  const open=idsOf(blocking.filter(r=>!isResolved(r)));
  return {considered:envelopes.length,open,resolved:idsOf(blocking.filter(isResolved)).filter(id=>!open.includes(id)),appealed:[...appealed].sort(),observed:idsOf(live.filter(r=>!BLOCKING.includes(r.severity))),ignored:ignored.sort((x,y)=>(x.id??'')<(y.id??'')?-1:(x.id??'')>(y.id??'')?1:x.reason<y.reason?-1:x.reason>y.reason?1:0)};
}

export function checkCurrency(assessment, {manifest, policy, now, incidents = []} = {}) {
  assessment=JSON.parse(canonical(assessment)); verifyAssessment(assessment);
  // A resealed or truncated report must not read as current: NaN comparisons would silently never fire.
  insist(timestamp(assessment.validUntil,'Assessment validity') >= timestamp(assessment.assessedAt,'Assessment time'),'Assessment validity precedes its assessment time'); hash(assessment.subjectDigest,'Assessment subject'); hash(assessment.policyDigest,'Assessment policy'); hash(assessment.scopeDigest,'Assessment scope');
  insist(DECISIONS.includes(assessment.decision),'Unknown assessment decision');
  manifest=validateManifest(manifest); policy=validatePolicy(policy);
  const at=timestamp(now,'Currency check time'), assessedAt=Date.parse(assessment.assessedAt), validUntil=Date.parse(assessment.validUntil);
  const triggers=[], fire=(id,detail)=>triggers.push({id,code:CURRENCY_CODES[id],detail});
  if (at < assessedAt) fire('clock-regression','Check time precedes the assessment time');
  if (digest(manifest) !== assessment.subjectDigest) fire('subject-changed','Manifest no longer matches the assessed subject digest');
  if (digest(policy) !== assessment.policyDigest) fire('policy-changed','Relying policy differs from the assessed policy');
  if (policy.revokedSubjectDigests.includes(assessment.subjectDigest)) fire('subject-revoked','Subject digest is revoked by the supplied policy');
  if (at > validUntil) fire('assessment-expired','Assessment validity interval has ended');
  if (policy.maxAssessmentAgeSeconds !== undefined && at - assessedAt > policy.maxAssessmentAgeSeconds*1000) fire('assessment-aged','Assessment is older than the policy maximum age');
  const inc=evaluateIncidents(incidents,assessment,policy,at);
  if (inc.open.length) fire('incident-open',`${inc.open.length} unresolved high or critical incident record(s) for this subject`);
  return {
    schema:'kya.currency/v1', assessmentDigest:assessment.reportDigest, checkedAt:new Date(at).toISOString(),
    current:triggers.length===0, reliable:triggers.length===0 && assessment.decision==='qualified', action:triggers.length ? 'reassess' : 'none', triggers, incidents:inc,
    authenticated:false, limits:['Detects change against supplied manifest, policy and clock only; it does not observe runtime behavior','Report checksum is unauthenticated; recompute from trusted inputs before reliance','Incident records are trusted only through the supplied policy anchors; an omitted incident is undetectable','A passing check is not an authorization grant'],
  };
}
