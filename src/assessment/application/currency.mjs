import { canonical, digest, insist } from '../../shared/canonical.mjs';
import { validateManifest, validatePolicy, timestamp } from '../../identity/domain/services/validation.mjs';
import { verifyAssessment } from './assess.mjs';
import { verifyIncident } from '../../evidence/domain/services/incidents.mjs';

// Monitoring triggers. An assessment is a point-in-time result; reliance later needs
// evidence that nothing it depended on has changed. Any fired trigger means: reassess.
const BLOCKING = ['high','critical'];
// Evaluate signed incident records. Untrusted, revoked, misdirected, future and duplicate records
// are listed as ignored, never silently dropped. Only an independent trusted key can resolve.
function evaluateIncidents(envelopes, assessment, policy, at) {
  insist(Array.isArray(envelopes) && envelopes.length <= 1024,'Incidents must be an array of at most 1024 records');
  const ignored=[], eligible=[], roles=new Map(policy.trustedKeys.map(k=>[k.id,k.role]));
  for (const raw of envelopes) {
    let v; try { v=verifyIncident(raw); } catch (e) { ignored.push({id:null,reason:'Invalid incident record: '+e.message}); continue; }
    const {payload,keyId}=v, skip=reason=>ignored.push({id:payload.id,reason});
    if (!roles.has(keyId)) skip('Signing key is not a trusted anchor');
    else if (policy.revokedKeyIds.includes(keyId)) skip('Signing key is revoked');
    else if (payload.subjectDigest !== assessment.subjectDigest) skip('Incident concerns a different subject');
    else if (Date.parse(payload.reportedAt) > at) skip('Incident is dated in the future');
    else eligible.push({...payload,role:roles.get(keyId)});
  }
  const counts=new Map(); for (const e of eligible) counts.set(e.id,(counts.get(e.id)??0)+1);
  const unique=eligible.filter(e=>counts.get(e.id)===1);
  for (const e of eligible) if (counts.get(e.id)>1) ignored.push({id:e.id,reason:'Duplicate incident ID quarantined'});
  const reports=new Map(unique.filter(e=>e.kind==='report').map(e=>[e.id,e])), resolved=new Set(), appealed=new Set();
  for (const e of unique.filter(e=>e.kind!=='report')) {
    const target=reports.get(e.refId);
    if (!target) ignored.push({id:e.id,reason:'References unknown incident'});
    else if (e.kind==='appeal') appealed.add(target.id);
    else if (e.role!=='independent') ignored.push({id:e.id,reason:'Resolution requires an independent trusted key'});
    else if (Date.parse(e.reportedAt) < Date.parse(target.reportedAt)) ignored.push({id:e.id,reason:'Resolution predates the incident'});
    else resolved.add(target.id);
  }
  const ids=[...reports.keys()].sort(), blocking=ids.filter(id=>BLOCKING.includes(reports.get(id).severity));
  return {considered:envelopes.length,open:blocking.filter(id=>!resolved.has(id)),resolved:blocking.filter(id=>resolved.has(id)),appealed:[...appealed].sort(),observed:ids.filter(id=>!BLOCKING.includes(reports.get(id).severity)),ignored};
}

export function checkCurrency(assessment, {manifest, policy, now, incidents = []} = {}) {
  assessment=JSON.parse(canonical(assessment)); verifyAssessment(assessment);
  manifest=validateManifest(manifest); policy=validatePolicy(policy);
  const at=timestamp(now,'Currency check time'), assessedAt=Date.parse(assessment.assessedAt), validUntil=Date.parse(assessment.validUntil);
  const triggers=[], fire=(id,detail)=>triggers.push({id,detail});
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
