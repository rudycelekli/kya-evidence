import { canonical, digest, insist } from '../../shared/canonical.mjs';
import { validateManifest, validateProfile, validatePolicy, timestamp, hash, DIMENSIONS } from '../../identity/domain/services/validation.mjs';
import { verifyEvidence } from '../../evidence/index.mjs';

const ratio = (n,d) => d ? Math.round(n/d*1_000_000)/1_000_000 : 0;
const points = (n,d) => d ? Math.floor(n/d*1000) : 0;
const outcomeOrder = {fail:4,error:3,abstain:2,pass:1};

export function assess({manifest,profile,evidence,policy,evaluatorDigest,now = new Date().toISOString()}) {
  validateManifest(manifest); validateProfile(profile); validatePolicy(policy); hash(evaluatorDigest,'Evaluator digest');
  const at = timestamp(now,'Assessment time');
  insist(Array.isArray(evidence) && evidence.length <= 4096,'Evidence bundle exceeds limit');
  const subjectDigest = digest(manifest), profileDigest = digest(profile);
  insist(policy.profileDigest === profileDigest,'Policy does not bind this profile');
  insist(policy.scopeId === manifest.scope.id,'Policy does not bind this scope');
  const trusted = new Map(policy.trustedKeys.map(k => [k.id,k]));
  const checkIds = new Set(profile.checks.map(c => c.id));
  const rejectedEvidence = [], eligible = [], bound = [];
  const reject = (index,id,reason) => rejectedEvidence.push({index,id:typeof id === 'string' ? id.slice(0,128) : null,reason});
  const subjectRevoked = policy.revokedSubjectDigests.includes(subjectDigest);
  const subjectExpired = Date.parse(manifest.expiresAt) <= at;
  const subjectFuture = Date.parse(manifest.issuedAt) > at;
  for (let index = 0; index < evidence.length; index++) {
    let p;
    try {
      const e = verifyEvidence(evidence[index]); p = e.payload;
      const k = trusted.get(e.keyId);
      insist(k,'Signer is not a relying-party trust anchor');
      insist(!subjectRevoked,'Subject is revoked'); insist(!subjectExpired,'Subject is expired'); insist(!subjectFuture,'Subject is not yet issued');
      insist(p.subjectDigest === subjectDigest,'Exact system digest differs');
      insist(p.scopeId === manifest.scope.id,'Evidence scope differs'); insist(p.profileDigest === profileDigest,'Frozen profile differs'); insist(p.evaluatorDigest === evaluatorDigest,'Evaluator digest differs');
      insist(checkIds.has(p.checkId),'Evidence check is outside frozen profile');
      insist(p.source !== 'declaration','A declaration cannot satisfy an observed check');
      insist(policy.allowedSources.includes(p.source),'Evidence source is disallowed');
      const observed = timestamp(p.observedAt), expires = timestamp(p.expiresAt);
      insist(observed <= at,'Observation is in the future'); insist(observed >= Date.parse(manifest.issuedAt),'Observation predates manifest');
      // Authentic, correctly bound observations establish recency before
      // invalidation. Revoking or expiring a failure must not resurrect an old pass.
      const record={...e,index,role:k.role,observed,validUntil:Math.min(expires,observed+policy.maxEvidenceAgeSeconds*1000)};
      bound.push(record);
      insist(!policy.revokedKeyIds.includes(e.keyId),'Signing key is revoked');
      insist(!policy.revokedEvidenceIds.includes(p.id),'Evidence is revoked');
      insist(expires > at,'Evidence is expired'); insist(at - observed < policy.maxEvidenceAgeSeconds*1000,'Evidence exceeds freshness policy');
      eligible.push(record);
    } catch (err) { reject(index,p?.id,err.message); }
  }

  // Only eligible, cryptographically trusted receipts can cause duplicate-ID quarantine.
  const counts = new Map();
  for (const e of bound) counts.set(e.payload.id,(counts.get(e.payload.id) ?? 0)+1);
  const unique = eligible.filter(e => {
    if (counts.get(e.payload.id) === 1) return true;
    reject(e.index,e.payload.id,'Duplicate evidence ID'); return false;
  });
  // Assess one whole run. Combining best cases from several runs would permit cherry-picking.
  const runs = new Map();
  // Conflicted receipts still establish a run's recency. Quarantine must never
  // resurrect an older successful run by deleting the newer failure's timestamp.
  for (const e of bound) {
    const id = e.payload.runId;
    if (!runs.has(id)) runs.set(id,[]);
    runs.get(id).push(e);
  }
  const candidates = [...runs].map(([id,items]) => ({id,items,at:Math.max(...items.map(e => e.observed))}));
  const failedCritical = items => items.some(e => e.payload.outcome==='fail' && profile.checks.find(c=>c.id===e.payload.checkId)?.critical);
  candidates.sort((a,b) => b.at-a.at || Number(failedCritical(b.items))-Number(failedCritical(a.items)) || (a.id<b.id?-1:a.id>b.id?1:0));
  const selectedRun = candidates[0] ?? null;
  const tiedRuns = candidates.filter(r=>r.at===selectedRun?.at);
  const ambiguousRuns = tiedRuns.length>1;
  const selectedRunConflict = selectedRun?.items.some(e=>counts.get(e.payload.id)>1) ?? false;
  const eligibleIndices=new Set(unique.map(e=>e.index));
  const selectedRunInvalid=selectedRun?.items.some(e=>!eligibleIndices.has(e.index))??false;
  const mixedRunIssuers=new Set(selectedRun?.items.map(e=>e.keyId)??[]).size>1;
  const observedCheckCounts=new Map();
  for(const e of selectedRun?.items??[])observedCheckCounts.set(e.payload.checkId,(observedCheckCounts.get(e.payload.checkId)??0)+1);
  const repeatedRunChecks=[...observedCheckCounts.values()].some(n=>n>1);
  const selected = new Map();
  for (const e of selectedRun?.items.filter(e=>eligibleIndices.has(e.index)) ?? []) {
    const prior = selected.get(e.payload.checkId);
    // A frozen check has one result per run. Keep the conservative observation
    // visible on conflicts; a successful retry must use a fresh whole run ID.
    if (!prior || outcomeOrder[e.payload.outcome] > outcomeOrder[prior.payload.outcome] || outcomeOrder[e.payload.outcome]===outcomeOrder[prior.payload.outcome] && e.observed<prior.observed) selected.set(e.payload.checkId,e);
  }
  for (const e of unique) {
    if (e.payload.runId !== selectedRun?.id) reject(e.index,e.payload.id,ambiguousRuns && e.observed===selectedRun.at ? 'Equally recent run excluded; ambiguous runs cannot qualify' : 'Older run excluded; checks cannot be mixed across runs');
    else if (selected.get(e.payload.checkId) !== e) reject(e.index,e.payload.id,'Superseded observation within selected run');
  }
  const checks = profile.checks.map(c => {
    const e = selected.get(c.id);
    return {...c,status:e?.payload.outcome ?? 'unknown',evidenceId:e?.payload.id ?? null,keyId:e?.keyId ?? null,independence:e?.role ?? null};
  });
  const total = checks.reduce((s,c)=>s+c.weight,0);
  const passed = checks.filter(c=>c.status==='pass').reduce((s,c)=>s+c.weight,0);
  const known = checks.filter(c=>['pass','fail'].includes(c.status)).reduce((s,c)=>s+c.weight,0);
  const unknown = total-known;
  const independent = checks.filter(c=>['pass','fail'].includes(c.status) && c.independence==='independent').reduce((s,c)=>s+c.weight,0);
  const coverage = ratio(known,total), independentCoverage = ratio(independent,total);
  const score = {earned:points(passed,total),possible:1000,upperBound:points(passed+unknown,total)};
  const dimensions = DIMENSIONS.map(id => {
    const cs = checks.filter(c=>c.dimension===id), t=cs.reduce((s,c)=>s+c.weight,0);
    const p = cs.filter(c=>c.status==='pass').reduce((s,c)=>s+c.weight,0);
    const k = cs.filter(c=>['pass','fail'].includes(c.status)).reduce((s,c)=>s+c.weight,0);
    return {id,earned:points(p,t),possible:t ? 1000 : 0,upperBound:points(p+t-k,t),coverage:ratio(k,t),weight:t};
  });
  const blockers = [];
  const criticalFailures = checks.filter(c=>c.critical && c.status==='fail');
  const criticalUnknowns = checks.filter(c=>c.critical && !['pass','fail'].includes(c.status));
  let decision;
  if (subjectRevoked) { decision='revoked'; blockers.push('Subject digest is revoked by relying policy'); }
  else if (subjectExpired || subjectFuture) { decision='expired'; blockers.push(subjectFuture ? 'Manifest is not yet valid' : 'Manifest has expired'); }
  else if (criticalFailures.length) { decision='blocked'; blockers.push(...criticalFailures.map(c=>`Critical check failed: ${c.id}`)); }
  else if (ambiguousRuns || selectedRunConflict || selectedRunInvalid || mixedRunIssuers || repeatedRunChecks || known===0 || criticalUnknowns.length || known/total < policy.minCoverage || independent/total < policy.minIndependentCoverage) {
    decision='insufficient-evidence';
    blockers.push(...criticalUnknowns.map(c=>`Critical check unproven: ${c.id}`));
    if (known/total < policy.minCoverage) blockers.push('Evidence coverage below relying policy');
    if (independent/total < policy.minIndependentCoverage) blockers.push('Independent coverage below relying policy');
    if (ambiguousRuns) blockers.push('Ambiguous equally recent runs');
    if (selectedRunConflict) blockers.push('Selected run contains quarantined conflicting evidence IDs');
    if (selectedRunInvalid) blockers.push('Latest bound run contains invalidated evidence; no fallback qualification');
    if (mixedRunIssuers) blockers.push('Frozen run has multiple evaluator issuers');
    if (repeatedRunChecks) blockers.push('Frozen check has repeated observations; retry requires a new whole run');
    if (known===0) blockers.push('No scored observations');
  } else if (score.earned < policy.minScore) { decision='blocked'; blockers.push('Score below relying policy'); }
  else { decision='qualified'; }
  if (!selected.size && decision==='qualified') { decision='insufficient-evidence'; blockers.push('No observed checks'); }
  const chosen = [...selected.values()];
  const modes = new Set(chosen.map(e=>e.payload.source));
  const evidenceMode = modes.size===0 ? 'none' : modes.size>1 ? 'mixed' : [...modes][0];
  const report = {
    schema:'kya.assessment/v1',subjectDigest,agentId:manifest.agent.id,agentName:manifest.agent.name,principalId:manifest.principal.id,scopeId:manifest.scope.id,
    profileDigest,profileId:profile.id,evaluatorDigest,policyDigest:digest(policy),evidenceBundleDigest:digest(evidence.map(e=>{try{return digest(e);}catch{return null;}})),
    assessedAt:now,validUntil:new Date(Math.min(Date.parse(manifest.expiresAt),...chosen.map(e=>e.validUntil))).toISOString(),
    selectedRunId:selectedRun?.id ?? null,ambiguousRuns,decision,evidenceMode,score,coverage,independentCoverage,dimensions,checks,blockers,
    rejectedEvidence:rejectedEvidence.sort((a,b)=>a.index-b.index),acceptedEvidenceDigests:chosen.map(e=>e.envelopeDigest).sort(),
    limitations:['Local policy result; not an authorization grant','Signatures attest bytes and key possession, not truthful execution','No universal predictive validation; public suites can be gamed',...(evidenceMode==='fixture'||evidenceMode==='mixed'?['Includes synthetic fixture evidence; not a real product benchmark']:[])]
  };
  return {...report,reportDigest:digest(report)};
}

export function verifyAssessment(report) {
  canonical(report);
  const {reportDigest,...body} = report;
  hash(reportDigest,'Report digest');
  insist(body.schema==='kya.assessment/v1' && digest(body)===reportDigest,'Assessment digest differs');
  return {integrity:true,reportDigest,authenticated:false,warning:'Report checksum is not an evaluator signature; recompute from trusted inputs for decisions'};
}

export function compareAssessments(left,right) {
  verifyAssessment(left); verifyAssessment(right);
  for (const k of ['scopeId','profileDigest','evaluatorDigest','policyDigest','evidenceMode']) insist(left[k]===right[k],`Cannot compare different ${k}`);
  insist(left.checks.length===right.checks.length && left.checks.every((c,i)=>c.id===right.checks[i].id && c.weight===right.checks[i].weight && ['pass','fail'].includes(c.status) && ['pass','fail'].includes(right.checks[i].status)),'Cannot compare incomplete or different check populations');
  return {schema:'kya.comparison/v1',left:left.reportDigest,right:right.reportDigest,scoreDelta:right.score.earned-left.score.earned,decisionChanged:left.decision!==right.decision,measurement:'same-policy evidence comparison; not a causal improvement claim'};
}
