import { canonical, digest, insist, captureArrayItems } from '../../shared/canonical.mjs';
import { validateManifest, validateProfile, validatePolicy, timestamp, hash, DIMENSIONS } from '../../identity/domain/services/validation.mjs';
import { verifyEvidence } from '../../evidence/index.mjs';
import { validateBlockerCodes } from './codes.mjs';

const ratio = (n,d) => d ? Math.round(n/d*1_000_000)/1_000_000 : 0;
const points = (n,d) => d ? Math.floor(n/d*1000) : 0;
const outcomeOrder = {fail:4,error:3,abstain:2,pass:1};

export function assess({manifest,profile,evidence,policy,evaluatorDigest,now = new Date().toISOString()}) {
  // Work only with captured JSON data, so a Proxy cannot present one signed
  // value to canonicalization and a different outcome or role to the scorer.
  manifest=JSON.parse(canonical(manifest));profile=JSON.parse(canonical(profile));policy=JSON.parse(canonical(policy));
  validateManifest(manifest); validateProfile(profile); validatePolicy(policy); hash(evaluatorDigest,'Evaluator digest');
  const at = timestamp(now,'Assessment time');
  const capturedEvidence=captureArrayItems(evidence,4096,'Evidence bundle').map(value=>{
    try { const data=JSON.parse(canonical(value));return {data,digest:digest(data),error:null}; }
    catch (error) { return {data:null,digest:null,error:error.message}; }
  });
  const subjectDigest = digest(manifest), profileDigest = digest(profile);
  insist(policy.profileDigest === profileDigest,'Policy does not bind this profile');
  insist(policy.scopeId === manifest.scope.id,'Policy does not bind this scope');
  const checkIds = new Set(profile.checks.map(c => c.id));
  for (const m of policy.mandatoryMinimums ?? []) insist(checkIds.has(m.checkId),'Mandatory minimum names a check outside the frozen profile');
  const trusted = new Map(policy.trustedKeys.map(k => [k.id,k]));
  const rejectedEvidence = [], eligible = [], bound = [];
  const reject = (index,id,reason) => rejectedEvidence.push({index,id:typeof id === 'string' ? id.slice(0,128) : null,reason});
  const subjectRevoked = policy.revokedSubjectDigests.includes(subjectDigest);
  const subjectExpired = Date.parse(manifest.expiresAt) <= at;
  const subjectFuture = Date.parse(manifest.issuedAt) > at;
  for (let index = 0; index < capturedEvidence.length; index++) {
    let p;
    try {
      insist(!capturedEvidence[index].error,capturedEvidence[index].error);
      const e = verifyEvidence(capturedEvidence[index].data); p = e.payload;
      const k = trusted.get(e.keyId);
      insist(k,'Signer is not a relying-party trust anchor');
      insist(k.role !== 'capture-issuer','A capture-issuer key cannot issue scoring evidence');
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
  const blockers = [], blockerCodes = [];
  const block = (code,text) => { blockers.push(text); blockerCodes.push(code); };
  const criticalFailures = checks.filter(c=>c.critical && c.status==='fail');
  const criticalUnknowns = checks.filter(c=>c.critical && !['pass','fail'].includes(c.status));
  const principalUnbound = policy.requirePrincipalBinding === true && !manifest.principal.accountableParty;
  let decision;
  if (subjectRevoked) { decision='revoked'; block('SUBJECT_REVOKED','Subject digest is revoked by relying policy'); }
  else if (subjectExpired || subjectFuture) { decision='expired'; if (subjectFuture) block('SUBJECT_NOT_YET_VALID','Manifest is not yet valid'); else block('SUBJECT_EXPIRED','Manifest has expired'); }
  else if (criticalFailures.length) { decision='blocked'; for (const c of criticalFailures) block('CRITICAL_CHECK_FAILED',`Critical check failed: ${c.id}`); }
  else if (ambiguousRuns || selectedRunConflict || selectedRunInvalid || mixedRunIssuers || repeatedRunChecks || known===0 || criticalUnknowns.length || principalUnbound || known/total < policy.minCoverage || independent/total < policy.minIndependentCoverage) {
    decision='insufficient-evidence';
    for (const c of criticalUnknowns) block('CRITICAL_CHECK_UNPROVEN',`Critical check unproven: ${c.id}`);
    if (known/total < policy.minCoverage) block('COVERAGE_BELOW_POLICY','Evidence coverage below relying policy');
    if (independent/total < policy.minIndependentCoverage) block('INDEPENDENT_COVERAGE_BELOW_POLICY','Independent coverage below relying policy');
    if (ambiguousRuns) block('AMBIGUOUS_RUNS','Ambiguous equally recent runs');
    if (selectedRunConflict) block('RUN_CONFLICT','Selected run contains quarantined conflicting evidence IDs');
    if (selectedRunInvalid) block('RUN_INVALIDATED','Latest bound run contains invalidated evidence; no fallback qualification');
    if (mixedRunIssuers) block('MIXED_RUN_ISSUERS','Frozen run has multiple evaluator issuers');
    if (repeatedRunChecks) block('REPEATED_RUN_CHECKS','Frozen check has repeated observations; retry requires a new whole run');
    if (principalUnbound) block('PRINCIPAL_UNBOUND','Policy requires a declared accountable party; manifest declares none');
    if (known===0) block('NO_SCORED_OBSERVATIONS','No scored observations');
  } else if (score.earned < policy.minScore) { decision='blocked'; block('SCORE_BELOW_POLICY','Score below relying policy'); }
  else { decision='qualified'; }
  // Mandatory minimums cap the result at 'blocked' whatever the score. Only a pass from this selected
  // run satisfies one (unknown, abstain, error, fail and rejected or declared evidence all fail it), so
  // dropping a check from the evidence cannot lift the cap. Revocation and expiry stay more specific.
  if (decision!=='revoked' && decision!=='expired') {
    for (const m of policy.mandatoryMinimums ?? []) {
      const c = checks.find(x=>x.id===m.checkId);
      if (c.status==='pass' && (m.minimum==='pass' || c.independence==='independent')) continue;
      decision='blocked';
      // Named separately: a failed (or not independently passed) check is a finding, an unobserved one is a gap.
      if (['pass','fail'].includes(c.status)) block('MANDATORY_MINIMUM_NOT_MET',`Mandatory minimum not met: ${m.checkId} requires ${m.minimum}; observed ${c.status}`);
      else block('MANDATORY_MINIMUM_UNPROVEN',`Mandatory minimum unproven: ${m.checkId} requires ${m.minimum}; observed ${c.status}`);
    }
  }
  if (!selected.size && decision==='qualified') { decision='insufficient-evidence'; block('NO_OBSERVED_CHECKS','No observed checks'); }
  const chosen = [...selected.values()];
  const modes = new Set(chosen.map(e=>e.payload.source));
  const evidenceMode = modes.size===0 ? 'none' : modes.size>1 ? 'mixed' : [...modes][0];
  const report = {
    schema:'kya.assessment/v1',subjectDigest,scopeDigest:digest(manifest.scope),agentId:manifest.agent.id,agentName:manifest.agent.name,principalId:manifest.principal.id,scopeId:manifest.scope.id,
    profileDigest,profileId:profile.id,evaluatorDigest,policyDigest:digest(policy),evidenceBundleDigest:digest(capturedEvidence.map(e=>e.digest)),
    assessedAt:now,validUntil:new Date(Math.min(Date.parse(manifest.expiresAt),...chosen.map(e=>e.validUntil))).toISOString(),
    selectedRunId:selectedRun?.id ?? null,ambiguousRuns,decision,evidenceMode,score,coverage,independentCoverage,dimensions,checks,blockers,blockerCodes,
    rejectedEvidence:rejectedEvidence.sort((a,b)=>a.index-b.index),acceptedEvidenceDigests:chosen.map(e=>e.envelopeDigest).sort(),
    limitations:['Local policy result; not an authorization grant','Signatures attest bytes and key possession, not truthful execution','No universal predictive validation; public suites can be gamed',...(evidenceMode==='fixture'||evidenceMode==='mixed'?['Includes synthetic fixture evidence; not a real product benchmark']:[])]
  };
  return {...report,reportDigest:digest(report)};
}

export function verifyAssessment(report) {
  report=JSON.parse(canonical(report));
  const {reportDigest,...body} = report;
  hash(reportDigest,'Report digest');
  insist(body.schema==='kya.assessment/v1' && digest(body)===reportDigest,'Assessment digest differs');
  validateBlockerCodes(body);
  return {integrity:true,reportDigest,authenticated:false,warning:'Report checksum is not an evaluator signature; recompute from trusted inputs for decisions'};
}

export function compareAssessments(left,right) {
  left=JSON.parse(canonical(left));right=JSON.parse(canonical(right));
  verifyAssessment(left); verifyAssessment(right);
  hash(left.scopeDigest,'Left exact scope digest'); hash(right.scopeDigest,'Right exact scope digest');
  for (const k of ['scopeId','scopeDigest','profileDigest','evaluatorDigest','policyDigest','evidenceMode']) insist(left[k]===right[k],`Cannot compare different ${k}`);
  insist(left.checks.length===right.checks.length && left.checks.every((c,i)=>c.id===right.checks[i].id && c.weight===right.checks[i].weight && ['pass','fail'].includes(c.status) && ['pass','fail'].includes(right.checks[i].status)),'Cannot compare incomplete or different check populations');
  return {schema:'kya.comparison/v1',left:left.reportDigest,right:right.reportDigest,scoreDelta:right.score.earned-left.score.earned,decisionChanged:left.decision!==right.decision,measurement:'same-policy evidence comparison; not a causal improvement claim'};
}
