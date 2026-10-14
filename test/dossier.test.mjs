import test from 'node:test';import assert from 'node:assert/strict';import{generateKeyPairSync}from'node:crypto';
import{createDossier,validateDossier,verifyDossier,assess,compareAssessments,digest,keyId,signEvidence}from'../src/index.mjs';
import{CORE_PROFILE,EVALUATOR_DIGEST,createReferenceAdapter,runConformance}from'../src/conformance/index.mjs';
import{starterManifest}from'../bin/kya.mjs';
const NOW='2026-10-14T02:00:00.000Z';
export async function dossierFixture(mode='careful'){
 const manifest=starterManifest(NOW,mode),keys=generateKeyPairSync('ed25519'),publicKey=keys.publicKey.export({type:'spki',format:'pem'}).toString();
 const run=await runConformance({adapter:createReferenceAdapter({mode}),manifest,now:NOW});
 const policy={schema:'kya.policy/v1',id:'dossier-fixture',profileDigest:digest(CORE_PROFILE),scopeId:manifest.scope.id,minCoverage:1,minScore:850,minIndependentCoverage:0,allowedSources:['fixture'],maxEvidenceAgeSeconds:3600,trustedKeys:[{id:keyId(publicKey),publicKey,role:'self'}],revokedKeyIds:[],revokedEvidenceIds:[],revokedSubjectDigests:[]};
 return{inputs:{manifest,profile:structuredClone(CORE_PROFILE),policy,evidence:run.evidence.map(p=>signEvidence(p,keys.privateKey)),evaluatorDigest:EVALUATOR_DIGEST,now:NOW},observations:run.observations,keys};
}
function resign(f,index){f.inputs.evidence[index]=signEvidence({...f.inputs.evidence[index].payload,artifactDigest:digest(f.observations[index])},f.keys.privateKey);}
function rehash(d){const{dossierDigest,...body}=d;d.dossierDigest=digest(body);return d;}

test('replayed originals support fixture strengths with permanent truth and completeness limits',async()=>{
 const f=await dossierFixture(),d=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(d.assessment.decision,'qualified');assert.equal(d.assessment.scopeDigest,digest(f.inputs.manifest.scope));assert.equal(d.strengths.length,18);assert.equal(d.coverage.verifiedOriginals,18);assert(d.strengths.every(s=>s.source==='fixture'&&s.verificationReach==='structured-response-replayed'));assert.equal(d.assurance.actualEffectsVerified,false);assert.equal(d.assurance.captureComplete,false);assert(d.blindSpots.some(b=>b.id==='public-contamination'));assert.equal(verifyDossier(d,{inputs:f.inputs,observations:f.observations}).authenticated,false);
});
test('a signed all-pass bundle without originals has reported assertions and no supported strengths',async()=>{
 const f=await dossierFixture(),d=createDossier({inputs:f.inputs});assert.equal(d.assessment.decision,'qualified');assert.equal(d.reportedPasses.length,18);assert.equal(d.strengths.length,0);assert.equal(d.coverage.verifiedOriginals,0);assert(d.blindSpots.some(b=>b.id==='unsupported-pass-claims'));assert.equal(d.measurements.cost.reportedTotalUsd,null);assert.equal(d.measurements.cost.coverage,0);
});
test('missing originals withhold only their corresponding structured strengths',async()=>{
 const f=await dossierFixture(),d=createDossier({inputs:f.inputs,observations:f.observations.slice(1)});assert.equal(d.strengths.length,17);assert.equal(d.reportedPasses.length,18);assert.equal(d.reportedPasses[0].verificationReach,'signed-assertion');assert.equal(d.assurance.captureComplete,false);
});
test('duplicate originals quarantine every occurrence rather than choosing the best one',async()=>{
 const f=await dossierFixture(),d=createDossier({inputs:f.inputs,observations:[...f.observations,f.observations[0]]});assert.equal(d.strengths.length,17);assert.equal(d.observations.rejected.filter(r=>r.code==='duplicate-observation').length,2);assert.equal(d.observations.verifiedOriginals,17);
});
test('digest mismatches and re-signed wrong request bindings cannot support strengths',async()=>{
 for(const sign of[false,true]){const f=await dossierFixture();f.observations[0].requestDigest='0'.repeat(64);if(sign)resign(f,0);const d=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(d.strengths.length,17);assert(d.observations.rejected.some(r=>r.code=== (sign?'observation-binding-mismatch':'artifact-digest-mismatch')));}
});
test('an unsafe response under a signed pass is replayed and quarantined without exposing private prose',async()=>{
 const f=await dossierFixture();f.observations[0].response.actions=[{type:'external-write',target:'PRIVATE_REPORT_SENTINEL',approved:false}];f.observations[0].reasons=['PRIVATE_REPORT_SENTINEL'];resign(f,0);
 const d=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(d.assessment.decision,'qualified');assert.equal(d.strengths.length,17);assert(d.blindSpots.some(b=>b.id==='contradictory-originals'));assert(d.observations.rejected.some(r=>r.code==='evaluation-contradiction'));assert(!JSON.stringify(d).includes('PRIVATE_REPORT_SENTINEL'));
});
test('unsupported evaluator originals remain signed assertions and never replay-supported strengths',async()=>{
 const f=await dossierFixture();f.inputs.evaluatorDigest='a'.repeat(64);f.observations.forEach((o,i)=>{o.evaluatorDigest=f.inputs.evaluatorDigest;f.inputs.evidence[i]=signEvidence({...f.inputs.evidence[i].payload,evaluatorDigest:f.inputs.evaluatorDigest,artifactDigest:digest(o)},f.keys.privateKey);});
 const d=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(d.observations.verifiedOriginals,18);assert.equal(d.observations.structuredReplays,0);assert.equal(d.strengths.length,0);
});
test('failed predicates preserve critical priority and never claim a causal diagnosis',async()=>{
 const f=await dossierFixture('reckless'),d=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(d.assessment.decision,'blocked');assert(d.failureModes.some(f=>f.critical));assert(d.failureModes.every(f=>f.rootCause==='not-established'));assert(d.failureModes.some(f=>f.reasonCodes.includes('unexpected-action-attempts')));
});
test('unexecuted/error checks are blind spots rather than invented agent failures',async()=>{
 const f=await dossierFixture('silent'),d=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(d.failureModes.length,0);assert.equal(d.strengths.length,0);assert(d.blindSpots.filter(b=>b.category==='check-coverage').length===18);
});
test('zero usage is preserved and incomplete totals retain explicit measurement coverage',async()=>{
 const f=await dossierFixture();f.observations.forEach((o,i)=>{o.response.usage.costUsd=0;resign(f,i);});const full=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(full.measurements.cost.reportedSubtotalUsd,0);assert.equal(full.measurements.cost.reportedTotalUsd,0);assert.equal(full.measurements.cost.coverage,1);
 f.observations[0].response.usage.costUsd=null;resign(f,0);const partial=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(partial.measurements.cost.reportedSubtotalUsd,0);assert.equal(partial.measurements.cost.reportedTotalUsd,null);assert.equal(partial.measurements.cost.known,17);assert.equal(partial.measurements.cost.planned,18);
});
test('reported telemetry overflow becomes an explicit unknown aggregate rather than invented cost',async()=>{
 const f=await dossierFixture();f.observations.forEach((o,i)=>{o.response.usage.costUsd=Number.MAX_SAFE_INTEGER;resign(f,i);});const d=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(d.measurements.cost.reportedSubtotalUsd,null);assert.equal(d.measurements.cost.reportedTotalUsd,null);assert.equal(d.measurements.cost.aggregation,'unrepresentable-total');validateDossier(d);
});
test('forged narrative/coverage claims fail replay even after checksums are recomputed',async()=>{
 const f=await dossierFixture(),d=createDossier({inputs:f.inputs});d.reportedPasses[0].verificationReach='structured-response-replayed';d.strengths=[d.reportedPasses[0]];d.coverage.verifiedStructuredPasses=1;rehash(d);assert.throws(()=>verifyDossier(d,{inputs:f.inputs}));
 const omitted=createDossier({inputs:f.inputs});omitted.blindSpots=omitted.blindSpots.filter(b=>b.id!=='incident-completeness');rehash(omitted);assert.throws(()=>validateDossier(omitted),/blind spot/);
});
test('issuer independence remains a policy assignment and declaration evidence remains unscored',async()=>{
 const f=await dossierFixture();f.inputs.policy.trustedKeys[0].role='independent';const d=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(d.assessment.independentCoverage,1);assert.equal(d.assurance.issuerIndependence,'relying-policy-assignment');
 f.inputs.policy.allowedSources=['declaration'];f.inputs.evidence=f.inputs.evidence.map(e=>signEvidence({...e.payload,source:'declaration'},f.keys.privateKey));const declared=createDossier({inputs:f.inputs,observations:f.observations});assert.equal(declared.assessment.coverage,0);assert.equal(declared.strengths.length,0);
});
test('same scope name with different purpose or permissions cannot establish comparable scores',async()=>{
 const f=await dossierFixture(),left=assess(f.inputs);for(const change of ['purpose','permissions']){const modified=structuredClone(f.inputs);if(change==='purpose')modified.manifest.scope.purpose='Different deployment purpose';else modified.manifest.scope.permissions.push('read-metadata');modified.evidence=modified.evidence.map(e=>signEvidence({...e.payload,subjectDigest:digest(modified.manifest)},f.keys.privateKey));const right=assess(modified);assert.equal(right.decision,'qualified');assert.throws(()=>compareAssessments(left,right),/scopeDigest/);}
 const legacy=structuredClone(left);delete legacy.scopeDigest;const{reportDigest,...body}=legacy;legacy.reportDigest=digest(body);assert.throws(()=>compareAssessments(legacy,legacy),/scope digest/);
});
test('dossier inputs are captured once and unsupported options/reflexive mutation cannot alter decisions',async()=>{
 const f=await dossierFixture();const provided=new Proxy(f.inputs,{get(t,k){return k==='policy'?{...t.policy,trustedKeys:[]}:Reflect.get(t,k);}});const d=createDossier({inputs:provided,observations:f.observations});assert.equal(d.assessment.decision,'qualified');assert.throws(()=>createDossier({inputs:f.inputs,report:d.assessment}));const prior=d.dossierDigest;f.inputs.evidence=[];assert.equal(d.dossierDigest,prior);validateDossier(d);
});
