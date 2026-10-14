import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { assess, signEvidence, verifyEvidence, verifyArtifact, verifyAssessment, compareAssessments, checkCurrency, digest, hashBytes, keyId, validateManifest, validatePolicy, validateProfile, validateEvidence } from '../src/index.mjs';
import { inputs, manifest, profile, policy, payload, bundle, keys, signerId, NOW, FUTURE, clone } from './helpers.mjs';

test('complete synthetic run qualifies only its local policy with explicit fixture provenance',()=>{
  const r=assess(inputs());assert.equal(r.decision,'qualified');assert.equal(r.score.earned,1000);assert.equal(r.coverage,1);assert.equal(r.evidenceMode,'fixture');assert.equal(r.independentCoverage,0);assert.equal(r.checks.length,6);assert.equal(verifyAssessment(r).authenticated,false);
});
test('proof verifies signature bytes but trust is checked separately',()=>{
  const x=inputs();const e=verifyEvidence(x.evidence[0]);assert.equal(e.keyId,signerId);
  x.policy.trustedKeys=[];const r=assess(x);assert.equal(r.decision,'insufficient-evidence');assert.equal(r.score.earned,0);assert.equal(r.rejectedEvidence.length,6);
});
test('empty evidence remains unknown with fixed 0..1000 range',()=>{
  const x=inputs();x.evidence=[];const r=assess(x);assert.equal(r.decision,'insufficient-evidence');assert.deepEqual(r.score,{earned:0,possible:1000,upperBound:1000});assert.ok(r.checks.every(c=>c.status==='unknown'));
});
test('declared claims cannot become scored observations even when policy allows their ingestion',()=>{
  const x=inputs();x.policy.allowedSources.push('declaration');x.evidence=x.evidence.map(e=>signEvidence({...e.payload,source:'declaration'},keys.privateKey));const r=assess(x);assert.equal(r.decision,'insufficient-evidence');assert.equal(r.coverage,0);assert.equal(r.score.earned,0);
});
test('removing a failed check cannot improve earned score or denominator',()=>{
  const x=inputs();x.evidence[5]=signEvidence(payload(x.manifest,x.profile,5,{outcome:'fail'}),keys.privateKey);const r=assess(x);
  x.evidence.pop();const removed=assess(x);assert.equal(removed.score.earned,r.score.earned);assert.equal(removed.score.possible,r.score.possible);assert.equal(removed.decision,'insufficient-evidence');
});
test('critical failure blocks even a policy permitting score zero and partial coverage',()=>{
  const x=inputs();x.policy.minCoverage=0;x.policy.minScore=0;x.evidence[0]=signEvidence(payload(x.manifest,x.profile,0,{outcome:'fail'}),keys.privateKey);const r=assess(x);assert.equal(r.decision,'blocked');assert.match(r.blockers[0],/Critical/);
});
for(const outcome of ['abstain','error']) test(`${outcome} does not count as known evidence`,()=>{
  const x=inputs();x.evidence[0]=signEvidence(payload(x.manifest,x.profile,0,{outcome}),keys.privateKey);const r=assess(x);assert.equal(r.decision,'insufficient-evidence');assert.equal(r.coverage,0.833333);assert.equal(r.score.earned,833);assert.equal(r.score.upperBound,1000);
});
for(const [field,value,reason] of [
  ['subjectDigest','a'.repeat(64),'system'],['scopeId','scope:other','scope'],['profileDigest','b'.repeat(64),'profile'],['evaluatorDigest','c'.repeat(64),'Evaluator'],['checkId','extra-check','profile'],['source','runtime','disallowed'],['source','declaration','declaration'],['observedAt','2026-10-13T12:00:00.001Z','future'],['observedAt','2026-10-13T10:59:59.999Z','predates'],['expiresAt',NOW,'expired']
])test(`evidence rejects wrong ${field} ${String(value).slice(0,20)}`,()=>{
  const x=inputs();const p=payload(x.manifest,x.profile,0,{[field]:value});
  if(field==='expiresAt')p.observedAt='2026-10-13T11:59:59.000Z';
  x.evidence[0]=signEvidence(p,keys.privateKey);const r=assess(x);assert.equal(r.decision,'insufficient-evidence');assert.match(r.rejectedEvidence[0].reason,new RegExp(reason,'i'));
});
test('changed tool/model/config/principal/artifact fields invalidate prior receipts',()=>{
  for(const mutate of [m=>m.system.model='new-model',m=>m.system.configDigest='a'.repeat(64),m=>m.system.artifactDigest='b'.repeat(64),m=>m.principal.id='controller:other',m=>m.agent.version='2',m=>m.scope.purpose='Different work']){
    const x=inputs();mutate(x.manifest);assert.equal(assess(x).score.earned,0);
  }
});
test('one latest run is selected; best cases from multiple runs are not composed',()=>{
  const x=inputs();x.policy.minCoverage=0;x.policy.minScore=0;
  const next=payload(x.manifest,x.profile,1,{id:'new-evidence',runId:'run-2',observedAt:'2026-10-13T12:00:01.000Z',outcome:'pass'});
  x.evidence.push(signEvidence(next,keys.privateKey));x.now='2026-10-13T12:00:02.000Z';const r=assess(x);assert.equal(r.selectedRunId,'run-2');assert.equal(r.score.earned,166);assert.equal(r.decision,'insufficient-evidence');
});
test('equally recent independent runs cannot bury a critical failure behind a lexicographic ID',()=>{
  const x=inputs();const pass=x.evidence.map(e=>signEvidence({...e.payload,runId:'a-pass',id:'pass-'+e.payload.id},keys.privateKey));
  const fail=x.evidence.map((e,i)=>signEvidence({...e.payload,runId:'z-fail',id:'fail-'+e.payload.id,outcome:i===0?'fail':'pass'},keys.privateKey));
  x.evidence=[...pass,...fail];const r=assess(x);assert.equal(r.decision,'blocked');assert.equal(r.ambiguousRuns,true);
  x.evidence=[...fail,...pass];assert.equal(assess(x).decision,'blocked');
});
test('equally recent successful runs are explicitly ambiguous rather than arbitrarily qualifying',()=>{
  const x=inputs();x.evidence.push(...x.evidence.map(e=>signEvidence({...e.payload,runId:'run-2',id:'new-'+e.payload.id},keys.privateKey)));assert.equal(assess(x).decision,'insufficient-evidence');
});
test('self-signed duplicate of a newer independent failure cannot revive an old passing run',()=>{
  const x=inputs();x.policy.trustedKeys[0].role='independent';x.policy.minIndependentCoverage=1;x.policy.minScore=1000;
  const self=generateKeyPairSync('ed25519'),pem=self.publicKey.export({format:'pem',type:'spki'}).toString();x.policy.trustedKeys.push({id:keyId(pem),publicKey:pem,role:'self'});
  const next=payload(x.manifest,x.profile,0,{id:'collision',runId:'new-fail',observedAt:'2026-10-13T12:00:01.000Z',outcome:'fail'});x.now='2026-10-13T12:00:02.000Z';
  x.evidence.push(signEvidence(next,keys.privateKey));assert.equal(assess(x).decision,'blocked');
  x.evidence.push(signEvidence({...next,outcome:'pass'},self.privateKey));const r=assess(x);assert.equal(r.selectedRunId,'new-fail');assert.notEqual(r.decision,'qualified');assert.equal(r.score.earned,0);
});
test('zero policy thresholds still require at least one scored observation',()=>{
  for(const outcome of ['error','abstain']){
    const x=inputs();x.profile.checks=x.profile.checks.slice(2,3);x.policy=policy(x.profile);x.policy.minCoverage=0;x.policy.minScore=0;
    x.evidence=[signEvidence(payload(x.manifest,x.profile,0,{outcome}),keys.privateKey)];assert.equal(assess(x).decision,'insufficient-evidence');
  }
});
test('revocation or expiry of a newer bound failure never revives an older successful run',()=>{
  for(const invalidation of ['revoked-evidence','revoked-key','expiry','freshness']){
    const x=inputs();x.now='2026-10-13T12:00:02.000Z';
    const newer=signEvidence(payload(x.manifest,x.profile,0,{id:'latest-failure',runId:'new-fail',observedAt:'2026-10-13T12:00:01.000Z',expiresAt:invalidation==='expiry'?'2026-10-13T12:00:02.000Z':FUTURE,outcome:'fail'}),keys.privateKey);x.evidence.push(newer);
    if(invalidation==='revoked-evidence')x.policy.revokedEvidenceIds=['latest-failure'];if(invalidation==='revoked-key')x.policy.revokedKeyIds=[signerId];if(invalidation==='freshness'){x.policy.maxEvidenceAgeSeconds=1;x.now='2026-10-13T12:00:03.000Z';}
    const r=assess(x);assert.equal(r.selectedRunId,'new-fail');assert.notEqual(r.decision,'qualified');assert.equal(r.score.earned,0);
  }
});
test('a later self-signed pass in an independent run cannot erase a critical failure',()=>{
  const x=inputs();x.policy.trustedKeys[0].role='independent';x.policy.minIndependentCoverage=0.8;x.now='2026-10-13T12:00:02.000Z';
  const self=generateKeyPairSync('ed25519'),pem=self.publicKey.export({format:'pem',type:'spki'}).toString();x.policy.trustedKeys.push({id:keyId(pem),publicKey:pem,role:'self'});
  x.evidence[0]=signEvidence(payload(x.manifest,x.profile,0,{outcome:'fail'}),keys.privateKey);
  x.evidence.push(signEvidence(payload(x.manifest,x.profile,0,{id:'late-self-pass',observedAt:'2026-10-13T12:00:01.000Z'}),self.privateKey));assert.equal(assess(x).decision,'blocked');
});
test('repeated frozen checks cannot refresh validity or repair a failure without a new run',()=>{
  const x=inputs();x.now='2026-10-13T12:00:02.000Z';x.evidence.push(signEvidence(payload(x.manifest,x.profile,3,{id:'late-pass',observedAt:'2026-10-13T12:00:01.000Z'}),keys.privateKey));assert.equal(assess(x).decision,'insufficient-evidence');
  x.evidence[0]=signEvidence(payload(x.manifest,x.profile,0,{outcome:'fail'}),keys.privateKey);x.evidence.push(signEvidence(payload(x.manifest,x.profile,0,{id:'late-pass-critical',observedAt:'2026-10-13T12:00:01.000Z'}),keys.privateKey));assert.equal(assess(x).decision,'blocked');
});
test('same-timestamp failure wins same-check conflict independent of input order',()=>{
  const x=inputs();const f=signEvidence(payload(x.manifest,x.profile,0,{id:'conflicting-fail',outcome:'fail'}),keys.privateKey);x.evidence.push(f);
  assert.equal(assess(x).decision,'blocked');x.evidence.reverse();assert.equal(assess(x).decision,'blocked');
});
test('duplicate eligible IDs quarantine all duplicates without boosting score',()=>{
  const x=inputs();x.evidence.push(x.evidence[0]);const r=assess(x);assert.equal(r.decision,'insufficient-evidence');assert.equal(r.rejectedEvidence.filter(e=>e.reason==='Duplicate evidence ID').length,2);
});
test('untrusted duplicate-ID poisoning cannot remove a trusted result',()=>{
  const x=inputs(), attacker=generateKeyPairSync('ed25519');x.evidence.push(signEvidence(payload(x.manifest,x.profile,0),attacker.privateKey));assert.equal(assess(x).decision,'qualified');
});
test('independence is assigned out of band, never invented by the receipt',()=>{
  const x=inputs();x.policy.minIndependentCoverage=1;assert.equal(assess(x).decision,'insufficient-evidence');x.policy.trustedKeys[0].role='independent';assert.equal(assess(x).independentCoverage,1);
  const forged=clone(x.evidence[0]);forged.payload.independence='independent';x.evidence=[forged];assert.equal(assess(x).decision,'insufficient-evidence');
});
for(const kind of ['key','evidence','subject'])test(`${kind} revocation invalidates qualification`,()=>{
  const x=inputs();if(kind==='key')x.policy.revokedKeyIds=[signerId];if(kind==='evidence')x.policy.revokedEvidenceIds=['evidence-0'];if(kind==='subject')x.policy.revokedSubjectDigests=[digest(x.manifest)];const r=assess(x);assert.notEqual(r.decision,'qualified');if(kind==='subject')assert.equal(r.decision,'revoked');
});
test('manifest expiry, future issuance, freshness boundary and validUntil are enforced',()=>{
  const x=inputs();assert.equal(assess(x).validUntil,'2026-10-13T13:00:00.000Z');x.now='2026-10-13T13:00:00.000Z';assert.equal(assess(x).decision,'insufficient-evidence');x.now=FUTURE;assert.equal(assess(x).decision,'expired');x.now='2026-10-13T10:00:00.000Z';assert.equal(assess(x).decision,'expired');
});
test('signature tampering, key substitution and noncanonical proof encoding fail',()=>{
  const x=inputs();const e=clone(x.evidence[0]);e.payload.outcome='fail';assert.throws(()=>verifyEvidence(e),/signature/);
  e.proof.algorithm='none';assert.throws(()=>verifyEvidence(e));
  const bad=clone(x.evidence[0]);bad.proof.signature+='=';assert.throws(()=>verifyEvidence(bad));
  const other=generateKeyPairSync('ed25519');bad.proof.publicKey=other.publicKey.export({format:'pem',type:'spki'}).toString();assert.throws(()=>verifyEvidence(bad));
});
test('Proxy access cannot substitute a different outcome after signature verification',()=>{
  const x=inputs(),e=signEvidence(payload(x.manifest,x.profile,0,{outcome:'fail'}),keys.privateKey);
  e.payload=new Proxy(e.payload,{get(t,k){return k==='outcome'?'pass':Reflect.get(t,k);}});
  assert.equal(verifyEvidence(e).payload.outcome,'fail');x.evidence[0]=e;assert.equal(assess(x).decision,'blocked');
});
test('Proxy access cannot substitute policy trust roles after canonical capture',()=>{
  const x=inputs();x.policy.minIndependentCoverage=1;const anchor=x.policy.trustedKeys[0];x.policy.trustedKeys[0]=new Proxy(anchor,{get(t,k){return k==='role'?'independent':Reflect.get(t,k);}});
  assert.equal(assess(x).decision,'insufficient-evidence');assert.equal(assess(x).independentCoverage,0);
});
test('public validators return captured plain JSON data instead of executable Proxy views',()=>{
  const p=payload(),proxy=new Proxy(p,{get(t,k){return k==='outcome'?'fail':Reflect.get(t,k);}});assert.equal(validateEvidence(proxy).outcome,'pass');
  const m=manifest();m.scope.forbidden=['read'];m.scope=new Proxy(m.scope,{get(t,k){return k==='forbidden'?[]:Reflect.get(t,k);}});assert.throws(()=>validateManifest(m),/Forbidden/);
});
test('artifact bytes are explicitly verified; signatures alone cannot validate the artifact',()=>{
  const p=payload();assert.equal(verifyArtifact(p,'trace-0'),true);assert.equal(verifyArtifact(p,'invented'),false);
});
test('artifact verification consumes the validated digest rather than a Proxy GET substitution',()=>{
  const p=payload();const proxy=new Proxy(p,{get(t,k){return k==='artifactDigest'?hashBytes('substituted-artifact'):Reflect.get(t,k);}});
  assert.equal(verifyArtifact(proxy,'trace-0'),true);assert.equal(verifyArtifact(proxy,'substituted-artifact'),false);
});
test('evidence container descriptors bind the same receipts for scoring and bundle hashing',()=>{
  const x=inputs(),original=x.evidence.slice();original[0]=signEvidence({...original[0].payload,outcome:'fail'},keys.privateKey);
  const pass=x.evidence[0];x.evidence=new Proxy(original,{get(t,k){return k==='0'?pass:Reflect.get(t,k);}});
  const report=assess(x);assert.equal(report.decision,'blocked');assert.equal(report.evidenceBundleDigest,digest(original.map(e=>digest(e))));
});
test('invalid evidence values are rejected once and represented by null digest markers',()=>{
  const x=inputs();const invalid={};Object.defineProperty(invalid,'payload',{enumerable:true,get(){throw Error('getter must not execute');}});x.evidence[0]=invalid;
  const report=assess(x);assert.equal(report.decision,'insufficient-evidence');assert.match(report.rejectedEvidence[0].reason,/accessors/);
  assert.equal(report.evidenceBundleDigest,digest(x.evidence.map((e,i)=>i?digest(e):null)));
  const sparse=inputs();delete sparse.evidence[0];assert.throws(()=>assess(sparse),/sparse/);
});
test('only public Ed25519 SPKI keys are admissible trust anchors',()=>{
  const x=policy();x.trustedKeys[0].publicKey=keys.privateKey.export({format:'pem',type:'pkcs8'}).toString();assert.throws(()=>validatePolicy(x),/public/);
  const rsa=generateKeyPairSync('rsa',{modulusLength:2048});assert.throws(()=>keyId(rsa.publicKey),/Ed25519/);
});
test('report checksum detects changed score; cannot establish issuer authenticity',()=>{
  const r=assess(inputs());r.score.earned=999;assert.throws(()=>verifyAssessment(r),/digest/);
  const {reportDigest,...body}=r;body.score.earned=1;const forged={...body,reportDigest:digest(body)};assert.equal(verifyAssessment(forged).authenticated,false);
});
test('comparisons require the same policy, profile, evaluator and complete populations',()=>{
  const x=inputs(),a=assess(x);x.evidence[5]=signEvidence(payload(x.manifest,x.profile,5,{outcome:'fail'}),keys.privateKey);const b=assess(x);assert.equal(compareAssessments(a,b).scoreDelta,-167);
  const y=inputs();y.policy.minScore=0;assert.throws(()=>compareAssessments(a,assess(y)),/policyDigest/);
  y.policy.minScore=800;y.evidence.pop();assert.throws(()=>compareAssessments(a,assess(y)),/incomplete/);
});
test('report verification and comparison consume the same captured data as their checksums',()=>{
  const report=assess(inputs());const proxy=new Proxy(report,{get(t,k){return k==='score'?{...t.score,earned:0}:k==='reportDigest'?'0'.repeat(64):Reflect.get(t,k);}});
  assert.equal(verifyAssessment(proxy).reportDigest,report.reportDigest);assert.equal(compareAssessments(report,proxy).scoreDelta,0);
});
for(const [label,make,validate] of [['manifest',manifest,validateManifest],['profile',profile,validateProfile],['policy',policy,validatePolicy],['evidence',payload,validateEvidence]]){
  for(const field of Object.keys(make()))test(`${label} rejects missing ${field}`,()=>{const v=make();delete v[field];assert.throws(()=>validate(v));});
  test(`${label} rejects unknown field`,()=>{const v=make();v.extra=true;assert.throws(()=>validate(v));});
}
test('semantically conflicting permissions, duplicate tool/check/key identifiers and temporal mistakes reject',()=>{
  const m=manifest();m.scope.forbidden=['read'];assert.throws(()=>validateManifest(m));
  const p=profile();p.checks.push(p.checks[0]);assert.throws(()=>validateProfile(p));
  const k=policy();k.trustedKeys.push(k.trustedKeys[0]);assert.throws(()=>validatePolicy(k));
  const e=payload();e.expiresAt=e.observedAt;assert.throws(()=>validateEvidence(e));
});

test('principal binding: an agent cannot be its own accountable party, and the declaration is optional but strict',()=>{
  const bound=(party)=>{const m=manifest();m.principal={id:'controller:test',accountableParty:party};return m;};
  assert.equal(validateManifest(bound({kind:'legal-entity',ref:'org:example-operator'})).principal.accountableParty.kind,'legal-entity');
  assert.equal(validateManifest(manifest()).principal.accountableParty,undefined);
  for(const bad of [{kind:'agent',ref:'org:x'},{kind:'natural-person',ref:'agent:test'},{kind:'natural-person'},{kind:'natural-person',ref:'person:a',name:'Real Name'},'person:a',null])assert.throws(()=>validateManifest(bound(bad)));
});
test('policy can require a declared accountable party; absence withholds qualification and the declaration is part of the subject',()=>{
  const base=inputs(),withParty=clone(base);withParty.manifest.principal.accountableParty={kind:'legal-entity',ref:'org:example-operator'};
  withParty.evidence=bundle(withParty.manifest,base.profile);
  const strict=i=>{const c=clone(i);c.policy.requirePrincipalBinding=true;return c;};
  assert.equal(assess(base).decision,'qualified');
  const missing=assess(strict(base));assert.equal(missing.decision,'insufficient-evidence');assert(missing.blockers.some(b=>/accountable party/i.test(b)));
  const present=assess(strict(withParty));assert.equal(present.decision,'qualified');
  assert.notEqual(present.subjectDigest,assess(base).subjectDigest);
  const relaxed=clone(withParty);relaxed.policy.requirePrincipalBinding=false;assert.equal(assess(relaxed).decision,'qualified');
  const bad=clone(base);bad.policy.requirePrincipalBinding='yes';assert.throws(()=>assess(bad));
});
test('policies and reports without the optional flag keep their previous digests and decisions',()=>{
  const i=inputs();assert.equal('requirePrincipalBinding' in validatePolicy(i.policy),false);
});

test('currency: an unchanged assessment is current and any monitoring trigger demands reassessment',()=>{
  const i=inputs(),report=assess(i),ctx=(edit=()=>{},now=NOW)=>{const c={manifest:clone(i.manifest),policy:clone(i.policy),now};edit(c);return c;};
  const ok=checkCurrency(report,ctx());assert.equal(ok.current,true);assert.equal(ok.action,'none');assert.deepEqual(ok.triggers,[]);assert.equal(ok.authenticated,false);
  const ids=c=>checkCurrency(report,c).triggers.map(t=>t.id);
  assert.deepEqual(ids(ctx(c=>{c.manifest.agent.version='2';})),['subject-changed']);
  assert.deepEqual(ids(ctx(c=>{c.manifest.system.tools[0].version='9';})),['subject-changed']);
  assert.deepEqual(ids(ctx(c=>{c.policy.minScore=0;})),['policy-changed']);
  assert.deepEqual(ids(ctx(c=>{c.policy.revokedSubjectDigests=[report.subjectDigest];})),['policy-changed','subject-revoked']);
  assert.deepEqual(ids(ctx(()=>{},new Date(Date.parse(report.validUntil)+1).toISOString())),['assessment-expired']);
  assert.deepEqual(ids(ctx(()=>{},new Date(Date.parse(report.assessedAt)-1).toISOString())),['clock-regression']);
  const aged=ctx(c=>{c.policy.maxAssessmentAgeSeconds=60;},new Date(Date.parse(report.assessedAt)+61_000).toISOString());
  assert(ids(aged).includes('assessment-aged'));
  const bound=assess({...i,policy:{...i.policy,maxAssessmentAgeSeconds:60}}),fresh=ctx(c=>{c.policy.maxAssessmentAgeSeconds=60;},new Date(Date.parse(bound.assessedAt)+60_000).toISOString());
  assert.equal(checkCurrency(bound,fresh).current,true);
  assert.equal(checkCurrency(bound,{...fresh,now:new Date(Date.parse(bound.assessedAt)+61_000).toISOString()}).action,'reassess');
});
test('currency: a non-qualified decision is never reported as reliable, and malformed or forged input is rejected',()=>{
  const i=inputs();i.evidence=[];const blocked=assess(i);assert.notEqual(blocked.decision,'qualified');
  const r=checkCurrency(blocked,{manifest:i.manifest,policy:i.policy,now:NOW});assert.equal(r.current,true);assert.equal(r.reliable,false);
  const good=assess(inputs()),forged=clone(good);forged.decision='qualified';forged.score.earned=1000;forged.validUntil='2099-01-01T00:00:00.000Z';
  assert.throws(()=>checkCurrency(forged,{manifest:inputs().manifest,policy:inputs().policy,now:NOW}),/digest differs/);
  assert.throws(()=>checkCurrency(good,{manifest:inputs().manifest,policy:inputs().policy}),/./);
  assert.throws(()=>checkCurrency(good,{manifest:inputs().manifest,policy:inputs().policy,now:'yesterday'}),/./);
  assert.throws(()=>checkCurrency(good,{manifest:{},policy:inputs().policy,now:NOW}),/./);
  const p=inputs().policy;p.maxAssessmentAgeSeconds=0;assert.throws(()=>validatePolicy(p),/age/i);
});

test('currency rejects a resealed assessment with missing or malformed validity fields instead of treating it as current',()=>{
  const i=inputs(),good=assess(i),ctx={manifest:i.manifest,policy:i.policy,now:'2030-01-01T00:00:00.000Z'};
  assert.deepEqual(checkCurrency(good,ctx).triggers.map(t=>t.id),['assessment-expired']);
  const reseal=edit=>{const r=clone(good);delete r.reportDigest;edit(r);return {...r,reportDigest:digest(r)};};
  for(const edit of [r=>{delete r.validUntil;},r=>{r.validUntil='never';},r=>{r.assessedAt='soon';},r=>{r.subjectDigest='x';},r=>{r.policyDigest=7;},r=>{r.decision='great';},r=>{r.scopeDigest='zz';},r=>{r.validUntil=new Date(Date.parse(r.assessedAt)-1000).toISOString();}])
    assert.throws(()=>checkCurrency(reseal(edit),ctx));
});
test('an agent cannot be its own accountable party under case or whitespace variation',()=>{
  for(const ref of ['AGENT:TEST','Agent:Test'])assert.throws(()=>{const m=manifest();m.principal={id:'controller:test',accountableParty:{kind:'natural-person',ref}};validateManifest(m);},/own accountable party/);
});
