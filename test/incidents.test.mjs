import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { assess, checkCurrency, signIncident, verifyIncident, keyId, hashBytes } from '../src/index.mjs';
import { inputs, keys, NOW, clone } from './helpers.mjs';

const reviewer=generateKeyPairSync('ed25519'),reviewerPem=reviewer.publicKey.export({format:'pem',type:'spki'}).toString();
const stranger=generateKeyPairSync('ed25519');
const reviewer2=generateKeyPairSync('ed25519'),reviewer2Pem=reviewer2.publicKey.export({format:'pem',type:'spki'}).toString();
const later='2026-10-13T12:30:00.000Z',CHECK='2026-10-13T13:00:00.000Z';
function setup(second=false){
  const i=inputs();i.policy.trustedKeys.push({id:keyId(reviewerPem),publicKey:reviewerPem,role:'independent'});
  if(second)i.policy.trustedKeys.push({id:keyId(reviewer2Pem),publicKey:reviewer2Pem,role:'independent'});
  const report=assess(i);
  const inc=(patch={},key=keys.privateKey)=>signIncident({schema:'kya.incident/v1',id:'inc:1',subjectDigest:report.subjectDigest,kind:'report',severity:'critical',refId:null,reportedAt:later,detailsDigest:hashBytes('private incident detail'),...patch},key);
  const ctx=(incidents,policy=i.policy)=>({manifest:i.manifest,policy,now:CHECK,incidents});
  return {i,report,inc,ctx};
}
const ids=r=>r.triggers.map(t=>t.id);

test('incident records are signed, domain-separated, strict and free of narrative text',()=>{
  const {inc}=setup(),e=inc();assert.equal(verifyIncident(e).payload.id,'inc:1');
  assert.throws(()=>verifyIncident({...e,payload:{...e.payload,severity:'low'}}),/signature/i);
  for(const patch of [{severity:'urgent'},{kind:'delete'},{summary:'free text'},{reportedAt:'today'},{kind:'resolution',refId:null},{kind:'report',refId:'inc:0'},{detailsDigest:'x'}])assert.throws(()=>inc(patch));
  assert.throws(()=>verifyIncident({payload:e.payload,proof:{...e.proof,signature:'A'.repeat(86)}}));
});
test('a trusted high or critical incident fires a trigger and demands reassessment',()=>{
  const {report,inc,ctx}=setup(),r=checkCurrency(report,ctx([inc()]));
  assert.deepEqual(ids(r),['incident-open']);assert.equal(r.action,'reassess');assert.deepEqual(r.incidents.open,['inc:1']);
  assert.deepEqual(ids(checkCurrency(report,ctx([inc({severity:'low'})]))),[]);
  assert.equal(checkCurrency(report,ctx([])).current,true);
});
test('untrusted, revoked, other-subject and malformed-time incidents cannot trigger or silently disappear',()=>{
  const {i,report,inc,ctx}=setup();
  const reasons=r=>r.incidents.ignored.map(x=>x.reason);
  let r=checkCurrency(report,ctx([inc({},stranger.privateKey)]));assert.deepEqual(ids(r),[]);assert.match(reasons(r)[0],/trusted/i);
  const revoked=clone(i.policy);revoked.revokedKeyIds=[keyId(keys.publicKey.export({format:'pem',type:'spki'}).toString())];
  r=checkCurrency(report,ctx([inc()],revoked));assert.deepEqual(ids(r).filter(x=>x==='incident-open'),[]);assert.match(reasons(r)[0],/revoked/i);
  r=checkCurrency(report,ctx([inc({subjectDigest:hashBytes('other')})]));assert.deepEqual(ids(r),[]);assert.match(reasons(r)[0],/different subject/i);
});
test('duplicate and conflicting IDs fail closed: they can never erase or downgrade a trusted blocking report',()=>{
  const {report,inc,ctx}=setup(),indep=(patch={})=>inc(patch,reviewer.privateKey);
  const base=indep();assert.deepEqual(ids(checkCurrency(report,ctx([base]))),['incident-open']);
  // the same envelope delivered twice must not quarantine itself
  assert.deepEqual(ids(checkCurrency(report,ctx([base,base]))),['incident-open']);
  // a subject-controlled (self) key reusing the ID with a low severity must not wipe the independent report
  const wipe=checkCurrency(report,ctx([base,inc({severity:'low'})]));assert.deepEqual(wipe.incidents.open,['inc:1']);
  // same-key equivocation keeps the most severe copy and surfaces the conflict
  const eq=checkCurrency(report,ctx([indep({severity:'low'}),indep({severity:'critical',detailsDigest:hashBytes('other')})]));
  assert.deepEqual(ids(eq),['incident-open']);assert(eq.incidents.ignored.some(x=>/conflict/i.test(x.reason)));
  // a self record reusing a resolution ID must not reopen a legitimately resolved incident
  const selfReport=inc();// reported by the subject's own key, so an independent key may resolve it
  const res=indep({id:'res:1',kind:'resolution',severity:'low',refId:'inc:1',reportedAt:'2026-10-13T12:45:00.000Z'});
  assert.deepEqual(ids(checkCurrency(report,ctx([selfReport,res,inc({id:'res:1',severity:'low'})]))),[]);
});
test('a high severity report blocks and a future-dated trusted blocking report fails closed',()=>{
  const {report,inc,ctx}=setup();
  assert.deepEqual(ids(checkCurrency(report,ctx([inc({severity:'high'})]))),['incident-open']);
  const future=checkCurrency(report,ctx([inc({reportedAt:'2026-10-14T00:00:00.000Z'})]));
  assert.deepEqual(ids(future),['incident-open']);assert(future.incidents.ignored.some(x=>/future/i.test(x.reason))||future.incidents.open.length===1);
  assert.deepEqual(ids(checkCurrency(report,ctx([inc({severity:'low',reportedAt:'2026-10-14T00:00:00.000Z'})]))),[]);
});
test('only an independent trusted key can resolve; self resolution and appeals cannot clear an incident',()=>{
  const {report,inc,ctx}=setup();
  const res=(key,patch={})=>inc({id:'res:1',kind:'resolution',severity:'low',refId:'inc:1',reportedAt:'2026-10-13T12:45:00.000Z',...patch},key);
  assert.deepEqual(ids(checkCurrency(report,ctx([inc(),res(reviewer.privateKey)]))),[]);
  const selfRes=checkCurrency(report,ctx([inc(),res(keys.privateKey)]));assert.deepEqual(ids(selfRes),['incident-open']);
  assert(selfRes.incidents.ignored.some(x=>/independent/i.test(x.reason)));
  const appeal=checkCurrency(report,ctx([inc(),inc({id:'app:1',kind:'appeal',severity:'low',refId:'inc:1'})]));
  assert.deepEqual(ids(appeal),['incident-open']);assert.deepEqual(appeal.incidents.appealed,['inc:1']);
  const early=res(reviewer.privateKey,{reportedAt:'2026-10-13T12:10:00.000Z'});
  assert.deepEqual(ids(checkCurrency(report,ctx([inc(),early]))),['incident-open']);
  const dangling=checkCurrency(report,ctx([res(reviewer.privateKey,{refId:'inc:404'})]));assert.deepEqual(ids(dangling),[]);assert(dangling.incidents.ignored.some(x=>/unknown incident/i.test(x.reason)));
  const mk=(who,patch={})=>inc({id:'res:2',kind:'resolution',severity:'low',refId:'inc:1',reportedAt:'2026-10-13T12:45:00.000Z',...patch},who);
  const own=[inc({},reviewer.privateKey),mk(reviewer.privateKey)];assert.deepEqual(ids(checkCurrency(report,ctx(own))),['incident-open']);
  assert(checkCurrency(report,ctx(own)).incidents.ignored.some(x=>/reporter/i.test(x.reason)));
  const equal=[inc(),mk(reviewer.privateKey,{reportedAt:later})];assert.deepEqual(ids(checkCurrency(report,ctx(equal))),['incident-open']);
  assert.throws(()=>checkCurrency(report,ctx('not-an-array')));
});

const setup2=()=>setup(true);
const res2=(inc,patch={})=>inc({id:'res:1',kind:'resolution',severity:'low',refId:'inc:1',reportedAt:'2026-10-13T12:45:00.000Z',...patch},reviewer2.privateKey);

test('same-key equivocation cannot hide a later unresolved report, in either input order',()=>{
  const {report,inc,ctx}=setup2(),A=reviewer.privateKey;
  const r1=inc({reportedAt:'2026-10-13T12:10:00.000Z'},A),r2=inc({severity:'high',reportedAt:'2026-10-13T12:50:00.000Z',detailsDigest:hashBytes('second')},A);
  const resolution=res2(inc,{reportedAt:'2026-10-13T12:30:00.000Z'});
  for(const order of [[r1,r2,resolution],[r2,r1,resolution],[resolution,r2,r1]]){const r=checkCurrency(report,ctx(order));assert.deepEqual(ids(r),['incident-open']);assert.equal(r.reliable,false);}
  const r3=inc({reportedAt:'2026-10-13T12:50:00.000Z',detailsDigest:hashBytes('third')},A);
  for(const order of [[r1,r3,resolution],[r3,r1,resolution]])assert.deepEqual(ids(checkCurrency(report,ctx(order))),['incident-open']);
});
test('a resolution cannot clear a report from a different key that shares its reference ID',()=>{
  const {report,inc,ctx}=setup2(),a=inc({},reviewer.privateKey),c=inc({reportedAt:'2026-10-13T12:20:00.000Z',detailsDigest:hashBytes('c')},keys.privateKey);
  const r=checkCurrency(report,ctx([a,c,res2(inc)]));assert.deepEqual(ids(r),['incident-open']);assert.deepEqual(r.incidents.open,['inc:1']);assert.deepEqual(r.incidents.resolved,[]);
  assert(r.incidents.ignored.some(x=>/ambiguous|conflict/i.test(x.reason)));
  // unambiguous reference still resolves
  assert.deepEqual(ids(checkCurrency(report,ctx([a,res2(inc)]))),[]);
});
test('a resolution delivered twice still resolves, and a future-dated resolution never does',()=>{
  const {report,inc,ctx}=setup2(),a=inc({},keys.privateKey),r=res2(inc);
  assert.deepEqual(ids(checkCurrency(report,ctx([a,r,r]))),[]);
  assert.deepEqual(ids(checkCurrency(report,ctx([a,res2(inc,{reportedAt:'2026-10-14T00:00:00.000Z'})]))),['incident-open']);
});
