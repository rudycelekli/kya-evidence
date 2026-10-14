import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { assess, checkCurrency, signIncident, verifyIncident, keyId, hashBytes } from '../src/index.mjs';
import { inputs, keys, NOW, clone } from './helpers.mjs';

const reviewer=generateKeyPairSync('ed25519'),reviewerPem=reviewer.publicKey.export({format:'pem',type:'spki'}).toString();
const stranger=generateKeyPairSync('ed25519');
const later='2026-10-13T12:30:00.000Z',CHECK='2026-10-13T13:00:00.000Z';
function setup(){
  const i=inputs();i.policy.trustedKeys.push({id:keyId(reviewerPem),publicKey:reviewerPem,role:'independent'});
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
test('untrusted, revoked, other-subject, future and duplicate incidents cannot trigger or silently disappear',()=>{
  const {i,report,inc,ctx}=setup();
  const reasons=r=>r.incidents.ignored.map(x=>x.reason);
  let r=checkCurrency(report,ctx([inc({},stranger.privateKey)]));assert.deepEqual(ids(r),[]);assert.match(reasons(r)[0],/trusted/i);
  const revoked=clone(i.policy);revoked.revokedKeyIds=[keyId(keys.publicKey.export({format:'pem',type:'spki'}).toString())];
  r=checkCurrency(report,ctx([inc()],revoked));assert.deepEqual(ids(r).filter(x=>x==='incident-open'),[]);assert.match(reasons(r)[0],/revoked/i);
  r=checkCurrency(report,ctx([inc({subjectDigest:hashBytes('other')})]));assert.deepEqual(ids(r),[]);assert.match(reasons(r)[0],/different subject/i);
  r=checkCurrency(report,ctx([inc({reportedAt:'2026-10-14T00:00:00.000Z'})]));assert.deepEqual(ids(r),[]);assert.match(reasons(r)[0],/future/i);
  r=checkCurrency(report,ctx([inc(),inc({severity:'high'})]));assert.deepEqual(ids(r),[]);assert.match(reasons(r)[0],/duplicate/i);
});
test('only an independent trusted key can resolve; self resolution and appeals cannot clear an incident',()=>{
  const {report,inc,ctx}=setup();
  const res=(key,patch={})=>inc({id:'res:1',kind:'resolution',severity:'low',refId:'inc:1',...patch},key);
  assert.deepEqual(ids(checkCurrency(report,ctx([inc(),res(reviewer.privateKey)]))),[]);
  const selfRes=checkCurrency(report,ctx([inc(),res(keys.privateKey)]));assert.deepEqual(ids(selfRes),['incident-open']);
  assert(selfRes.incidents.ignored.some(x=>/independent/i.test(x.reason)));
  const appeal=checkCurrency(report,ctx([inc(),inc({id:'app:1',kind:'appeal',severity:'low',refId:'inc:1'})]));
  assert.deepEqual(ids(appeal),['incident-open']);assert.deepEqual(appeal.incidents.appealed,['inc:1']);
  const early=res(reviewer.privateKey,{reportedAt:'2026-10-13T12:10:00.000Z'});
  assert.deepEqual(ids(checkCurrency(report,ctx([inc(),early]))),['incident-open']);
  const dangling=checkCurrency(report,ctx([res(reviewer.privateKey,{refId:'inc:404'})]));assert.deepEqual(ids(dangling),[]);assert(dangling.incidents.ignored.some(x=>/unknown incident/i.test(x.reason)));
  assert.throws(()=>checkCurrency(report,ctx('not-an-array')));
});
