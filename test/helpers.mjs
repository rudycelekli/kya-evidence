import { generateKeyPairSync } from 'node:crypto';
import { digest, hashBytes, keyId, signEvidence, DIMENSIONS } from '../src/index.mjs';

export const NOW='2026-10-13T12:00:00.000Z';
export const FUTURE='2026-10-14T12:00:00.000Z';
export const evaluatorDigest=hashBytes('test evaluator/v1 — synthetic');
export const keys=generateKeyPairSync('ed25519');
export const publicKey=keys.publicKey.export({format:'pem',type:'spki'}).toString();
export const signerId=keyId(publicKey);
export function manifest() {
  return {schema:'kya.manifest/v1',agent:{id:'agent:test',name:'Synthetic agent',version:'1'},principal:{id:'controller:test'},system:{harness:'test-fixture',harnessVersion:'1',model:'none',artifactDigest:hashBytes('fixture'),configDigest:hashBytes('config'),tools:[{id:'files',version:'1',permissions:['read']}]},scope:{id:'scope:test',purpose:'Synthetic local checks',permissions:['read','write'],forbidden:['publish'],approvalRequired:['write']},issuedAt:'2026-10-13T11:00:00.000Z',expiresAt:FUTURE};
}
export function profile() { return {schema:'kya.profile/v1',id:'test-v1',version:'1',title:'Synthetic protocol checks',checks:DIMENSIONS.map((dimension,i)=>({id:`check-${i}`,dimension,title:`${dimension} check`,weight:1,critical:i<2}))}; }
export function policy(p=profile()) {
  return {schema:'kya.policy/v1',id:'local-test',profileDigest:digest(p),scopeId:'scope:test',minCoverage:1,minScore:800,minIndependentCoverage:0,allowedSources:['fixture'],maxEvidenceAgeSeconds:3600,trustedKeys:[{id:signerId,publicKey,role:'self'}],revokedKeyIds:[],revokedEvidenceIds:[],revokedSubjectDigests:[]};
}
export function payload(m=manifest(),p=profile(),i=0,patch={}) {
  return {schema:'kya.evidence/v1',id:`evidence-${i}`,subjectDigest:digest(m),scopeId:m.scope.id,profileDigest:digest(p),evaluatorDigest,runId:'run-1',checkId:p.checks[i].id,outcome:'pass',observedAt:NOW,expiresAt:FUTURE,artifactDigest:hashBytes(`trace-${i}`),source:'fixture',...patch};
}
export function bundle(m=manifest(),p=profile()) {return p.checks.map((_,i)=>signEvidence(payload(m,p,i),keys.privateKey));}
export function inputs() {const m=manifest(),p=profile();return {manifest:m,profile:p,policy:policy(p),evidence:bundle(m,p),evaluatorDigest,now:NOW};}
export const clone=v=>structuredClone(v);
