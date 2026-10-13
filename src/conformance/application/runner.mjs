import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { digest,canonical } from '../../shared/canonical.mjs';
import { validateManifest,validateProfile,timestamp } from '../../identity/domain/services/validation.mjs';
import { CORE_PROFILE,SCENARIOS,EVALUATOR_DIGEST,SYNTHETIC_SECRET,SYNTHETIC_PRIVATE,deepFreeze } from '../domain/scenarios.mjs';
import { evaluateScenario } from '../domain/evaluator.mjs';
import { adapterOrigin } from './origins.mjs';
function redact(value){return JSON.parse(canonical(value).replaceAll(SYNTHETIC_SECRET,'[synthetic-secret-redacted]').replaceAll(SYNTHETIC_PRIVATE,'[synthetic-private-redacted]'));}
async function boundedRun(adapter,request,signal){
  if(signal?.aborted)throw Object.assign(new Error('Run aborted'),{code:'ABORTED'});
  const controller=new AbortController();let timer,stop;
  const aborted=new Promise((_,reject)=>{stop=()=>{controller.abort();reject(Object.assign(new Error('Run aborted'),{code:'ABORTED'}));};signal?.addEventListener('abort',stop,{once:true});timer=setTimeout(()=>{controller.abort();reject(Object.assign(new Error('Scenario timeout'),{code:'TIMEOUT'}));},request.timeoutMs);});
  try{return await Promise.race([Promise.resolve().then(()=>adapter.run(request,{signal:controller.signal})),aborted]);}finally{clearTimeout(timer);signal?.removeEventListener('abort',stop);}
}
export async function runConformance({adapter,manifest,profile=CORE_PROFILE,now=new Date().toISOString(),signal}={}){
  if(!adapter||typeof adapter.run!=='function')throw new TypeError('Adapter must expose run(request, {signal})');
  if(signal!==undefined&&!(signal instanceof AbortSignal))throw new TypeError('Invalid abort signal');
  manifest=validateManifest(manifest);profile=validateProfile(profile);timestamp(now);
  if(digest(profile)!==digest(CORE_PROFILE))throw new TypeError('This evaluator requires the complete frozen core profile');
  const frozenManifest=JSON.parse(canonical(manifest)),subjectDigest=digest(frozenManifest),profileDigest=digest(CORE_PROFILE),runId=randomUUID(),origin=adapterOrigin(adapter),observations=[],evidence=[];
  for(const scenario of SCENARIOS){
    const request=deepFreeze({schema:'kya.scenario-request/v1',scenarioId:scenario.id,runId,subjectDigest,scopeId:frozenManifest.scope.id,manifest:structuredClone(frozenManifest),prompt:scenario.prompt,context:structuredClone(scenario.context),timeoutMs:scenario.timeoutMs});
    const start=performance.now();let evaluation,response=null,error=null;
    try{response=JSON.parse(canonical(await boundedRun(adapter,request,signal)));evaluation=evaluateScenario(scenario.id,response,{subjectDigest,principalId:frozenManifest.principal.id});if(evaluation.outcome==='error')response=null;}
    catch(cause){error=['TIMEOUT','ABORTED','OUTPUT_LIMIT','NONZERO_EXIT','MALFORMED_JSON','INVALID_RESPONSE','SPAWN_FAILED','INPUT_LIMIT'].includes(cause?.code)?cause.code:'ADAPTER_ERROR';evaluation={outcome:'error',reasons:[error.toLowerCase()]};response=null;}
    const observation={schema:'kya.observation/v1',scenarioId:scenario.id,runId,source:origin.source,subjectDigest,scopeId:frozenManifest.scope.id,profileDigest,evaluatorDigest:EVALUATOR_DIGEST,requestDigest:digest(request),response:response?redact(response):null,outcome:evaluation.outcome,reasons:evaluation.reasons,error,transportLatencyMs:Math.round((performance.now()-start)*1000)/1000};
    observations.push(observation);evidence.push({schema:'kya.evidence/v1',id:`${runId}:${scenario.checkId}`,subjectDigest,scopeId:frozenManifest.scope.id,profileDigest,evaluatorDigest:EVALUATOR_DIGEST,runId,checkId:scenario.checkId,outcome:evaluation.outcome,observedAt:now,expiresAt:new Date(Date.parse(now)+3600000).toISOString(),artifactDigest:digest(observation),source:origin.source});
  }
  return{schema:'kya.conformance-run/v1',runId,adapter:{...origin},subjectDigest,profileDigest,evaluatorDigest:EVALUATOR_DIGEST,evidence,observations,observedAt:now,costs:{reportedUsd:observations.every(o=>o.response?.usage?.costUsd!==null&&o.response?.usage?.costUsd!==undefined)?observations.reduce((sum,o)=>sum+o.response.usage.costUsd,0):null},limitations:['Structured traces are adapter observations, not independent proof of real side effects.','Public synthetic cases are susceptible to contamination.','Usage cost values are adapter-reported; unmeasured cost remains null.']};
}
