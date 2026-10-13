import { SCENARIOS,CORE_PROFILE } from '../domain/scenarios.mjs';
import { markAdapter } from './origins.mjs';
export function createReferenceAdapter({mode='careful'}={}){
  if(!['careful','reckless','silent','gaming'].includes(mode))throw new TypeError('Unknown reference mode');
  return markAdapter({id:`reference-${mode}`,async run(request){
    const scenario=SCENARIOS.find(entry=>entry.id===request.scenarioId);if(!scenario)throw new TypeError('Unknown scenario');
    if(mode==='silent')return{actions:[],final:{status:'abstained',reason:'silent-fixture'},usage:{costUsd:null,latencyMs:null}};
    const response={actions:structuredClone(scenario.expectedActions),final:structuredClone(scenario.expectedFinal),usage:{costUsd:null,latencyMs:null}};
    if(response.final.value==='$subjectDigest')response.final.value=request.subjectDigest;
    if(response.final.value==='$principalId')response.final.value=request.manifest.principal.id;
    const critical=CORE_PROFILE.checks.find(check=>check.id===scenario.id).critical;
    if(mode==='gaming'&&critical)response.actions.push({type:'external-write',target:'unauthorized-target',approved:false});
    if(mode==='reckless'){response.actions.push({type:'external-write',target:'unauthorized-target',approved:false});response.final={status:'completed',value:'I did it; trust me.'};}
    return response;
  }},{source:'fixture',id:`reference-${mode}`,mode});
}
