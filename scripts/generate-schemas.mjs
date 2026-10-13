import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { canonical } from '../src/shared/canonical.mjs';

const root=fileURLToPath(new URL('../schemas/',import.meta.url));
const str={type:'string',minLength:1,maxLength:512,pattern:'^[^\\u0000-\\u001f\\u007f]+$'};
const id={...str,maxLength:128,pattern:'^[A-Za-z0-9][A-Za-z0-9:._/-]*$'};
const hash={type:'string',pattern:'^[a-f0-9]{64}$'};
const time={type:'string',format:'date-time',pattern:'^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'};
const list=(items=id,maxItems=256)=>({type:'array',items,maxItems,uniqueItems:true});
const obj=properties=>({type:'object',properties,required:Object.keys(properties),additionalProperties:false});
const pem={type:'string',maxLength:2000,pattern:'^-----BEGIN PUBLIC KEY-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+\\r?\\n-----END PUBLIC KEY-----\\r?\\n?$'};
const evidence=obj({schema:{const:'kya.evidence/v1'},id,subjectDigest:hash,scopeId:id,profileDigest:hash,evaluatorDigest:hash,runId:id,checkId:id,outcome:{enum:['pass','fail','abstain','error']},observedAt:time,expiresAt:time,artifactDigest:hash,source:{enum:['runtime','fixture','declaration']}});
const schemas={
  manifest:obj({schema:{const:'kya.manifest/v1'},agent:obj({id,name:str,version:{...str,maxLength:128}}),principal:obj({id}),system:obj({harness:{...str,maxLength:128},harnessVersion:{...str,maxLength:128},model:{...str,maxLength:128},artifactDigest:hash,configDigest:hash,tools:{type:'array',maxItems:128,items:obj({id,version:{...str,maxLength:128},permissions:list()})}}),scope:obj({id,purpose:str,permissions:list(),forbidden:list(),approvalRequired:list()}),issuedAt:time,expiresAt:time}),
  profile:obj({schema:{const:'kya.profile/v1'},id,version:{...str,maxLength:64},title:str,checks:{type:'array',minItems:1,maxItems:256,items:obj({id,dimension:{enum:['identity','authority','security','reliability','accountability','operations']},title:str,weight:{type:'integer',minimum:1,maximum:100000},critical:{type:'boolean'}})}}),
  policy:obj({schema:{const:'kya.policy/v1'},id,profileDigest:hash,scopeId:id,minCoverage:{type:'number',minimum:0,maximum:1},minScore:{type:'integer',minimum:0,maximum:1000},minIndependentCoverage:{type:'number',minimum:0,maximum:1},allowedSources:list({enum:['runtime','fixture','declaration']},3),maxEvidenceAgeSeconds:{type:'integer',minimum:1,maximum:31536000},trustedKeys:{type:'array',maxItems:256,items:obj({id:hash,publicKey:pem,role:{enum:['self','independent']}})},revokedKeyIds:list(hash,4096),revokedEvidenceIds:list(id,4096),revokedSubjectDigests:list(hash,4096)}),
  evidence,
  envelope:obj({payload:evidence,proof:obj({algorithm:{const:'Ed25519'},keyId:hash,publicKey:pem,signature:{type:'string',pattern:'^[A-Za-z0-9_-]{86}$'}})})
};
await mkdir(root,{recursive:true});
for(const [name,value]of Object.entries(schemas)){
  const full={$schema:'https://json-schema.org/draft/2020-12/schema',$id:`urn:kya-evidence:${name}:v1`,title:`KYA Evidence ${name} v1`,description:'Structural schema only. Runtime validator additionally enforces key fingerprint, temporal ordering, uniqueness by ID, scope relations and canonical JSON resource limits.',...value};
  const path=root+name+'.schema.json',output=JSON.stringify(full,null,2)+'\n';
  if(process.argv.includes('--check')){if(canonical(JSON.parse(await readFile(path,'utf8')))!==canonical(full))throw Error(`Schema drift: ${name}`);}
  else await writeFile(path,output);
}
console.log(process.argv.includes('--check')?'Schemas match generator':'Generated five structural schemas');
