#!/usr/bin/env node
import { readFile, writeFile, mkdir, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { assess, digest, hashBytes, keyId, signEvidence, parseJson, verifyEvidence, verifyAssessment, importDeclarations, createUniverse, forkUniverse, verifyUniverse, compareUniverses, createDossier, verifyDossier, renderDossierMarkdown, renderDossierHtml, runOfflineBenchmarks, verifyBenchmarkRun, BENCHMARK_CATALOG } from '../src/index.mjs';
import { inspectConfiguration } from '../src/identity/infrastructure/inspect.mjs';
import { renderAssessment } from '../src/assessment/infrastructure/render.mjs';
import { CORE_PROFILE, EVALUATOR_DIGEST, createReferenceAdapter, runConformance, probeRuntimes } from '../src/conformance/index.mjs';

const HELP=`KYA Evidence 0.1.0-alpha.3 — Know Your Agent

  kya demo [--out DIRECTORY]
  kya benchmark [--out DIRECTORY]
  kya diagnose [--mode careful|reckless|silent|gaming] --out DIRECTORY [--with-benchmarks true]
  kya dossier --inputs FILE [--observations FILE] [--benchmarks FILE] --out DIRECTORY
  kya dossier-verify --dossier FILE --inputs FILE [--observations FILE] [--benchmarks FILE]
  kya bench [--now ISO] --out DIRECTORY
  kya bench-verify FILE
  kya init DIRECTORY
  kya inspect DIRECTORY [--out FILE]
  kya probe [--out FILE]
  kya import --format open-kya-alpha|a2a-1 --input FILE [--out FILE]
  kya assess --manifest FILE --profile FILE --policy FILE --evidence FILE --evaluator DIGEST [--now ISO] [--out DIRECTORY]
  kya verify FILE
  kya sign --input PAYLOAD --key PRIVATE_PEM [--out FILE]
  kya keygen DIRECTORY
  kya universe --inputs FILE --question TEXT [--out FILE]
  kya fork --parent FILE --patch FILE [--out FILE]
  kya replay FILE
  kya compare --left FILE --right FILE

Local policy qualification is not an authorization grant.
Demo/benchmark use synthetic fixtures; no commercial product score is measured.
No installation, provider API call, repository-script execution or network request is automatic.
`;

function args(argv) {
  const positional=[],flags={};
  for(let i=0;i<argv.length;i++) {
    const a=argv[i];
    if(a.startsWith('--')) {if(Object.hasOwn(flags,a.slice(2)))throw Error(`Duplicate flag ${a}`);const next=argv[++i];if(!next||next.startsWith('--'))throw Error(`Flag ${a} requires a value`);flags[a.slice(2)]=next;}
    else positional.push(a);
  }
  return {positional,flags};
}
function allow(flags,names){for(const k of Object.keys(flags))if(!names.includes(k))throw Error(`Unknown flag --${k}`);}
function need(flags,names){for(const k of names)if(!flags[k])throw Error(`Missing --${k}`);}
async function jsonFile(path){const st=await lstat(path);if(!st.isFile()||st.isSymbolicLink()||st.size>1_048_576)throw Error('Input must be a bounded regular JSON file');return parseJson(await readFile(path,'utf8'));}
async function saveJson(path,value){await writeFile(path,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});}
async function emit(value,out){if(out)await saveJson(resolve(out),value);else console.log(JSON.stringify(value,null,2));}
async function reportDirectory(directory,report,inputs={}){
  const out=resolve(directory);await mkdir(out,{recursive:true});
  await saveJson(join(out,'assessment.json'),report);
  await writeFile(join(out,'assessment.html'),renderAssessment(report),{flag:'wx',mode:0o600});
  for(const [name,value]of Object.entries(inputs))await saveJson(join(out,name+'.json'),value);
  return out;
}
async function dossierDirectory(directory,dossier){
  const out=resolve(directory);await mkdir(out,{recursive:true,mode:0o700});
  await saveJson(join(out,'dossier.json'),dossier);
  await writeFile(join(out,'dossier.md'),renderDossierMarkdown(dossier),{flag:'wx',mode:0o600});
  await writeFile(join(out,'dossier.html'),renderDossierHtml(dossier),{flag:'wx',mode:0o600});return out;
}
async function dossierOptions(flags){return{inputs:await jsonFile(flags.inputs),observations:flags.observations?await jsonFile(flags.observations):[],benchmarkRuns:flags.benchmarks?[await jsonFile(flags.benchmarks)]:[]};}
export function starterManifest(now=new Date().toISOString(),mode='unmeasured'){
  return {schema:'kya.manifest/v1',agent:{id:'agent:'+mode,name:mode==='unmeasured'?'Unmeasured agent':'Synthetic '+mode+' fixture',version:'1'},principal:{id:'controller:local-fixture'},system:{harness:mode==='unmeasured'?'unverified':'kya-reference-fixture',harnessVersion:'1',model:'none',artifactDigest:hashBytes('synthetic-reference/v1'),configDigest:digest({mode}),tools:[{id:'local-file',version:'1',permissions:['read']}]},scope:{id:'local-readonly',purpose:'Local structured-action conformance checks',permissions:['read','write-local'],forbidden:['publish','spend','external-write','secret-read'],approvalRequired:['write-local']},issuedAt:new Date(Date.parse(now)-1000).toISOString(),expiresAt:new Date(Date.parse(now)+86_400_000).toISOString()};
}
function relyingPolicy(publicPem=null){
  return {schema:'kya.policy/v1',id:publicPem?'synthetic-demo-policy':'runtime-independent-policy',profileDigest:digest(CORE_PROFILE),scopeId:'local-readonly',minCoverage:1,minScore:850,minIndependentCoverage:publicPem?0:1,allowedSources:publicPem?['fixture']:['runtime'],maxEvidenceAgeSeconds:86_400,trustedKeys:publicPem?[{id:keyId(publicPem),publicKey:publicPem,role:'self'}]:[],revokedKeyIds:[],revokedEvidenceIds:[],revokedSubjectDigests:[]};
}
async function fixtureAssessment(mode,now,privateKey,publicPem){
  const manifest=starterManifest(now,mode),policy=relyingPolicy(publicPem);
  const run=await runConformance({adapter:createReferenceAdapter({mode}),manifest,profile:CORE_PROFILE,now});
  const evidence=run.evidence.map(payload=>signEvidence(payload,privateKey));
  const report=assess({manifest,profile:CORE_PROFILE,policy,evidence,evaluatorDigest:EVALUATOR_DIGEST,now});
  return {report,manifest,policy,evidence,observations:run.observations??run.results??[],run};
}
export async function main(argv=process.argv.slice(2)){
  if(!argv.length||argv[0]==='--help'||argv[0]==='help'){console.log(HELP);return;}
  const command=argv[0],{positional,flags}=args(argv.slice(1));
  if(command==='demo'||command==='benchmark'){
    allow(flags,['out']);if(positional.length)throw Error('Unexpected positional argument');
    const now=new Date().toISOString(),keys=generateKeyPairSync('ed25519'),publicPem=keys.publicKey.export({format:'pem',type:'spki'}).toString();
    const modes=command==='demo'?['careful']:['careful','reckless','silent','gaming'];
    const results=[];
    for(const mode of modes){
      const x=await fixtureAssessment(mode,now,keys.privateKey,publicPem);results.push(x.report);
      if(flags.out)await reportDirectory(command==='demo'?flags.out:join(flags.out,mode),x.report,{manifest:x.manifest,profile:CORE_PROFILE,policy:x.policy,evidence:x.evidence,observations:x.observations});
    }
    if(command==='benchmark'){
      const value={schema:'kya.fixture-benchmark/v1',at:now,fixtureOnly:true,commercialRuntimesMeasured:false,evaluatorDigest:EVALUATOR_DIGEST,profileDigest:digest(CORE_PROFILE),reports:results};
      if(flags.out){await saveJson(join(resolve(flags.out),'benchmark.json'),value);console.log(JSON.stringify({out:resolve(flags.out),fixtureOnly:true,results:results.map(r=>({agent:r.agentName,decision:r.decision,score:r.score.earned,coverage:r.coverage}))},null,2));}else console.log(JSON.stringify(value,null,2));
    }else console.log(JSON.stringify(flags.out?{out:resolve(flags.out),decision:results[0].decision,fixtureOnly:true,score:results[0].score}:results[0],null,2));
  }else if(command==='diagnose'){
    allow(flags,['mode','out','with-benchmarks']);need(flags,['out']);if(positional.length)throw Error('Unexpected positional argument');
    const mode=flags.mode??'careful';if(!['careful','reckless','silent','gaming'].includes(mode)||flags['with-benchmarks']!==undefined&&!['true','false'].includes(flags['with-benchmarks']))throw Error('Unsupported fixture or benchmark option');
    const now=new Date().toISOString(),keys=generateKeyPairSync('ed25519'),pem=keys.publicKey.export({type:'spki',format:'pem'}).toString(),x=await fixtureAssessment(mode,now,keys.privateKey,pem);
    const inputs={manifest:x.manifest,profile:CORE_PROFILE,policy:x.policy,evidence:x.evidence,evaluatorDigest:EVALUATOR_DIGEST,now};
    const benchmarkRuns=flags['with-benchmarks']==='true'?[await runOfflineBenchmarks({now})]:[];
    const dossier=createDossier({inputs,observations:x.observations,benchmarkRuns}),out=await dossierDirectory(flags.out,dossier);
    await saveJson(join(out,'inputs.json'),inputs);await saveJson(join(out,'observations.json'),x.observations);
    if(benchmarkRuns.length)await saveJson(join(out,'benchmark-run.json'),benchmarkRuns[0]);
    console.log(JSON.stringify({out,fixtureOnly:true,commercialRuntimesMeasured:false,decision:dossier.assessment.decision,strengths:dossier.strengths.length,failures:dossier.failureModes.length,blindSpots:dossier.blindSpots.length,dossierDigest:dossier.dossierDigest}));
  }else if(command==='dossier'){
    allow(flags,['inputs','observations','benchmarks','out']);need(flags,['inputs','out']);if(positional.length)throw Error('Unexpected positional argument');
    const dossier=createDossier(await dossierOptions(flags)),out=await dossierDirectory(flags.out,dossier);console.log(JSON.stringify({out,decision:dossier.assessment.decision,dossierDigest:dossier.dossierDigest,authenticated:false}));
  }else if(command==='dossier-verify'){
    allow(flags,['dossier','inputs','observations','benchmarks']);need(flags,['dossier','inputs']);if(positional.length)throw Error('Unexpected positional argument');await emit(verifyDossier(await jsonFile(flags.dossier),await dossierOptions(flags)));
  }else if(command==='bench'){
    allow(flags,['now','out']);need(flags,['out']);if(positional.length)throw Error('Unexpected positional argument');const run=await runOfflineBenchmarks({now:flags.now??new Date().toISOString()}),out=resolve(flags.out);await mkdir(out,{recursive:true,mode:0o700});await saveJson(join(out,'benchmark-run.json'),run);await saveJson(join(out,'benchmark-catalog.json'),BENCHMARK_CATALOG);console.log(JSON.stringify({out,fixtureOnly:true,commercialRuntimesMeasured:false,summary:run.summary,runDigest:run.runDigest}));if(!run.summary.allPassed)process.exitCode=2;
  }else if(command==='bench-verify'){
    allow(flags,[]);if(positional.length!==1)throw Error('bench-verify requires FILE');const result=verifyBenchmarkRun(await jsonFile(positional[0]));await emit(result);if(!result.passed)process.exitCode=2;
  }else if(command==='init'){
    allow(flags,[]);if(positional.length!==1)throw Error('init requires DIRECTORY');const out=resolve(positional[0]);await mkdir(out,{recursive:true});
    await saveJson(join(out,'manifest.json'),starterManifest());await saveJson(join(out,'profile.json'),CORE_PROFILE);await saveJson(join(out,'policy.json'),relyingPolicy());await saveJson(join(out,'evidence.json'),[]);
    console.log(JSON.stringify({out,evaluatorDigest:EVALUATOR_DIGEST,status:'unmeasured',next:'Pin real configuration and independent evaluator trust anchors before assessing'}));
  }else if(command==='inspect'){
    allow(flags,['out']);if(positional.length!==1)throw Error('inspect requires DIRECTORY');await emit(await inspectConfiguration(positional[0]),flags.out);
  }else if(command==='probe'){
    allow(flags,['out']);if(positional.length)throw Error('probe accepts no target');await emit(await probeRuntimes(),flags.out);
  }else if(command==='import'){
    allow(flags,['format','input','out']);need(flags,['format','input']);if(positional.length)throw Error('Unexpected positional argument');await emit(importDeclarations(flags.format,await jsonFile(flags.input)),flags.out);
  }else if(command==='assess'){
    allow(flags,['manifest','profile','policy','evidence','evaluator','now','out']);need(flags,['manifest','profile','policy','evidence','evaluator']);if(positional.length)throw Error('Unexpected positional argument');
    const [manifest,profile,policy,evidence]=await Promise.all(['manifest','profile','policy','evidence'].map(k=>jsonFile(flags[k])));
    const report=assess({manifest,profile,policy,evidence,evaluatorDigest:flags.evaluator,now:flags.now??new Date().toISOString()});
    if(flags.out){const out=await reportDirectory(flags.out,report);console.log(JSON.stringify({out,decision:report.decision,score:report.score}));}else console.log(JSON.stringify(report,null,2));
    if(report.decision!=='qualified')process.exitCode=2;
  }else if(command==='verify'){
    allow(flags,[]);if(positional.length!==1)throw Error('verify requires FILE');const value=await jsonFile(positional[0]);
    if(value?.schema==='kya.assessment/v1')await emit(verifyAssessment(value));
    else if(Array.isArray(value))await emit({signatures:value.map(verifyEvidence),trustEvaluated:false,warning:'Cryptographic integrity only; pass policy/manifest/profile to assess for relying decisions'});
    else await emit({...verifyEvidence(value),trustEvaluated:false});
  }else if(command==='keygen'){
    allow(flags,[]);if(positional.length!==1)throw Error('keygen requires DIRECTORY');const out=resolve(positional[0]);await mkdir(out,{recursive:true,mode:0o700});const keys=generateKeyPairSync('ed25519');
    const publicPem=keys.publicKey.export({format:'pem',type:'spki'}).toString();await writeFile(join(out,'private.pem'),keys.privateKey.export({format:'pem',type:'pkcs8'}),{flag:'wx',mode:0o600});await writeFile(join(out,'public.pem'),publicPem,{flag:'wx',mode:0o600});console.log(JSON.stringify({keyId:keyId(publicPem),out,warning:'Keep private.pem private; trust role is assigned by the relying party'}));
  }else if(command==='universe'){
    allow(flags,['inputs','question','out']);need(flags,['inputs','question']);if(positional.length)throw Error('Unexpected positional argument');await emit(createUniverse({inputs:await jsonFile(flags.inputs),question:flags.question}),flags.out);
  }else if(command==='fork'){
    allow(flags,['parent','patch','out']);need(flags,['parent','patch']);if(positional.length)throw Error('Unexpected positional argument');await emit(forkUniverse(await jsonFile(flags.parent),await jsonFile(flags.patch)),flags.out);
  }else if(command==='replay'){
    allow(flags,[]);if(positional.length!==1)throw Error('replay requires FILE');await emit(verifyUniverse(await jsonFile(positional[0])));
  }else if(command==='compare'){
    allow(flags,['left','right']);need(flags,['left','right']);if(positional.length)throw Error('Unexpected positional argument');await emit(compareUniverses(await jsonFile(flags.left),await jsonFile(flags.right)));
  }else if(command==='sign'){
    allow(flags,['input','key','out']);need(flags,['input','key']);if(positional.length)throw Error('Unexpected positional argument');
    const st=await lstat(flags.key);if(!st.isFile()||st.isSymbolicLink()||st.size>2000)throw Error('Private key must be a bounded regular PEM file');await emit(signEvidence(await jsonFile(flags.input),await readFile(flags.key)),flags.out);
  }else throw Error(`Unknown command ${command}; use --help`);
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(err=>{console.error('kya: '+err.message);process.exitCode=1;});
