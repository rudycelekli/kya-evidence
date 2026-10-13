import { mkdtemp,cp,readFile,writeFile,rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { hashBytes } from '../src/index.mjs';

const root=fileURLToPath(new URL('../',import.meta.url)),source='src/assessment/application/assess.mjs';
const original=await readFile(join(root,source),'utf8');
const mutants=[
  ['trust-anchor bypass',"const k = trusted.get(e.keyId);","const k = trusted.get(e.keyId) ?? {role:'independent'};"],
  ['revoked-key bypass',"insist(!policy.revokedKeyIds.includes(e.keyId),'Signing key is revoked');","/* mutation: skip key revocation */"],
  ['declaration laundering',"insist(p.source !== 'declaration','A declaration cannot satisfy an observed check');","/* mutation: allow declaration */"],
  ['critical-gate removal',"const criticalFailures = checks.filter(c=>c.critical && c.status==='fail');","const criticalFailures = [];"],
  ['ambiguity-gate removal',"const ambiguousRuns = tiedRuns.length>1;","const ambiguousRuns = false;"],
  ['duplicate fallback laundering',"for (const e of bound) {\n    const id = e.payload.runId;","for (const e of unique) {\n    const id = e.payload.runId;"]
];
const results=[];
function counts(output){const get=name=>Number(new RegExp(`^# ${name} (\\d+)$`,'m').exec(output)?.[1]??NaN);return{tests:get('tests'),pass:get('pass'),fail:get('fail'),cancelled:get('cancelled'),skipped:get('skipped')};}
function runTests(dir){const p=spawnSync(process.execPath,['--test','--test-reporter=tap','test/assessment.test.mjs'],{cwd:dir,encoding:'utf8',timeout:10000,maxBuffer:200000});if(p.error||p.signal)throw Error('Mutation test execution failed');return{process:p,counts:counts(p.stdout)};}
for(const [name,from,to]of mutants){
  if(!original.includes(from))throw Error('Mutation anchor drift: '+name);
  const dir=await mkdtemp(join(tmpdir(),'kya-mutant-'));
  try{await cp(join(root,'src'),join(dir,'src'),{recursive:true});await cp(join(root,'test'),join(dir,'test'),{recursive:true});await cp(join(root,'package.json'),join(dir,'package.json'));await cp(join(root,'profiles'),join(dir,'profiles'),{recursive:true});
    const baseline=runTests(dir);if(baseline.process.status!==0||!Number.isSafeInteger(baseline.counts.tests)||baseline.counts.tests<1||baseline.counts.fail!==0||baseline.counts.cancelled!==0||baseline.counts.skipped!==0)throw Error('Mutation baseline did not run cleanly: '+name);
    const mutated=original.replace(from,to);await writeFile(join(dir,source),mutated);const candidate=runTests(dir);
    if(candidate.counts.tests!==baseline.counts.tests||candidate.counts.cancelled!==0||candidate.counts.skipped!==0)throw Error('Mutant did not exercise identical complete test population: '+name);
    const killed=candidate.process.status!==0&&candidate.counts.fail>0;results.push({name,killed,baselineTests:baseline.counts.tests,mutantTests:candidate.counts.tests,failedAssertions:candidate.counts.fail,mutantSourceDigest:hashBytes(mutated),exitCode:candidate.process.status});
    if(!killed)throw Error('SURVIVING evaluator mutant: '+name);
  }finally{await rm(dir,{recursive:true,force:true});}
}
console.log(JSON.stringify({schema:'kya.mutation-controls/v1',baselineSourceDigest:hashBytes(original),controls:results,allKilled:true,limits:'Six targeted gate mutations; not exhaustive security verification'},null,2));
