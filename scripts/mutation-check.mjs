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
,
  ['principal-binding gate removal',"const principalUnbound = policy.requirePrincipalBinding === true && !manifest.principal.accountableParty;","const principalUnbound = false;"],
  ['expiry trigger removal',"if (at > validUntil) fire(","if (false) fire(",'src/assessment/application/currency.mjs'],
  ['subject-change trigger removal',"if (digest(manifest) !== assessment.subjectDigest) fire(","if (false) fire(",'src/assessment/application/currency.mjs'],
  ['independent-resolution requirement removal',"else if (e.role!=='independent') ignored.push","else if (false) ignored.push",'src/assessment/application/currency.mjs'],
  ['incident trust-anchor bypass',"if (!roles.has(keyId)) skip(","if (false) skip(",'src/assessment/application/currency.mjs'],
  ['blocking-severity downgrade',"const BLOCKING = ['high','critical'];","const BLOCKING = ['critical'];",'src/assessment/application/currency.mjs'],
  ['reporter self-resolution allowed',"else if (targets[0].keyId===e.keyId) ignored.push","else if (false) ignored.push",'src/assessment/application/currency.mjs'],
  ['malformed validity accepted',"insist(timestamp(assessment.validUntil,'Assessment validity') >= timestamp(assessment.assessedAt,'Assessment time'),'Assessment validity precedes its assessment time');","",'src/assessment/application/currency.mjs'],
  ['future resolution honoured',"if (e.future) { ignored.push({id:e.id,reason:'Incident is dated in the future'}); continue; }","",'src/assessment/application/currency.mjs'],
  ['envelope dedupe removed',"if (seen.has(envelopeDigest)) continue;","",'src/assessment/application/currency.mjs'],
  ['ambiguous-reference gate removed',"if ((counts.get(e.refId)??0)>1) ignored.push","if (false) ignored.push",'src/assessment/application/currency.mjs'],
  ['mandatory-minimum gate removal',"if (decision!=='revoked' && decision!=='expired') {\n    for (const m of policy.mandatoryMinimums","if (false) {\n    for (const m of policy.mandatoryMinimums"],
  ['mandatory-minimum unknown treated as met',"if (c.status==='pass' && (m.minimum==='pass'","if (c.status!=='fail' && (m.minimum==='pass'"],
  ['independent-pass downgraded to pass',"(m.minimum==='pass' || c.independence==='independent')","(true)"],
  ['mandatory-minimum overrides revoked subject',"if (decision!=='revoked' && decision!=='expired') {\n    for (const m of policy.mandatoryMinimums","if (true) {\n    for (const m of policy.mandatoryMinimums"],
  ['mandatory-minimum profile binding removed',"for (const m of policy.mandatoryMinimums ?? []) insist(checkIds.has(m.checkId),'Mandatory minimum names a check outside the frozen profile');","/* mutation: skip minimum profile binding */"],
  ['blocker code dropped from report',"blockers.push(text); blockerCodes.push(code);","blockers.push(text);"],
  ['critical failure mislabelled',"block('CRITICAL_CHECK_FAILED',","block('SCORE_BELOW_POLICY',"],
  ['blocker code validation removed',"if (!Object.hasOwn(report, 'blockerCodes')) return;","return;",'src/assessment/application/codes.mjs'],
  ['duplicate minimum accepted',"insist(!seen.has(e.checkId),'Duplicate mandatory minimum check'); ","",'src/identity/domain/services/validation.mjs'],
  ['currency trigger code removed',"code:CURRENCY_CODES[id],","",'src/assessment/application/currency.mjs'],
  ['report exit-code check removed',"else if (found[0].status === 'skip' || run.error || (run.exitCode !== 0 && !run.tests.some(x => x.status === 'fail'))) unknown = true;","else if (found[0].status === 'skip') unknown = true;",'src/conformance-report/report.mjs'],
  ['blocker-code critical count cross-check removed',"insist(c.filter(x => x === 'CRITICAL_CHECK_FAILED').length === failedCritical, 'Invalid blocker codes: critical failure count does not match the report checks');","",'src/assessment/application/codes.mjs'],
  ['unproven minimum named as failed',"else block('MANDATORY_MINIMUM_UNPROVEN',","else block('MANDATORY_MINIMUM_NOT_MET',",'src/assessment/application/assess.mjs'],
  ['ambiguity judged only over live reports',"if ((counts.get(e.refId)??0)>1) ignored.push","if (targets.length>1) ignored.push",'src/assessment/application/currency.mjs']
];
const results=[];
function failedNames(output){return [...output.matchAll(/^not ok \d+ - (.+)$/gm)].map(m=>m[1]).slice(0,5);}
function counts(output){const get=name=>Number(new RegExp(`^# ${name} (\\d+)$`,'m').exec(output)?.[1]??NaN);return{tests:get('tests'),pass:get('pass'),fail:get('fail'),cancelled:get('cancelled'),skipped:get('skipped')};}
function runTests(dir){const p=spawnSync(process.execPath,['--test','--test-reporter=tap','test/assessment.test.mjs','test/incidents.test.mjs','test/refusal-codes.test.mjs','test/mandatory-minimums.test.mjs','test/conformance-report.test.mjs'],{cwd:dir,encoding:'utf8',timeout:90000,maxBuffer:200000});if(p.error||p.signal)throw Error('Mutation test execution failed');return{process:p,counts:counts(p.stdout)};}
for(const [name,from,to,target=source]of mutants){
  const base=target===source?original:await readFile(join(root,target),'utf8');
  if(!base.includes(from))throw Error('Mutation anchor drift: '+name);
  const dir=await mkdtemp(join(tmpdir(),'kya-mutant-'));
  try{await cp(join(root,'src'),join(dir,'src'),{recursive:true});await cp(join(root,'test'),join(dir,'test'),{recursive:true});await cp(join(root,'package.json'),join(dir,'package.json'));await cp(join(root,'profiles'),join(dir,'profiles'),{recursive:true});for(const extra of ['dashboard','docs','schemas','scripts','evidence'])await cp(join(root,extra),join(dir,extra),{recursive:true});
    const baseline=runTests(dir);if(baseline.process.status!==0||!Number.isSafeInteger(baseline.counts.tests)||baseline.counts.tests<1||baseline.counts.fail!==0||baseline.counts.cancelled!==0||baseline.counts.skipped!==0)throw Error('Mutation baseline did not run cleanly: '+name);
    const mutated=base.replace(from,to);await writeFile(join(dir,target),mutated);const candidate=runTests(dir);
    if(candidate.counts.tests!==baseline.counts.tests||candidate.counts.cancelled!==0||candidate.counts.skipped!==0)throw Error('Mutant did not exercise identical complete test population: '+name);
    const killed=candidate.process.status!==0&&candidate.counts.fail>0;results.push({name,killed,killedBy:failedNames(candidate.process.stdout),baselineTests:baseline.counts.tests,mutantTests:candidate.counts.tests,failedAssertions:candidate.counts.fail,mutantSourceDigest:hashBytes(mutated),exitCode:candidate.process.status});
    if(!killed)throw Error('SURVIVING evaluator mutant: '+name);
  }finally{await rm(dir,{recursive:true,force:true});}
}
console.log(JSON.stringify({schema:'kya.mutation-controls/v1',baselineSourceDigest:hashBytes(original),controls:results,allKilled:true,limits:'Targeted gate mutations with textual anchors; not exhaustive security verification'},null,2));
