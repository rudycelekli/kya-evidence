import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync,spawn } from 'node:child_process';
import { mkdtemp,readFile,writeFile,rm,stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { verifyEvidence,verifyAssessment } from '../src/index.mjs';
import { inputs } from './helpers.mjs';
import { renderAssessment } from '../src/assessment/infrastructure/render.mjs';

const root=fileURLToPath(new URL('../',import.meta.url)),bin=join(root,'bin/kya.mjs');
const run=args=>spawnSync(process.execPath,[bin,...args],{cwd:root,encoding:'utf8',timeout:15000,maxBuffer:2_097_152});
test('CLI help and unknown flags have useful bounded behavior',()=>{
  assert.match(run(['--help']).stdout,/Know Your Agent/);const x=run(['demo','--evil','yes']);assert.equal(x.status,1);assert.match(x.stderr,/Unknown flag/);
  assert.equal(run(['demo','--out']).status,1);assert.equal(run(['unknown']).status,1);assert.equal(run(['probe','--out','a','--out','b']).status,1);
});
test('CLI demo creates verifiable signed evidence and report without a private key',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'kya-demo-'));
  try{const p=run(['demo','--out',dir]);assert.equal(p.status,0,p.stderr);const r=JSON.parse(await readFile(join(dir,'assessment.json'),'utf8'));assert.equal(r.evidenceMode,'fixture');assert.equal(r.decision,'qualified');assert.equal(verifyAssessment(r).integrity,true);const es=JSON.parse(await readFile(join(dir,'evidence.json'),'utf8'));assert.equal(es.length,18);es.forEach(verifyEvidence);assert.equal(run(['demo','--out',dir]).status,1);assert.equal((await readFile(join(dir,'policy.json'),'utf8')).includes('PRIVATE KEY'),false);}
  finally{await rm(dir,{recursive:true,force:true});}
});
test('benchmark differentiates careful unsafe abstaining and gaming fixtures',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'kya-benchmark-'));
  try{const p=run(['benchmark','--out',dir]);assert.equal(p.status,0,p.stderr);const value=JSON.parse(await readFile(join(dir,'benchmark.json'),'utf8'));assert.equal(value.fixtureOnly,true);assert.equal(value.commercialRuntimesMeasured,false);assert.equal(value.reports[0].decision,'qualified');assert.equal(value.reports[1].decision,'blocked');assert.equal(value.reports[2].decision,'insufficient-evidence');assert.equal(value.reports[3].decision,'blocked');}
  finally{await rm(dir,{recursive:true,force:true});}
});
test('CLI assessment is reproducible, verifies checksums, and fails closed in CI',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'kya-assess-'));
  try{const x=inputs();for(const k of ['manifest','profile','policy','evidence'])await writeFile(join(dir,k+'.json'),JSON.stringify(x[k]));
    const cmd=['assess',...['manifest','profile','policy','evidence'].flatMap(k=>['--'+k,join(dir,k+'.json')]),'--evaluator',x.evaluatorDigest,'--now',x.now];const a=run(cmd),b=run(cmd);assert.equal(a.status,0,a.stderr);assert.equal(a.stdout,b.stdout);const r=JSON.parse(a.stdout);await writeFile(join(dir,'report.json'),a.stdout);assert.equal(JSON.parse(run(['verify',join(dir,'report.json')]).stdout).authenticated,false);
    await writeFile(join(dir,'evidence.json'),'[]');assert.equal(run(cmd).status,2);await writeFile(join(dir,'manifest.json'),'{"schema":1,"schema":2}');assert.equal(run(cmd).status,1);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('keygen keeps secrets off stdout and refuses existing file overwrite',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'kya-key-'));
  try{const p=run(['keygen',dir]);assert.equal(p.status,0,p.stderr);assert.equal(p.stdout.includes('PRIVATE KEY'),false);assert.equal((await stat(join(dir,'private.pem'))).mode&0o777,0o600);assert.equal(run(['keygen',dir]).status,1);}
  finally{await rm(dir,{recursive:true,force:true});}
});
test('HTML renderer escapes untrusted names, check titles, reasons and identifiers',()=>{
  const attack='<img src=x onerror=alert(1)>';
  // Rendering does not execute content or depend on a DOM implementation.
  const report={agentName:attack,evidenceMode:'none',score:{earned:0,upperBound:1000},decision:'insufficient-evidence',coverage:0,independentCoverage:0,validUntil:attack,scopeId:attack,blockers:[attack],checks:[{id:attack,dimension:'security',critical:true,status:'unknown',evidenceId:attack}],rejectedEvidence:[{index:0,id:attack,reason:attack}],subjectDigest:'a',profileDigest:'b',evaluatorDigest:'c',policyDigest:'d',reportDigest:'e'};
  const html=renderAssessment(report);assert.equal(html.includes(attack),false);assert.match(html,/&lt;img/);assert.match(html,/default-src 'none'/);
});
test('local server serves public docs/modules but refuses private paths',async()=>{
  const child=spawn(process.execPath,[join(root,'scripts/serve.mjs')],{cwd:root,env:{...process.env,KYA_PORT:'0'},stdio:['ignore','pipe','pipe']});
  try{const url=await new Promise((resolve,reject)=>{let output='';const timer=setTimeout(()=>reject(Error('Server startup timeout')),5000);child.stdout.on('data',b=>{output+=b;if(/http:\/\/127.0.0.1:\d+/.test(output)){clearTimeout(timer);resolve(output.match(/http:\/\/127.0.0.1:\d+/)[0]);}});child.once('exit',code=>{clearTimeout(timer);reject(Error('Server exited '+code));});});
    assert.equal((await fetch(url+'/')).status,200);assert.equal((await fetch(url+'/README.md')).status,200);assert.equal((await fetch(url+'/.private/checkpoint.json')).status,404);assert.equal((await fetch(url+'/%2e%2e/.git/config')).status,404);assert.equal((await fetch(url+'/',{method:'POST'})).status,405);
  }finally{child.kill('SIGTERM');}
});
test('CLI currency exits 0 for an unchanged subject and 2 with triggers after a manifest change',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'kya-currency-'));
  try{
    const {assess}=await import('../src/index.mjs'),i=inputs(),report=assess(i),w=(n,v)=>writeFile(join(dir,n),JSON.stringify(v));
    await w('a.json',report);await w('m.json',i.manifest);await w('p.json',i.policy);
    const base=['currency','--assessment',join(dir,'a.json'),'--policy',join(dir,'p.json'),'--now',i.now];
    const ok=run([...base,'--manifest',join(dir,'m.json')]);assert.equal(ok.status,0,ok.stderr);assert.equal(JSON.parse(ok.stdout).action,'none');
    await w('m2.json',{...i.manifest,agent:{...i.manifest.agent,version:'9'}});
    const bad=run([...base,'--manifest',join(dir,'m2.json')]);assert.equal(bad.status,2);assert.equal(JSON.parse(bad.stdout).triggers[0].id,'subject-changed');
    assert.equal(run([...base]).status,1);
  }finally{await rm(dir,{recursive:true,force:true});}
});
