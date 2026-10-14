import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir,mkdtemp,writeFile,rm,readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseClaudeResult,parseCodexEvents,buildClaudeCodePlan,buildCodexExecPlan,createClaudeCodeAdapter,createCodexExecAdapter,runConformance } from '../src/conformance/index.mjs';
import { executeNativeTransport } from '../src/conformance/infrastructure/native-transport.mjs';
import { preflightCodexInstructions,preflightCodexAuth } from '../src/conformance/infrastructure/native-policy.mjs';
import { hashBytes } from '../src/shared/canonical.mjs';
import manifest from '../examples/manifest.json' with {type:'json'};

const response={actions:[],final:{status:'refused',reason:'secret-boundary'},usage:{costUsd:null,latencyMs:null}};
const claude=(patch={})=>({type:'result',subtype:'success',is_error:false,result:JSON.stringify(response),permission_denials:[],...patch});
const prefix=[{type:'thread.started',thread_id:'synthetic-thread'},{type:'turn.started'}];
const final=(id='answer')=>({type:'item.completed',item:{id,type:'agent_message',text:JSON.stringify(response)}});
const codex=(items=[final()],terminal={type:'turn.completed'})=>[...prefix,...items,terminal].map(e=>JSON.stringify(e)).join('\n')+'\n';
const options={executable:process.execPath,cwd:process.cwd(),model:'synthetic-no-model'};
const codeError=code=>error=>error.code===code&&!error.message.includes('SYNTHETIC_PRIVATE_LOG');

test('Claude result parses declared output with completion and exact byte digest',()=>{
  const raw=JSON.stringify(claude());const parsed=parseClaudeResult(raw);assert.equal(parsed.accepted,true);assert.equal(parsed.source,'declaration');assert.equal(parsed.runtimeStatus,'completed');assert.equal(parsed.rawOutputDigest,hashBytes(raw));assert.deepEqual(parsed.response,response);assert.equal(parsed.events.length,1);
  assert.equal(parseClaudeResult(JSON.stringify(claude({result:'',structured_output:response}))).accepted,true);
});
test('Claude failed result survives without leaking provider error text',()=>{
  const raw=JSON.stringify(claude({subtype:'error_max_turns',is_error:true,result:'SYNTHETIC_PRIVATE_LOG'}));const parsed=parseClaudeResult(raw);assert.equal(parsed.runtimeStatus,'failed');assert.equal(parsed.response,null);assert.equal(parsed.accepted,false);assert(!JSON.stringify(parsed).includes('SYNTHETIC_PRIVATE_LOG'));
});
test('Claude refuses multiple final outputs, malformed flags and hidden tool attempts',()=>{
  assert.throws(()=>parseClaudeResult(JSON.stringify([claude(),claude()])),codeError('NATIVE_AMBIGUOUS_COMPLETION'));
  assert.throws(()=>parseClaudeResult(JSON.stringify(claude({structured_output:response}))),codeError('NATIVE_AMBIGUOUS_FINAL'));
  assert.throws(()=>parseClaudeResult(JSON.stringify(claude({is_error:'false'}))),codeError('NATIVE_INVALID_COMPLETION'));
  assert.throws(()=>parseClaudeResult(JSON.stringify(claude({is_error:true}))),codeError('NATIVE_INVALID_COMPLETION'));
  const tool=[{type:'assistant',message:{content:[{type:'tool_use',name:'Bash',input:{command:'SYNTHETIC_PRIVATE_LOG'}}]}},claude()];const parsed=parseClaudeResult(JSON.stringify(tool));assert.equal(parsed.accepted,false);assert.equal(parsed.response,null);assert(parsed.toolAttempts.some(a=>a.kind==='tool_use'));assert(!JSON.stringify(parsed).includes('SYNTHETIC_PRIVATE_LOG'));
  const denied=parseClaudeResult(JSON.stringify(claude({permission_denials:[{tool_name:'Bash'}]})));assert.equal(denied.accepted,false);assert(denied.violations.includes('native-tool-attempt'));
});
test('Codex one completed turn retains event summaries and declaration provenance',()=>{
  const raw=codex();const parsed=parseCodexEvents(Buffer.from(raw));assert.equal(parsed.accepted,true);assert.equal(parsed.source,'declaration');assert.equal(parsed.rawOutputDigest,hashBytes(raw));assert.deepEqual(parsed.response,response);assert.deepEqual(parsed.events.map(e=>e.type),['thread.started','turn.started','item.completed','turn.completed']);
  const commentary={type:'item.completed',item:{id:'progress',type:'agent_message',phase:'commentary',text:'SYNTHETIC_PRIVATE_LOG'}};const parsedCommentary=parseCodexEvents(codex([commentary,final()]));assert.equal(parsedCommentary.accepted,true);assert(!JSON.stringify(parsedCommentary).includes('SYNTHETIC_PRIVATE_LOG'));
});
test('Codex failed/error turns dominate any polished final',()=>{
  for(const raw of [codex([final()],{type:'turn.failed',error:{message:'SYNTHETIC_PRIVATE_LOG'}}),codex([{type:'error',message:'SYNTHETIC_PRIVATE_LOG'},final()])]){const parsed=parseCodexEvents(raw);assert.equal(parsed.runtimeStatus,'failed');assert.equal(parsed.accepted,false);assert.equal(parsed.response,null);assert(!JSON.stringify(parsed).includes('SYNTHETIC_PRIVATE_LOG'));}
});
test('Codex native tool events cannot be laundered as a clean asserted trace',()=>{
  for(const kind of ['command_execution','file_change','mcp_tool_call','web_search']){
    const tool={type:'item.completed',item:{id:'tool',type:kind,command:'SYNTHETIC_PRIVATE_LOG',status:'failed'}};const parsed=parseCodexEvents(codex([tool,final()]));assert.equal(parsed.accepted,false);assert.equal(parsed.response,null);assert(parsed.toolAttempts.some(a=>a.kind===kind));assert(!JSON.stringify(parsed).includes('SYNTHETIC_PRIVATE_LOG'));
  }
  const disguised={type:'item.completed',item:{id:'reason',type:'reasoning',payload:{type:'tool_use',command:'hidden'}}};assert.equal(parseCodexEvents(codex([disguised,final()])).accepted,false);
});
test('Codex ambiguous finals, repeated completions, unknown items and missing turns reject',()=>{
  assert.throws(()=>parseCodexEvents(codex([final('one'),final('two')])),codeError('NATIVE_AMBIGUOUS_FINAL'));
  assert.throws(()=>parseCodexEvents(codex([final('same'),final('same')])),codeError('NATIVE_DUPLICATE_ITEM'));
  assert.throws(()=>parseCodexEvents(codex()+'{"type":"turn.completed"}\n'),codeError('NATIVE_AMBIGUOUS_COMPLETION'));
  assert.throws(()=>parseCodexEvents(codex([{type:'item.completed',item:{id:'new',type:'new_tool_kind'}},final()])),codeError('NATIVE_UNKNOWN_ITEM'));
  assert.throws(()=>parseCodexEvents(JSON.stringify(final())),codeError('NATIVE_INVALID_SEQUENCE'));
  assert.throws(()=>parseCodexEvents(prefix.map(e=>JSON.stringify(e)).join('\n')),codeError('NATIVE_MISSING_COMPLETION'));
});
test('both parsers reject duplicate JSON, malformed UTF8, unbounded bytes and protocol forgery',()=>{
  for(const parser of [parseClaudeResult,parseCodexEvents]){assert.throws(()=>parser(Buffer.from([255])),codeError('NATIVE_INVALID_UTF8'));assert.throws(()=>parser('x'.repeat(262145)),codeError('OUTPUT_LIMIT'));}
  assert.throws(()=>parseClaudeResult('{"type":"result","type":"result"}'),codeError('NATIVE_MALFORMED_JSON'));
  assert.throws(()=>parseCodexEvents('{"type":"thread.started","thread_id":"x","thread_id":"y"}\n'),codeError('NATIVE_MALFORMED_JSON'));
  assert.throws(()=>parseClaudeResult(JSON.stringify(claude({result:JSON.stringify({...response,source:'runtime'})}))),codeError('NATIVE_INVALID_RESPONSE'));
  assert.throws(()=>parseCodexEvents(codex().replace('\n','\n\n')),codeError('NATIVE_INVALID_JSONL'));
  assert.throws(()=>parseCodexEvents(Array(514).fill('{"type":"error"}').join('\n')),codeError('NATIVE_EVENT_LIMIT'));
});
test('plans are explicit, frozen and refuse authority override fields',()=>{
  const claudePlan=buildClaudeCodePlan(options),codexPlan=buildCodexExecPlan(options);assert.equal(claudePlan.observationSource,'declaration');assert.equal(claudePlan.executionState,'blocked-managed-policy-unresolved');assert(claudePlan.args.includes('--tools'));assert.equal(claudePlan.args[claudePlan.args.indexOf('--tools')+1],'');assert(claudePlan.args.includes('--no-chrome'));assert(codexPlan.args.includes('read-only'));assert(codexPlan.args.includes('features.shell_tool=false'));assert(codexPlan.args.includes('web_search="disabled"'));
  assert.throws(()=>claudePlan.args.push('--dangerously-skip-permissions'));assert.throws(()=>{codexPlan.environment.OPENAI_API_KEY='injected';});
  for(const patch of [{env:{}},{args:[]},{policyReview:{serverPolicyResolved:true}},{model:'--dangerously-bypass-approvals-and-sandbox'},{timeoutMs:30001},{executable:'relative-cli'}])assert.throws(()=>buildClaudeCodePlan({...options,...patch}),codeError('NATIVE_INVALID_OPTIONS'));
  process.env.OPENAI_API_KEY='SYNTHETIC_PRIVATE_LOG';process.env.ANTHROPIC_API_KEY='SYNTHETIC_PRIVATE_LOG';try{const plan=buildClaudeCodePlan({...options,auth:{home:process.cwd()}});assert(!Object.hasOwn(plan.environment,'OPENAI_API_KEY'));assert(!Object.hasOwn(plan.environment,'ANTHROPIC_API_KEY'));assert.equal(plan.environment.DISABLE_AUTOUPDATER,'1');}finally{delete process.env.OPENAI_API_KEY;delete process.env.ANTHROPIC_API_KEY;}
});
test('factories never promote declared output and require explicit auth before launch',async()=>{
  for(const create of [createClaudeCodeAdapter,createCodexExecAdapter]){const adapter=create(options);await assert.rejects(adapter.run({}),codeError('NATIVE_AUTH_REQUIRED'));const c=new AbortController();c.abort();const run=await runConformance({adapter,manifest,now:'2026-10-13T12:00:00.000Z',signal:c.signal});assert(run.evidence.every(e=>e.source==='declaration'));assert(run.evidence.every(e=>e.outcome==='error'));assert.equal(adapter.inspectObservations().length,0);}
});
test('global Codex instructions are a hard gate even with project docs disabled',async()=>{
  const base=fileURLToPath(new URL('../.private/',import.meta.url));await mkdir(base,{recursive:true});const directory=await mkdtemp(join(base,'native-policy-'));
  try{assert.equal((await preflightCodexInstructions(directory)).status,'no-active-global-instruction-file');const text='Synthetic global instruction';await writeFile(join(directory,'AGENTS.md'),text);await assert.rejects(preflightCodexInstructions(directory),codeError('NATIVE_GLOBAL_INSTRUCTIONS_UNRESOLVED'));assert.equal((await preflightCodexInstructions(directory,hashBytes(text),true)).status,'included-user-instructions');await assert.rejects(preflightCodexInstructions(directory,'1'.repeat(64),true),codeError('NATIVE_GLOBAL_INSTRUCTIONS_UNRESOLVED'));await writeFile(join(directory,'AGENTS.override.md'),text);await assert.rejects(preflightCodexInstructions(directory,hashBytes(text),true),codeError('NATIVE_GLOBAL_INSTRUCTIONS_UNRESOLVED'));}finally{await rm(directory,{recursive:true,force:true});}
});
test('Codex stored API/unknown auth modes are blocked without exposing credentials',async()=>{
  const base=fileURLToPath(new URL('../.private/',import.meta.url));await mkdir(base,{recursive:true});const directory=await mkdtemp(join(base,'native-auth-'));
  try{await assert.rejects(preflightCodexAuth(directory),codeError('NATIVE_AUTH_MODE_UNVERIFIED'));for(const data of [{auth_mode:'api',OPENAI_API_KEY:'SYNTHETIC_PRIVATE_LOG'},{auth_mode:'chatgpt',OPENAI_API_KEY:'SYNTHETIC_PRIVATE_LOG',tokens:{}},{auth_mode:'unknown',tokens:{}}]){await writeFile(join(directory,'auth.json'),JSON.stringify(data));await assert.rejects(preflightCodexAuth(directory),codeError('NATIVE_AUTH_MODE_UNVERIFIED'));}await writeFile(join(directory,'auth.json'),JSON.stringify({auth_mode:'chatgpt',OPENAI_API_KEY:null,tokens:{synthetic:true}}));const result=await preflightCodexAuth(directory);assert.equal(result.mode,'chatgpt');assert(!Object.hasOwn(result,'tokens'));}finally{await rm(directory,{recursive:true,force:true});}
});
test('actual disposable vendor-shaped child observations stay declaration and retain failure',async()=>{
  // This is an owned synthetic Node fixture, not a vendor binary or real login.
  const base=fileURLToPath(new URL('../.private/',import.meta.url));await mkdir(base,{recursive:true});const directory=await mkdtemp(join(base,'native-synthetic-child-'));
  try{
    const executable=join(directory,'synthetic-vendor');await writeFile(join(directory,'auth.json'),JSON.stringify({auth_mode:'chatgpt',OPENAI_API_KEY:null,tokens:{synthetic:true}}));
    await writeFile(executable,`#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(codex())});\n`,{mode:0o700});
    const adapter=createCodexExecAdapter({executable,cwd:directory,model:'synthetic-no-model',auth:{home:directory,codexHome:directory}});
    assert.deepEqual(await adapter.run({schema:'synthetic-test-request'}),response);assert.deepEqual(await adapter.run({schema:'synthetic-test-request'}),response);
    const observed=adapter.inspectObservations();assert.equal(observed.length,2);assert(observed.every(o=>o.source==='declaration'));assert(observed.every(o=>o.transport.exitCode===0));observed[0].rawOutputDigest='changed';assert.notEqual(adapter.inspectObservations()[0].rawOutputDigest,'changed');
    await writeFile(executable,`#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(codex([final()],{type:'turn.failed'}))});process.exit(1);\n`);
    await assert.rejects(adapter.run({schema:'synthetic-test-request'}),codeError('NONZERO_EXIT'));const last=adapter.inspectObservations().at(-1);assert.equal(last.runtimeStatus,'failed');assert.equal(last.accepted,false);assert.equal(last.transport.exitCode,1);
  }finally{await rm(directory,{recursive:true,force:true});}
});
test('Codex optional provider schema is explicitly selected, hashed and rechecked before launch',async()=>{
  const base=fileURLToPath(new URL('../.private/',import.meta.url));await mkdir(base,{recursive:true});const directory=await mkdtemp(join(base,'native-schema-'));
  try{const schemaPath=join(directory,'schema.json'),raw=JSON.stringify({type:'object',properties:{final:{type:'object'}}});await writeFile(schemaPath,raw);const adapter=createCodexExecAdapter({...options,schemaPath,auth:{home:directory,codexHome:directory}});assert.equal(adapter.commandPlan.schemaDigest,hashBytes(raw));assert(adapter.commandPlan.args.includes('--output-schema'));await writeFile(schemaPath,'{}');await assert.rejects(adapter.run({}),codeError('NATIVE_SCHEMA_CHANGED'));assert.equal(adapter.inspectObservations()[0].accepted,false);await writeFile(schemaPath,'{"type":"object","type":"string"}');assert.throws(()=>buildCodexExecPlan({...options,schemaPath}),codeError('NATIVE_SCHEMA_UNVERIFIED'));}finally{await rm(directory,{recursive:true,force:true});}
});
test('explicit transcript capture receives original bounded bytes by copy before acceptance',async()=>{
  const base=fileURLToPath(new URL('../.private/',import.meta.url));await mkdir(base,{recursive:true});const directory=await mkdtemp(join(base,'native-capture-'));
  try{const raw=codex(),executable=join(directory,'synthetic-vendor');await writeFile(executable,`#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(raw)});\n`,{mode:0o700});await writeFile(join(directory,'auth.json'),JSON.stringify({auth_mode:'chatgpt',tokens:{synthetic:true}}));let captured=false;const adapter=createCodexExecAdapter({executable,cwd:directory,model:'synthetic',auth:{home:directory,codexHome:directory},async captureTranscript(bytes,metadata){assert.equal(Buffer.from(bytes).toString('utf8'),raw);assert.equal(metadata.rawOutputDigest,hashBytes(raw));assert.equal(metadata.source,'declaration');assert(!Object.hasOwn(metadata,'stderr'));bytes.fill(0);captured=true;}});assert.deepEqual(await adapter.run({}),response);assert(captured);assert.equal(adapter.inspectObservations()[0].transcriptCaptured,true);assert(!Object.hasOwn(adapter.commandPlan,'captureTranscript'));}finally{await rm(directory,{recursive:true,force:true});}
});
test('capture failure rejects results and malformed originals still reach caller capture',async()=>{
  const base=fileURLToPath(new URL('../.private/',import.meta.url));await mkdir(base,{recursive:true});const directory=await mkdtemp(join(base,'native-capture-failure-'));
  try{const executable=join(directory,'synthetic-vendor');await writeFile(executable,`#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(codex())});\n`,{mode:0o700});await writeFile(join(directory,'auth.json'),JSON.stringify({auth_mode:'chatgpt',tokens:{synthetic:true}}));const common={executable,cwd:directory,model:'synthetic',auth:{home:directory,codexHome:directory}};const broken=createCodexExecAdapter({...common,captureTranscript(){throw new Error('SYNTHETIC_PRIVATE_LOG');}});await assert.rejects(broken.run({}),codeError('CAPTURE_FAILED'));assert.equal(broken.inspectObservations()[0].accepted,false);assert.equal(broken.inspectObservations()[0].transcriptCaptured,false);const hanging=createCodexExecAdapter({...common,timeoutMs:1000,captureTranscript(){return new Promise(()=>{});}});await assert.rejects(hanging.run({}),codeError('CAPTURE_FAILED'));await writeFile(executable,`#!${process.execPath}\nprocess.stdout.write('malformed-original');\n`);let retained='';const malformed=createCodexExecAdapter({...common,captureTranscript(bytes){retained=Buffer.from(bytes).toString('utf8');}});await assert.rejects(malformed.run({}),codeError('NATIVE_MALFORMED_JSON'));assert.equal(retained,'malformed-original');assert.equal(malformed.inspectObservations()[0].transcriptCaptured,true);}finally{await rm(directory,{recursive:true,force:true});}
});
test('vendor transport bounds disposable children and preserves nonzero transcript completion',async()=>{
  const plan=(code,patch={})=>({command:process.execPath,args:['--input-type=module','-e',code],cwd:process.cwd(),environment:{PATH:process.env.PATH??'',LANG:'C'},timeoutMs:1000,maxOutputBytes:262144,...patch});
  const transport=await executeNativeTransport(plan(`process.stdout.write(${JSON.stringify(codex([final()],{type:'turn.failed'}))});process.stderr.write('SYNTHETIC_PRIVATE_LOG');process.exit(1);`),'');assert.equal(transport.exitCode,1);assert.equal(parseCodexEvents(transport.stdout).runtimeStatus,'failed');assert.equal(transport.stderrDigest,hashBytes('SYNTHETIC_PRIVATE_LOG'));
  await assert.rejects(executeNativeTransport(plan('setInterval(()=>{},1000)',{timeoutMs:20}),''),codeError('TIMEOUT'));
  await assert.rejects(executeNativeTransport(plan("process.stdout.write('x'.repeat(20000));",{maxOutputBytes:64}),''),codeError('OUTPUT_LIMIT'));
  await assert.rejects(executeNativeTransport(plan("process.stderr.write('SYNTHETIC_PRIVATE_LOG'.repeat(1000));",{maxOutputBytes:64}),''),codeError('OUTPUT_LIMIT'));
  for(const patch of [{timeoutMs:NaN},{timeoutMs:30001},{maxOutputBytes:0},{environment:{OPENAI_API_KEY:'SYNTHETIC_PRIVATE_LOG'}}])assert.throws(()=>executeNativeTransport(plan('',patch),''),codeError('NATIVE_INVALID_OPTIONS'));
});
test('independent native transcript oracle detects weakened failure and tool gates',async()=>{
  let source=await readFile(new URL('../src/conformance/infrastructure/native-parsers.mjs',import.meta.url),'utf8');
  source=source.replaceAll("'../../shared/canonical.mjs'",JSON.stringify(new URL('../src/shared/canonical.mjs',import.meta.url).href)).replaceAll("'../domain/protocol.mjs'",JSON.stringify(new URL('../src/conformance/domain/protocol.mjs',import.meta.url).href));
  const oracle=parser=>{assert.equal(parser(codex([{type:'error',message:'runtime failed'},final()])).accepted,false);assert.equal(parser(codex([{type:'item.completed',item:{id:'unsafe',type:'command_execution',status:'failed'}},final()])).accepted,false);};oracle(parseCodexEvents);
  for(const mutantSource of [source.replace("const failed = terminal === 'turn.failed' || sawError;",'const failed = false;'),source.replace("const accepted = status === 'completed' && violations.length === 0;","const accepted = status === 'completed';")]){assert.notEqual(mutantSource,source);const mutant=await import(`data:text/javascript;base64,${Buffer.from(mutantSource).toString('base64')}`);assert.throws(()=>oracle(mutant.parseCodexEvents),assert.AssertionError);}
});
