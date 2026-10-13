import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createCommandAdapter,runConformance,probeRuntimes } from '../src/conformance/index.mjs';
import { executeBounded } from '../src/conformance/infrastructure/command.mjs';
import manifest from '../examples/manifest.json' with {type:'json'};
const valid={actions:[],final:{status:'refused',reason:'secret-boundary'},usage:{costUsd:null,latencyMs:null}};
const child=(code,options={})=>createCommandAdapter({command:process.execPath,args:['--input-type=module','-e',code],timeoutMs:2000,...options});
const errorCode=code=>error=>error.code===code&&!error.message.includes('PRIVATE_STDERR');
test('one JSON request without shell interpolation or inherited secret environment',async()=>{
  const adapter=child(`let input='';for await(const c of process.stdin)input+=c;const req=JSON.parse(input);if(req.marker!=='$(touch nope); & *')process.exit(2);process.stdout.write(JSON.stringify(${JSON.stringify(valid)}));`);assert.deepEqual(await adapter.run({marker:'$(touch nope); & *'}),valid);
  process.env.KYA_TRANSPORT_TEST_SECRET='must-not-leak';try{assert.deepEqual(await child(`if(process.env.KYA_TRANSPORT_TEST_SECRET)process.exit(3);process.stdout.write(JSON.stringify(${JSON.stringify(valid)}));`).run({}),valid);}finally{delete process.env.KYA_TRANSPORT_TEST_SECRET;}
});
test('timeouts, abort and output limits suppress stderr',async()=>{
  await assert.rejects(child('setInterval(()=>{},1000)',{timeoutMs:30}).run({}),errorCode('TIMEOUT'));
  await assert.rejects(child("process.stdout.write('x'.repeat(10000));",{maxOutputBytes:128}).run({}),errorCode('OUTPUT_LIMIT'));
  await assert.rejects(child("process.stderr.write('PRIVATE_STDERR'.repeat(1000));",{maxOutputBytes:128}).run({}),errorCode('OUTPUT_LIMIT'));
  const before=new AbortController();before.abort();await assert.rejects(child('throw new Error("must-not-launch")').run({},{signal:before.signal}),errorCode('ABORTED'));
  const active=new AbortController(),pending=child('setInterval(()=>{},1000)').run({},{signal:active.signal});active.abort();await assert.rejects(pending,errorCode('ABORTED'));
});
test('malformed, duplicate, trailing, spoofed and nonzero output fails precisely',async()=>{
  for(const payload of ['not-json','{"actions":[],"actions":[]}',`${JSON.stringify(valid)}\n${JSON.stringify(valid)}`])await assert.rejects(child(`process.stdout.write(${JSON.stringify(payload)})`).run({}),errorCode('MALFORMED_JSON'));
  await assert.rejects(child("process.stderr.write('PRIVATE_STDERR');process.exit(7)").run({}),errorCode('NONZERO_EXIT'));
  await assert.rejects(child(`process.stdout.write(JSON.stringify({...${JSON.stringify(valid)},source:'fixture'}))`).run({}),errorCode('INVALID_RESPONSE'));
  await assert.rejects(child(`process.stdout.write(Buffer.concat([Buffer.from('{"actions":[],"final":{"status":"completed","value":"'),Buffer.from([255]),Buffer.from('"},"usage":{"costUsd":null,"latencyMs":null}}')]));`).run({}),errorCode('MALFORMED_JSON'));
  await assert.rejects(createCommandAdapter({command:'/definitely/not/a/kya-executable'}).run({}),errorCode('SPAWN_FAILED'));
});
test('transport limits and inputs validate before process launch',()=>{
  for(const options of [{command:'node',timeoutMs:0},{command:'node',timeoutMs:30001},{command:'node',maxOutputBytes:0},{command:'node',args:'-e'},{command:'node\0'}])assert.throws(()=>createCommandAdapter(options));
  assert.throws(()=>executeBounded({command:process.execPath,input:'x'.repeat(131073)}),errorCode('INPUT_LIMIT'));assert.throws(()=>executeBounded({command:process.execPath,signal:{aborted:false}}),/Invalid abort signal/);
});
test('actual child fixture is observed transport, visibly identified as a synthetic manifest',async()=>{
  const adapter=createCommandAdapter({command:process.execPath,args:[fileURLToPath(new URL('../examples/command-fixture.mjs',import.meta.url))]});const run=await runConformance({adapter,manifest,now:'2026-10-13T12:00:00.000Z'});assert(run.evidence.every(e=>e.outcome==='pass'));assert(run.evidence.every(e=>e.source==='runtime'));assert.equal(manifest.system.model,'deterministic-fixture-no-model');
});
test('version probes report availability but never quality scores',async()=>{
  const results=await probeRuntimes();assert.deepEqual(results.map(r=>r.id),['claude','codex']);for(const result of results){assert(['available','not-installed','probe-failed'].includes(result.status));assert.equal(result.quality,'unmeasured');assert(!Object.hasOwn(result,'score'));}
});
