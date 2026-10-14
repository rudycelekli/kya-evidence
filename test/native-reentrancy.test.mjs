import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createCodexExecAdapter } from '../src/conformance/index.mjs';

async function ownedAdapter() {
  const base=fileURLToPath(new URL('../.private/',import.meta.url));await mkdir(base,{recursive:true});
  const home=await mkdtemp(join(base,'native-reentrancy-'));
  return {home,adapter:createCodexExecAdapter({executable:process.execPath,cwd:home,model:'synthetic-no-model',auth:{home,codexHome:home}})};
}

test('caller request capture cannot reenter the native execution slot',async()=>{
  const {home,adapter}=await ownedAdapter();
  try{
    let nested,started=false;
    const request=new Proxy({id:'outer'},{ownKeys(target){if(!started){started=true;nested=adapter.run({id:'nested'});nested.catch(()=>{});}return Reflect.ownKeys(target);}});
    const outer=adapter.run(request);
    const results=await Promise.allSettled([outer,nested]);
    assert.deepEqual(results.map(r=>r.reason?.code),['NATIVE_AUTH_MODE_UNVERIFIED','NATIVE_CONCURRENCY_LIMIT']);
    assert.equal(adapter.inspectObservations().length,1);
  }finally{await rm(home,{recursive:true,force:true});}
});

test('failed caller request capture consumes its attempt and releases the execution slot',async()=>{
  const {home,adapter}=await ownedAdapter();
  try{
    const invalid=new Proxy({},{ownKeys(){throw Error('synthetic capture failure');}});
    for(let i=0;i<511;i++)await assert.rejects(adapter.run(invalid),e=>e.code==='NATIVE_TRANSPORT_ERROR');
    assert.equal(adapter.inspectObservations().length,0);
    await assert.rejects(adapter.run({}),e=>e.code==='NATIVE_AUTH_MODE_UNVERIFIED');
    await assert.rejects(adapter.run({}),e=>e.code==='NATIVE_OBSERVATION_LIMIT');
    assert.equal(adapter.inspectObservations().length,1);
  }finally{await rm(home,{recursive:true,force:true});}
});
