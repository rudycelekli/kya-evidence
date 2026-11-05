import test from 'node:test';
import assert from 'node:assert/strict';
import { createUniverse,verifyUniverse } from '../src/index.mjs';
import { readFileSync } from 'node:fs';
const frozen=JSON.parse(readFileSync(new URL('./fixtures/universe-options-inputs.json',import.meta.url),'utf8'));
const inputs=()=>structuredClone(frozen);
const question='Frozen option capture';
test('ordinary options retain replay and optional defaults',()=>{
 const u=createUniverse({inputs:inputs(),question});assert.equal(verifyUniverse(u).replayMatched,true);assert.equal(u.question,question);
});
test('option getters are rejected without invocation',()=>{
 let calls=0;const options={inputs:inputs(),get question(){calls++;return question;}};
 assert.throws(()=>createUniverse(options));assert.equal(calls,0);
});
test('proxy get view cannot launder an invalid own question',()=>{
 const options=new Proxy({inputs:inputs(),question:42},{get(t,k){return k==='question'?question:Reflect.get(t,k);}});
 assert.throws(()=>createUniverse(options));
});
test('inherited options are not accepted as frozen inputs',()=>{
 const options=Object.create({inputs:inputs(),question});assert.throws(()=>createUniverse(options));
});
