import test from 'node:test';
import assert from 'node:assert/strict';
import { canonical } from '../src/shared/canonical.mjs';
const expected='["kept","must-not-disappear"]';
const values=()=>['kept','must-not-disappear'];
function shrinking(target){let reads=0;const value=new Proxy(target,{get(t,k,r){return k==='length'?(++reads<=2?2:1):Reflect.get(t,k,r);}});return {value,reads:()=>reads};}
test('ordinary dense array preserves both data items',()=>{assert.equal(canonical(values()),expected);});
test('changing GET length cannot remove descriptor-backed membership',()=>{const p=shrinking(values());assert.equal(canonical(p.value),expected);assert.equal(p.reads(),0);});
test('canonical array capture does not invoke GET length',()=>{let reads=0;const p=new Proxy(values(),{get(t,k,r){if(k==='length'){reads++;throw Error('GET length executed');}return Reflect.get(t,k,r);}});assert.equal(canonical(p),expected);assert.equal(reads,0);});
test('changing GET length cannot conceal an own accessor',()=>{let calls=0;const a=values();Object.defineProperty(a,'1',{enumerable:true,configurable:true,get(){calls++;return 'hidden';}});const p=shrinking(a);assert.throws(()=>canonical(p.value),/accessors/);assert.equal(calls,0);assert.equal(p.reads(),0);});
