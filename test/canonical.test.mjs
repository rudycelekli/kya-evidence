import test from 'node:test';
import assert from 'node:assert/strict';
import { canonical, digest, parseJson, hashBytes } from '../src/index.mjs';

test('canonical ordering and hash are deterministic across member insertion order',()=>{
  assert.equal(canonical({b:[true,null],a:1}),'{"a":1,"b":[true,null]}');
  assert.equal(digest({b:2,a:1}),digest({a:1,b:2}));
  assert.notEqual(digest('x'),hashBytes('x'));
});
for (const [name,value] of [['undefined',undefined],['infinity',Infinity],['NaN',NaN],['bigint',1n],['function',()=>0],['symbol',Symbol('x')],['date',new Date()],['unsafe integer',Number.MAX_SAFE_INTEGER+1],['sparse array',Array(2)]]) {
  test(`canonical rejects ${name}`,()=>assert.throws(()=>canonical(value)));
}
test('canonical rejects accessors without invoking them',()=>{
  let calls=0; const value={}; Object.defineProperty(value,'a',{enumerable:true,get(){calls++;return 1;}});
  assert.throws(()=>canonical(value),/accessors/); assert.equal(calls,0);
});
test('canonical rejects array accessors, extra members, symbols and nonenumerable data',()=>{
  const arr=[1]; Object.defineProperty(arr,'0',{get(){throw Error('getter ran');}}); assert.throws(()=>canonical(arr),/accessors/);
  const other=[1];other.extra=2;assert.throws(()=>canonical(other));
  const symbol={a:1};symbol[Symbol()]=2;assert.throws(()=>canonical(symbol));
  const hidden={};Object.defineProperty(hidden,'x',{value:1});assert.throws(()=>canonical(hidden));
});
test('cycles/depth/size cannot consume unbounded parser resources',()=>{
  const cyclic={};cyclic.a=cyclic;assert.throws(()=>canonical(cyclic),/Cyclic/);
  let deep=1;for(let i=0;i<34;i++)deep=[deep];assert.throws(()=>canonical(deep),/resource/);
  assert.throws(()=>parseJson('"'+'x'.repeat(1_048_576)+'"'),/byte limit/);
});
for (const [name,text] of [
  ['duplicate','{"a":1,"a":2}'],['escaped duplicate','{"a":1,"\\u0061":2}'],['nested duplicate','{"x":{"a":1,"a":2}}'],['prototype','{"__proto__":{"x":1}}'],['constructor','{"constructor":1}'],['trailing comma','[1,]'],['missing comma','[1 2]'],['trailing token','true false'],['leading zero','01'],['invalid string','"x\nx"'],['overflow','1e999'],['unsafe numeric','9007199254740993'],['not JSON whitespace','\ufeff{}'],['unclosed array','[1'],['bad escape','"\\z"'],['no value','']
]) test(`strict JSON parser rejects ${name}`,()=>assert.throws(()=>parseJson(text)));
test('strict parser preserves strings, escapes, numeric values and JSON whitespace',()=>{
  const value={text:'a"\\\n',unicode:'🧭',nums:[1,-2,0.25,1e-10],yes:true,no:false,nil:null};
  assert.deepEqual(parseJson(' \n'+JSON.stringify(value)+'\t'),value);
  assert.equal(canonical(-0),'0');
});
test('canonical subset has stable golden vectors',()=>{
  assert.equal(hashBytes('abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(digest({a:1}),'015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862');
});
