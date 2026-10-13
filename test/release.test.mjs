import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { verifyReleaseReceipt } from '../scripts/lib/ustar.mjs';
import { digest,hashBytes } from '../src/index.mjs';

function checksum(h){h.fill(32,148,156);h.write(h.reduce((s,n)=>s+n,0).toString(8).padStart(6,'0')+'\0 ',148,8);}
function fixture({name='package/bin/kya.mjs',body=Buffer.from('fixture'),change=()=>{},copies=1,tail=Buffer.alloc(1024)}={}){
  const h=Buffer.alloc(512);h.write(name,0);const oct=(p,n,v)=>h.write(v.toString(8).padStart(n-1,'0')+'\0',p,n);oct(100,8,name==='package/bin/kya.mjs'?0o755:0o644);oct(108,8,0);oct(116,8,0);oct(124,12,body.length);oct(136,12,0);h[156]=48;h.write('ustar\0'+'00',257);change(h);checksum(h);
  const record=Buffer.concat([h,body,Buffer.alloc((512-body.length%512)%512)]),tar=Buffer.concat([...Array.from({length:copies},()=>record),tail]),archive=gzipSync(tar);
  const inventory=Array.from({length:copies},()=>({path:name.slice(8),bytes:body.length,sha256:hashBytes(body)}));
  const receipt={schema:'kya.release-receipt/v1',package:'kya-evidence',version:'test',sourceCommit:'a'.repeat(40),archive:'fixture.tgz',archiveSha256:hashBytes(archive),inventoryDigest:digest(inventory),inventory,build:{format:'deterministic ustar+gzip'},status:'prepared-local-unpublished',assurance:'unsigned'};
  return {receipt,archive,tar};
}
test('frozen regular-file archive subset verifies with explicit unsigned source limits',()=>{
  const {receipt,archive}=fixture(),r=verifyReleaseReceipt(receipt,archive);assert.equal(r.files,1);assert.equal(r.archiveIntegrity,'verified');assert.equal(r.authenticatedPublisher,false);assert.equal(r.sourceCommitVerified,false);
});
test('verified receipt output uses captured metadata rather than unverified Proxy GET values',()=>{
  const {receipt,archive}=fixture();const proxy=new Proxy(receipt,{get(t,k){return k==='sourceCommit'?'substituted':Reflect.get(t,k);}});
  assert.equal(verifyReleaseReceipt(proxy,archive).sourceCommit,receipt.sourceCommit);
});
for(const [name,change]of [
  ['symlink',h=>{h[156]=50;h.write('/etc/shadow',157);}],['hardlink',h=>h[156]=49],['directory',h=>h[156]=53],['pax override',h=>h[156]=120],['linkname on regular',h=>h.write('elsewhere',157)],['prefix',h=>h.write('private',345)],['owner name',h=>h.write('person',265)],['uid',h=>h.write('0000001\0',108)],['mtime',h=>h.write('00000000001\0',136)],['executable mode wrong',h=>h.write('0000644\0',100)],['magic',h=>h.write('notar\0',257)],['version',h=>h.write('01',263)],['noncanonical numeric',h=>h.write('    755\0',100)]
])test(`verifier rejects ${name} despite matching unsigned byte inventory`,()=>{const x=fixture({change});assert.throws(()=>verifyReleaseReceipt(x.receipt,x.archive));});
for(const name of ['package/../escape','package/a/../../escape','package//empty','package/.hidden/../escape','/absolute'])test(`verifier rejects unsafe path ${name}`,()=>{const x=fixture({name});assert.throws(()=>verifyReleaseReceipt(x.receipt,x.archive));});
test('verifier rejects duplicate paths, missing terminator and trailing nonzero data',()=>{
  for(const opt of [{copies:2},{tail:Buffer.alloc(512)},{tail:Buffer.concat([Buffer.alloc(1024),Buffer.from('evil'),Buffer.alloc(508)])}]){const x=fixture(opt);assert.throws(()=>verifyReleaseReceipt(x.receipt,x.archive));}
});
test('verifier rejects checksum changes, nonzero padding and truncated body',()=>{
  for(const mutate of [b=>b[10]^=1,b=>b[520]=1,b=>b.write('00000077777\0',124)]){const x=fixture();mutate(x.tar);const archive=gzipSync(x.tar);x.receipt.archiveSha256=hashBytes(archive);assert.throws(()=>verifyReleaseReceipt(x.receipt,archive));}
});
test('receipt digest mismatches, filename traversal and gzip output limits reject',()=>{
  const x=fixture();x.receipt.archiveSha256='0'.repeat(64);assert.throws(()=>verifyReleaseReceipt(x.receipt,x.archive));
  const y=fixture();y.receipt.archive='../fixture.tgz';assert.throws(()=>verifyReleaseReceipt(y.receipt,y.archive));
  const z=fixture(),bomb=gzipSync(Buffer.alloc(20_000_512));z.receipt.archiveSha256=hashBytes(bomb);assert.throws(()=>verifyReleaseReceipt(z.receipt,bomb));
});
