import { gunzipSync } from 'node:zlib';
import { canonical,digest,hashBytes,insist,exactKeys } from '../../src/shared/canonical.mjs';

const zeros=b=>b.every(x=>x===0);
function field(h,start,size){const b=h.subarray(start,start+size),end=b.indexOf(0);insist(end>=0&&zeros(b.subarray(end)),'Tar text field is not NUL padded');return b.subarray(0,end).toString('utf8');}
function octal(h,start,size){const s=h.subarray(start,start+size).toString('ascii');insist(new RegExp(`^[0-7]{${size-1}}\\x00$`).test(s),'Noncanonical tar octal field');const n=parseInt(s,8);insist(Number.isSafeInteger(n),'Tar integer overflow');return n;}
export function verifyReleaseReceipt(receipt,archive,opts={}){
  receipt=JSON.parse(canonical(receipt));
  exactKeys(receipt,['schema','package','version','sourceCommit','archive','archiveSha256','inventoryDigest','inventory','build','status','assurance'],'Release receipt');
  insist(receipt.schema==='kya.release-receipt/v1','Unsupported release receipt');
  insist(typeof receipt.archive==='string'&&/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tgz$/.test(receipt.archive),'Unsafe archive filename');
  insist(Array.isArray(receipt.inventory)&&receipt.inventory.length>0&&receipt.inventory.length<=1000,'Invalid release inventory');
  for(const f of receipt.inventory){exactKeys(f,['path','bytes','sha256'],'Inventory entry');insist(typeof f.path==='string'&&f.path.length<=92&&f.path.split('/').every(s=>s!=='.'&&s!=='..'&&/^[A-Za-z0-9._-]+$/.test(s)),'Unsafe inventory path');insist(Number.isSafeInteger(f.bytes)&&f.bytes>=0&&/^[a-f0-9]{64}$/.test(f.sha256),'Invalid inventory entry');}
  insist(archive instanceof Uint8Array&&archive.length<=20_000_000,'Archive resource limit');
  insist(digest(receipt.inventory)===receipt.inventoryDigest&&hashBytes(archive)===receipt.archiveSha256,'Release digest differs');
  const tar=gunzipSync(archive,{maxOutputLength:20_000_000});
  insist(tar.length%512===0,'Truncated tar blocks');
  const actual=[],names=new Set();let pos=0,terminated=false,pkgBytes=null;
  while(pos<tar.length){
    const h=tar.subarray(pos,pos+512);
    if(zeros(h)){insist(pos+1024<=tar.length&&zeros(tar.subarray(pos)),'Invalid tar terminator/trailing bytes');terminated=true;break;}
    const name=field(h,0,100);
    insist(name.startsWith('package/')&&name.slice(8).length>0&&name.slice(8).split('/').every(s=>s!=='.'&&s!=='..'&&/^[A-Za-z0-9._-]+$/.test(s))&&!names.has(name),'Unsafe or duplicate tar path');names.add(name);
    insist(h[156]===48&&zeros(h.subarray(157,257))&&h.subarray(257,265).equals(Buffer.from('ustar\0'+'00'))&&zeros(h.subarray(265)),'Unsupported tar type, link, prefix or metadata');
    const check=h.subarray(148,156).toString('ascii');insist(/^[0-7]{6}\x00 $/.test(check),'Invalid tar checksum field');
    const expected=parseInt(check,8),sum=h.reduce((s,n,i)=>s+(i>=148&&i<156?32:n),0);insist(expected===sum,'Tar header checksum differs');
    insist(octal(h,100,8)===(name==='package/bin/kya.mjs'?0o755:0o644)&&octal(h,108,8)===0&&octal(h,116,8)===0&&octal(h,136,12)===0,'Tar mode/owner/time differs from frozen subset');
    const n=octal(h,124,12),end=pos+512+n,next=pos+512+Math.ceil(n/512)*512;
    insist(end<=tar.length&&next<=tar.length&&zeros(tar.subarray(end,next)),'Truncated tar body or nonzero padding');
    if(name==='package/package.json')pkgBytes=Buffer.from(tar.subarray(pos+512,end));
    actual.push({path:name.slice(8),bytes:n,sha256:hashBytes(tar.subarray(pos+512,end))});pos=next;
  }
  insist(terminated&&digest(actual)===receipt.inventoryDigest,'Unpacked inventory differs or missing tar terminator');
  if(opts.expectCommit!==undefined){
    insist(typeof opts.expectCommit==='string'&&/^[a-f0-9]{40}$/.test(opts.expectCommit),'Expected commit must be a 40 character lowercase hex SHA');
    insist(receipt.sourceCommit===opts.expectCommit,'Receipt source commit differs from the expected commit');
  }
  if(opts.bindPackage===true){
    insist(pkgBytes!==null,'Archive has no package.json to bind the receipt to');
    let meta;try{meta=JSON.parse(pkgBytes.toString('utf8'));}catch{insist(false,'Archive package.json is not valid JSON');}
    insist(meta!==null&&typeof meta==='object'&&meta.name===receipt.package&&meta.version===receipt.version,'Receipt package or version differs from the archive package.json');
  }
  return {expectedCommitMatched:opts.expectCommit!==undefined,archiveSha256:receipt.archiveSha256,sourceCommit:receipt.sourceCommit,sourceCommitVerified:false,files:actual.length,archiveIntegrity:'verified',authenticatedPublisher:false,publication:'not performed'};
}
