import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { hashBytes,digest } from '../src/index.mjs';

const out=fileURLToPath(new URL('../dist/',import.meta.url));
const r=JSON.parse(await readFile(join(out,'release-receipt.json'),'utf8'));
if(r.schema!=='kya.release-receipt/v1'||digest(r.inventory)!==r.inventoryDigest)throw Error('Invalid release inventory receipt');
const archive=await readFile(join(out,r.archive));if(hashBytes(archive)!==r.archiveSha256)throw Error('Archive digest differs');
const tar=gunzipSync(archive,{maxOutputLength:20_000_000}),actual=[];
for(let pos=0;pos<tar.length;){const h=tar.subarray(pos,pos+512);if(h.every(x=>x===0))break;const name=h.subarray(0,100).toString('utf8').replace(/\0.*$/s,'');const n=parseInt(h.subarray(124,136).toString('ascii').replace(/\0.*$/s,''),8);if(!Number.isSafeInteger(n)||n<0||pos+512+n>tar.length||!name.startsWith('package/'))throw Error('Invalid package tar record');const body=tar.subarray(pos+512,pos+512+n);actual.push({path:name.slice(8),bytes:n,sha256:hashBytes(body)});pos+=512+Math.ceil(n/512)*512;}
if(digest(actual)!==r.inventoryDigest)throw Error('Unpacked file inventory differs');
console.log(JSON.stringify({archiveSha256:r.archiveSha256,sourceCommit:r.sourceCommit,files:actual.length,archiveIntegrity:'verified',authenticatedPublisher:false,publication:'not performed'}));
