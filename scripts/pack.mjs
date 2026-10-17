import { mkdir, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { hashBytes, digest } from '../src/index.mjs';
import { isForbiddenPath, isTextLike, textMarker } from './lib/package-guard.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
function git(args,binary=false){const p=spawnSync('git',args,{cwd:root,encoding:binary?undefined:'utf8',maxBuffer:20_000_000});if(p.status!==0)throw Error('Git snapshot read failed');return p.stdout;}
const commit=git(['rev-parse','HEAD']).trim();
if(git(['status','--porcelain']).trim())throw Error('Commit all source files before creating a release artifact');
const pkg=JSON.parse(git(['show',commit+':package.json']));
const allowed=['package.json',...pkg.files];
const files=git(['ls-tree','-r','-z',commit,'--',...allowed]).split('\0').filter(Boolean).map(line=>{
  const m=/^(100644|100755) blob ([a-f0-9]{40,64})\t(.+)$/.exec(line);if(!m)throw Error('Refusing nonregular Git tree entry');return{path:join(root,m[3]),blob:m[2]};
}).sort((a,b)=>relative(root,a.path)<relative(root,b.path)?-1:relative(root,a.path)>relative(root,b.path)?1:0);
if(!files.some(f=>relative(root,f.path)==='README.md')||!files.some(f=>relative(root,f.path)==='LICENSE'))throw Error('Required source files missing from frozen Git tree');
function octal(header,offset,length,value){const text=value.toString(8).padStart(length-1,'0')+'\0';if(text.length>length)throw Error('Tar field overflow');header.write(text,offset,length,'ascii');}
function record(path,bytes){
  const header=Buffer.alloc(512),name='package/'+relative(root,path).replaceAll('\\','/');
  if(Buffer.byteLength(name)>100)throw Error('Package path too long for frozen ustar subset: '+name);
  header.write(name,0,100,'utf8');octal(header,100,8,name==='package/bin/kya.mjs'?0o755:0o644);octal(header,108,8,0);octal(header,116,8,0);octal(header,124,12,bytes.length);octal(header,136,12,0);header.fill(32,148,156);header.write('0',156,1);header.write('ustar\0',257,6);header.write('00',263,2);
  const sum=header.reduce((s,n)=>s+n,0);header.write(sum.toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');
  return Buffer.concat([header,bytes,Buffer.alloc((512-bytes.length%512)%512)]);
}
const entries=[],inventory=[];
for(const file of files){const path=file.path,bytes=git(['cat-file','blob',file.blob],true);const name=relative(root,path).replaceAll('\\','/');
  if(isForbiddenPath(name))throw Error('Private path in package inventory');
  if(isTextLike(name)&&textMarker(bytes.toString('utf8')))throw Error('Private path/secret marker in package text: '+name);
  entries.push(record(path,bytes));inventory.push({path:name,bytes:bytes.length,sha256:hashBytes(bytes)});
}
const archive=gzipSync(Buffer.concat([...entries,Buffer.alloc(1024)]),{level:9});
const out=join(root,'dist');await mkdir(out,{recursive:true});const name=`${pkg.name}-${pkg.version}.tgz`;
const receipt={schema:'kya.release-receipt/v1',package:pkg.name,version:pkg.version,sourceCommit:commit,archive:name,archiveSha256:hashBytes(archive),inventoryDigest:digest(inventory),inventory,build:{format:'deterministic ustar+gzip from immutable Git blobs',uid:0,gid:0,mtime:0,node:process.version},status:'prepared-local-unpublished',assurance:'Unsigned reproducible build receipt; no publisher authorization or artifact signature'};
await writeFile(join(out,name),archive);await writeFile(join(out,'release-receipt.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify({archive:join(out,name),sha256:receipt.archiveSha256,files:inventory.length,status:receipt.status}));
