import { readdir, readFile, mkdir, writeFile, lstat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { hashBytes, digest } from '../src/index.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const pkg=JSON.parse(await readFile(join(root,'package.json'),'utf8'));
const allowed=['package.json',...pkg.files];
async function walk(path){const st=await lstat(path);if(st.isSymbolicLink()||!st.isFile()&&!st.isDirectory())throw Error('Refusing nonregular package file');if(st.isFile())return[path];let out=[];for(const name of (await readdir(path)).sort())out.push(...await walk(join(path,name)));return out;}
const paths=[];for(const entry of allowed)paths.push(...await walk(join(root,entry)));
const files=[...new Set(paths)].sort((a,b)=>relative(root,a)<relative(root,b)?-1:relative(root,a)>relative(root,b)?1:0);
function octal(header,offset,length,value){const text=value.toString(8).padStart(length-1,'0')+'\0';if(text.length>length)throw Error('Tar field overflow');header.write(text,offset,length,'ascii');}
function record(path,bytes){
  const header=Buffer.alloc(512),name='package/'+relative(root,path).replaceAll('\\','/');
  if(Buffer.byteLength(name)>100)throw Error('Package path too long for frozen ustar subset: '+name);
  header.write(name,0,100,'utf8');octal(header,100,8,name==='package/bin/kya.mjs'?0o755:0o644);octal(header,108,8,0);octal(header,116,8,0);octal(header,124,12,bytes.length);octal(header,136,12,0);header.fill(32,148,156);header.write('0',156,1);header.write('ustar\0',257,6);header.write('00',263,2);
  const sum=header.reduce((s,n)=>s+n,0);header.write(sum.toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');
  return Buffer.concat([header,bytes,Buffer.alloc((512-bytes.length%512)%512)]);
}
const entries=[],inventory=[];
for(const path of files){const bytes=await readFile(path);const name=relative(root,path).replaceAll('\\','/');
  if(/(?:^|\/)(?:\.env|\.private|\.swarm|\.claude-flow|node_modules)(?:\/|$)|\.pem$/.test(name))throw Error('Private path in package inventory');
  if(/\.(?:mjs|js|json|md|html|css|svg|ts)$/.test(name)&&/(?:\/Users\/rudycelekli|sk-(?:proj-)?[A-Za-z0-9]{24,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/.test(bytes.toString('utf8')))throw Error('Private path/secret marker in package text: '+name);
  entries.push(record(path,bytes));inventory.push({path:name,bytes:bytes.length,sha256:hashBytes(bytes)});
}
const archive=gzipSync(Buffer.concat([...entries,Buffer.alloc(1024)]),{level:9});
const git=spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}),status=spawnSync('git',['status','--porcelain','--untracked-files=no'],{cwd:root,encoding:'utf8'});
if(git.status!==0||status.status!==0||status.stdout.trim())throw Error('Commit tracked changes before creating a release artifact');
const out=join(root,'dist');await mkdir(out,{recursive:true});const name=`${pkg.name}-${pkg.version}.tgz`;
const receipt={schema:'kya.release-receipt/v1',package:pkg.name,version:pkg.version,sourceCommit:git.stdout.trim(),archive:name,archiveSha256:hashBytes(archive),inventoryDigest:digest(inventory),inventory,build:{format:'deterministic ustar+gzip',uid:0,gid:0,mtime:0,node:process.version},status:'prepared-local-unpublished',assurance:'Unsigned reproducible build receipt; no publisher authorization or artifact signature'};
await writeFile(join(out,name),archive);await writeFile(join(out,'release-receipt.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify({archive:join(out,name),sha256:receipt.archiveSha256,files:inventory.length,status:receipt.status}));
