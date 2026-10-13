import { lstat, readFile, realpath } from 'node:fs/promises';
import { resolve, relative, sep } from 'node:path';
import { digest, hashBytes, insist } from '../../shared/canonical.mjs';

const ALLOWLIST=['package.json','AGENTS.md','CLAUDE.md','.claude/settings.json','.codex/config.toml','mcp.json'];
export async function inspectConfiguration(directory,{now=new Date().toISOString()}={}) {
  const root=await realpath(resolve(directory));
  insist((await lstat(root)).isDirectory(),'Inspection target must be a directory');
  const files=[],errors=[];
  for(const name of ALLOWLIST) {
    try {
      const path=resolve(root,name),st=await lstat(path);
      insist(st.isFile() && !st.isSymbolicLink(),'Not a regular file');
      insist(st.size<=65_536,'File exceeds inspection limit');
      const actual=await realpath(path),rel=relative(root,actual);
      insist(rel!== '..' && !rel.startsWith('..'+sep),'Inspection path escapes target');
      const bytes=await readFile(path);insist(bytes.length<=65_536,'File grew beyond inspection limit');
      files.push({path:name,bytes:bytes.length,digest:hashBytes(bytes)});
    } catch(e) { if(e.code!=='ENOENT')errors.push({path:name,reason:'Unreadable or excluded by regular-file/size/boundary rule'}); }
  }
  const manifest={schema:'kya.manifest/v1',agent:{id:'agent:local-inventory',name:'Unmeasured local configuration inventory',version:'unverified'},principal:{id:'controller:unverified'},system:{harness:'unverified',harnessVersion:'unverified',model:'unverified',artifactDigest:digest(files),configDigest:digest(files.filter(x=>/settings|config|mcp/.test(x.path))),tools:[]},scope:{id:'local-readonly',purpose:'Partial static configuration inventory; no behavioral assessment',permissions:['read'],forbidden:['publish','spend','external-write'],approvalRequired:[]},issuedAt:now,expiresAt:new Date(Date.parse(now)+86_400_000).toISOString()};
  return {schema:'kya.inventory/v1',manifest,inventory:{status:'partial',files,errors},limitations:['Allowlisted file digests only; not an exact executable or full configuration attestation','No config values, environment variables, auth files or file contents are emitted','No source code or repository scripts were executed','No quality score or identity verification was performed']};
}
