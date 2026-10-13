import { access,readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { executeBounded } from './command.mjs';
async function executable(name){
  const directories=(process.env.PATH??'').split(process.platform==='win32'?';':':').filter(Boolean);
  // NVM binaries may be installed yet absent from the desktop app's PATH.
  const nvmRoot=join(homedir(),'.nvm','versions','node');
  try{for(const entry of (await readdir(nvmRoot,{withFileTypes:true})).filter(e=>e.isDirectory()&&/^v\d+\.\d+\.\d+$/u.test(e.name)).sort((a,b)=>b.name.localeCompare(a.name)))directories.push(join(nvmRoot,entry.name,'bin'));}catch{}
  const candidates=directories.map(directory=>join(directory,name));
  if(name==='codex'&&process.platform==='darwin')candidates.push('/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex');
  for(const candidate of candidates)try{await access(candidate,constants.X_OK);return candidate;}catch{}
  return null;
}
export async function probeRuntimes(){
  return Promise.all(['claude','codex'].map(async id=>{
    const command=await executable(id);if(!command)return{id,status:'not-installed',version:null,quality:'unmeasured'};
    try{const output=await executeBounded({command,args:['--version'],timeoutMs:2000,maxOutputBytes:4096,versionProbe:true});const version=output.trim().split('\n').map(l=>l.trim()).find(l=>/^[a-zA-Z0-9][a-zA-Z0-9 .+_()\-]{0,159}$/u.test(l)&&/\d+\.\d+/u.test(l));return{id,status:version?'available':'probe-failed',version:version??null,quality:'unmeasured'};}catch{return{id,status:'probe-failed',version:null,quality:'unmeasured'};}
  }));
}
