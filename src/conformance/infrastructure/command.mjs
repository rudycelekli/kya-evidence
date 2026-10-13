import { spawn } from 'node:child_process';
import { dirname,isAbsolute } from 'node:path';
import { canonical,parseJson } from '../../shared/canonical.mjs';
import { validateResponse } from '../domain/protocol.mjs';
import { markAdapter } from '../application/origins.mjs';
function failure(code){return Object.assign(new Error(`Command transport failed: ${code}`),{code});}
function integer(value,min,max,name){if(!Number.isSafeInteger(value)||value<min||value>max)throw new TypeError(`Invalid ${name}`);}
function string(value,name){if(typeof value!=='string'||!value||value.length>4096||value.includes('\0'))throw new TypeError(`Invalid ${name}`);}
function validate({command,args,cwd,timeoutMs,maxOutputBytes}){
  string(command,'command');if(!Array.isArray(args)||args.length>128||args.some(v=>typeof v!=='string'||v.length>16384||v.includes('\0')))throw new TypeError('Invalid args');if(cwd!==undefined)string(cwd,'cwd');integer(timeoutMs,1,30000,'timeoutMs');integer(maxOutputBytes,1,1048576,'maxOutputBytes');
}
function safeEnvironment(command,versionProbe){const separator=process.platform==='win32'?';':':';const path=versionProbe&&isAbsolute(command)?`${dirname(command)}${separator}${process.env.PATH??''}`:process.env.PATH??'';const env={PATH:path,LANG:'C',LC_ALL:'C'};if(process.platform==='win32')for(const k of ['SystemRoot','WINDIR','PATHEXT'])if(process.env[k])env[k]=process.env[k];return env;}
/** Bounded shell=false process transport. The caller supplies OS isolation. */
export function executeBounded({command,args=[],cwd,timeoutMs=30000,maxOutputBytes=131072,input='',signal,versionProbe=false}){
  validate({command,args,cwd,timeoutMs,maxOutputBytes});if(typeof input!=='string'||Buffer.byteLength(input)>131072)throw failure('INPUT_LIMIT');if(signal!==undefined&&!(signal instanceof AbortSignal))throw new TypeError('Invalid abort signal');if(signal?.aborted)return Promise.reject(failure('ABORTED'));
  return new Promise((resolve,reject)=>{
    let child,timer,finished=false,count=0,stderrCount=0;const chunks=[];
    const cleanup=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);};
    const settle=(error,result)=>{if(finished)return;finished=true;cleanup();if(error)reject(error);else resolve(result);};
    const kill=code=>{
      // POSIX process-group cleanup reaches descendants but grants no sandbox boundary.
      if(child?.pid){try{if(process.platform!=='win32')process.kill(-child.pid,'SIGKILL');else child.kill('SIGKILL');}catch{try{child.kill('SIGKILL');}catch{}}}
      child?.stdin.destroy();child?.stdout.destroy();child?.stderr.destroy();settle(failure(code));
    };
    const abort=()=>kill('ABORTED');
    try{child=spawn(command,args,{cwd,shell:false,windowsHide:true,detached:process.platform!=='win32',env:safeEnvironment(command,versionProbe),stdio:['pipe','pipe','pipe']});}catch{settle(failure('SPAWN_FAILED'));return;}
    signal?.addEventListener('abort',abort,{once:true});timer=setTimeout(()=>kill('TIMEOUT'),timeoutMs);
    child.once('error',()=>settle(failure('SPAWN_FAILED')));child.stdin.on('error',()=>{});
    child.stdout.on('data',chunk=>{count+=chunk.length;if(count>maxOutputBytes)kill('OUTPUT_LIMIT');else chunks.push(chunk);});
    child.stderr.on('data',chunk=>{stderrCount+=chunk.length;if(stderrCount>maxOutputBytes)kill('OUTPUT_LIMIT');}); // stderr is discarded, never included in errors
    child.once('close',code=>{if(finished)return;if(code!==0){settle(failure('NONZERO_EXIT'));return;}let output;try{output=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));}catch{settle(failure('MALFORMED_JSON'));return;}if(versionProbe){settle(null,output);return;}let parsed;try{parsed=parseJson(output);}catch{settle(failure('MALFORMED_JSON'));return;}try{validateResponse(parsed);}catch{settle(failure('INVALID_RESPONSE'));return;}settle(null,parsed);});
    child.stdin.end(input);
  });
}
export function createCommandAdapter({command,args=[],cwd,timeoutMs=30000,maxOutputBytes=131072}={}){
  validate({command,args,cwd,timeoutMs,maxOutputBytes});const fixedArgs=[...args];
  return markAdapter({id:'command-json',run(request,{signal}={}){return executeBounded({command,args:fixedArgs,cwd,timeoutMs,maxOutputBytes,input:`${canonical(request)}\n`,signal});}},{source:'runtime',id:'command-json',mode:null});
}
