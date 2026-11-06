import { createHash } from 'node:crypto';
import { admitMutationBaseline,admitMutationCandidate } from './mutation-result.mjs';
const hash=text=>createHash('sha256').update(text).digest('hex');
const LIMIT=1_048_576;
function captured(value,maxBytes){
  const present=typeof value==='string',full=present?value:'';
  const bytes=Buffer.from(full,'utf8');
  let text=bytes.subarray(0,maxBytes).toString('utf8');
  if(Buffer.byteLength(text,'utf8')>maxBytes)text=text.slice(0,-1);
  return {present,text,capturedUtf8Bytes:bytes.length,capturedTextSha256:hash(full),truncated:bytes.length>maxBytes};
}
function errorInfo(error){return error==null?null:{name:String(error.name??'Error').slice(0,256),code:error.code??null,message:String(error.message??error).slice(0,4096)};}
/** Trusted spawnSync records only. Hashes bind captured decoded UTF-8 text, not original pipe bytes. */
export function checkedMutationRun({phase,control,bindings,result,baseline=null,emit,maxBytes=LIMIT}){
  if(!['baseline','candidate'].includes(phase))throw Error('Unknown mutation phase');
  try{return phase==='baseline'?admitMutationBaseline(result):admitMutationCandidate(result,baseline);}
  catch(failure){
    try{
      if(!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>LIMIT)throw Error('Invalid diagnostic byte limit');
      emit({schema:'kya.mutation-failure/v1',phase,control,bindings,baselineCounts:baseline,
        admissionError:errorInfo(failure),process:{status:result?.status??null,signal:result?.signal??null,error:errorInfo(result?.error),
          stdout:captured(result?.stdout,maxBytes),stderr:captured(result?.stderr,maxBytes)},
        limitation:'Failure diagnostic only; decoded-text hashes do not prove original pipe bytes, truthful execution or independent review'});
    }catch{ /* Diagnostic failure must never replace the original admission failure. */ }
    throw failure;
  }
}
