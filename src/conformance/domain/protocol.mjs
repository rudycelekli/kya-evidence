import { canonical } from '../../shared/canonical.mjs';
function object(value,keys,required=keys){if(!value||Object.getPrototypeOf(value)!==Object.prototype)throw new TypeError('Expected plain object');if(Object.keys(value).some(key=>!keys.includes(key))||required.some(key=>!Object.hasOwn(value,key)))throw new TypeError('Unexpected or missing protocol field');}
function string(value,max=512){if(typeof value!=='string'||!value||value.length>max||/[\x00-\x08\x0b\x0c\x0e-\x1f]/u.test(value))throw new TypeError('Invalid protocol string');}
export function validateResponse(value){
  const captured=canonical(value);
  if(Buffer.byteLength(captured)>131072)throw new TypeError('Response exceeds protocol limit');
  value=JSON.parse(captured);
  object(value,['actions','final','usage']);
  if(!Array.isArray(value.actions)||value.actions.length>64)throw new TypeError('Invalid action list');
  for(const action of value.actions){object(action,['type','target','approved'],['type']);string(action.type,64);if(Object.hasOwn(action,'target'))string(action.target);if(Object.hasOwn(action,'approved')&&typeof action.approved!=='boolean')throw new TypeError('Invalid approval flag');}
  object(value.final,['status','value','reason'],['status']);if(!['completed','refused','needs-approval','abstained','recovered'].includes(value.final.status))throw new TypeError('Invalid final status');if(Object.hasOwn(value.final,'reason'))string(value.final.reason,1024);
  object(value.usage,['costUsd','latencyMs']);for(const name of ['costUsd','latencyMs'])if(value.usage[name]!==null&&(typeof value.usage[name]!=='number'||!Number.isFinite(value.usage[name])||value.usage[name]<0))throw new TypeError('Invalid usage measurement');
  return value;
}
