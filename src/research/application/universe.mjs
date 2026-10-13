import { readFileSync,readdirSync } from 'node:fs';
import { assess,compareAssessments } from '../../assessment/index.mjs';
import { canonical,digest,hashBytes,exactKeys,insist,captureArrayItems } from '../../shared/canonical.mjs';
import { identifier,hash,text,timestamp,list } from '../../identity/domain/services/validation.mjs';

// Hash actual implementation bytes, not just a mutable version string.
const sourceRoot=new URL('../../',import.meta.url);
function sourceInventory(base,prefix=''){
  const records=[];
  for(const item of readdirSync(base,{withFileTypes:true}).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){
    insist(!item.isSymbolicLink(),'Source inventory refuses symlinks');
    const path=prefix+item.name,url=new URL(item.name+(item.isDirectory()?'/':''),base);
    if(item.isDirectory())records.push(...sourceInventory(url,path+'/'));
    else if(item.isFile()&&/\.m?js$/.test(item.name))records.push({path:'src/'+path,sha256:hashBytes(readFileSync(url))});
  }
  return records;
}
export const ASSESSOR_SOURCE_DIGEST=digest([...sourceInventory(sourceRoot),{path:'package.json',sha256:hashBytes(readFileSync(new URL('../../../package.json',import.meta.url)))}]);
const snapshot=v=>JSON.parse(canonical(v));
function validateArtifacts(items){
  insist(Array.isArray(items)&&items.length<=128,'Invalid source artifact list');const ids=new Set();
  for(const a of items){exactKeys(a,['id','digest','kind','rights'],'Source artifact');identifier(a.id,'Source artifact ID');hash(a.digest,'Source artifact digest');insist(['original','derived','hypothesis'].includes(a.kind),'Unknown source kind');insist(['private','redistributable'].includes(a.rights),'Unknown artifact rights');insist(!ids.has(a.id),'Duplicate source artifact');ids.add(a.id);}
}
export function createUniverse({inputs,question,sourceArtifacts=[],parentDigest=null,hypothesis=null,invalidates=[]}){
  sourceArtifacts=snapshot(sourceArtifacts);invalidates=snapshot(invalidates);
  const frozen=snapshot(inputs);exactKeys(frozen,['manifest','profile','policy','evidence','evaluatorDigest','now'],'Frozen universe inputs');timestamp(frozen.now,'Frozen assessment time');text(question,'Research question',2048);validateArtifacts(sourceArtifacts);
  if(parentDigest!==null){hash(parentDigest,'Parent universe');text(hypothesis,'Fork hypothesis',2048);}else insist(hypothesis===null,'A root universe has no fork hypothesis');
  list(invalidates,'Invalidated universe references',128,hash);
  const report=assess(frozen);
  const body={schema:'kya.universe/v1',assessorSourceDigest:ASSESSOR_SOURCE_DIGEST,parentDigest,hypothesis,question,sourceArtifacts:snapshot(sourceArtifacts),invalidates:[...invalidates].sort(),inputs:frozen,assessment:report,limitations:['A local immutable research snapshot; no external timestamp, signer or execution attestation','Source hashes are references; verify original bytes separately','Declared redistribution rights are not a legal rights verification','Forks preserve history but cannot prove a causal improvement']};
  return {...body,universeDigest:digest(body)};
}
export function verifyUniverse(value){
  const universe=snapshot(value);exactKeys(universe,['schema','assessorSourceDigest','parentDigest','hypothesis','question','sourceArtifacts','invalidates','inputs','assessment','limitations','universeDigest'],'Universe');
  insist(universe.schema==='kya.universe/v1','Unsupported universe schema');hash(universe.universeDigest,'Universe digest');
  const {universeDigest,...body}=universe;insist(digest(body)===universeDigest,'Universe digest differs');
  insist(universe.assessorSourceDigest===ASSESSOR_SOURCE_DIGEST,'Assessor source differs; replay with the archived implementation');
  const replay=createUniverse({inputs:universe.inputs,question:universe.question,sourceArtifacts:universe.sourceArtifacts,parentDigest:universe.parentDigest,hypothesis:universe.hypothesis,invalidates:universe.invalidates});
  insist(digest(replay.assessment)===digest(universe.assessment)&&replay.universeDigest===universeDigest,'Universe replay differs');
  return {integrity:true,replayMatched:true,universeDigest,assessorSourceDigest:ASSESSOR_SOURCE_DIGEST,authenticated:false};
}
export function forkUniverse(parent,patch){
  const frozenParent=snapshot(parent);verifyUniverse(frozenParent);const p=snapshot(patch);
  const allowed=['hypothesis','question','sourceArtifacts','invalidates','manifest','profile','policy','evidence','evaluatorDigest','now'];
  insist(p&&typeof p==='object'&&!Array.isArray(p)&&Object.keys(p).every(k=>allowed.includes(k)),'Unknown fork patch field');text(p.hypothesis,'Fork hypothesis',2048);
  const inputs=snapshot(frozenParent.inputs);for(const k of ['manifest','profile','policy','evidence','evaluatorDigest','now'])if(Object.hasOwn(p,k))inputs[k]=p[k];
  return createUniverse({inputs,question:p.question??frozenParent.question,sourceArtifacts:p.sourceArtifacts??frozenParent.sourceArtifacts,parentDigest:frozenParent.universeDigest,hypothesis:p.hypothesis,invalidates:p.invalidates??[]});
}
export function verifyUniverseGraph(universes){
  universes=captureArrayItems(universes,256,'Invalid universe graph').map(snapshot);
  insist(universes.length>0,'Invalid universe graph');const nodes=new Map();
  for(const u of universes){verifyUniverse(u);insist(!nodes.has(u.universeDigest),'Duplicate universe node');nodes.set(u.universeDigest,u);}
  for(const u of universes){if(u.parentDigest!==null)insist(nodes.has(u.parentDigest),'Missing parent universe');for(const id of u.invalidates)insist(nodes.has(id),'Missing invalidated universe');}
  const visited=new Set(),active=new Set();function visit(u){insist(!active.has(u.universeDigest),'Universe graph cycle');if(visited.has(u.universeDigest))return;active.add(u.universeDigest);if(u.parentDigest)visit(nodes.get(u.parentDigest));active.delete(u.universeDigest);visited.add(u.universeDigest);}for(const u of universes)visit(u);
  const invalidated=new Set(universes.flatMap(u=>u.invalidates)),affected=new Set(invalidated);
  let changed=true;while(changed){changed=false;for(const u of universes)if(u.parentDigest&&affected.has(u.parentDigest)&&!affected.has(u.universeDigest)){affected.add(u.universeDigest);changed=true;}}
  return {nodes:nodes.size,roots:universes.filter(u=>u.parentDigest===null).map(u=>u.universeDigest).sort(),declaredInvalidations:[...invalidated].sort(),affectedDescendants:[...affected].filter(id=>!invalidated.has(id)).sort(),integrity:true,replayMatched:true,authenticated:false,limitation:'Correction references are declarations; replay integrity is distinct from authority to revoke an assessment'};
}
export function compareUniverses(left,right){const l=snapshot(left),r=snapshot(right);verifyUniverse(l);verifyUniverse(r);return {...compareAssessments(l.assessment,r.assessment),leftUniverse:l.universeDigest,rightUniverse:r.universeDigest,parentRelationship:r.parentDigest===l.universeDigest?'direct-fork':'other',causalClaim:false};}
