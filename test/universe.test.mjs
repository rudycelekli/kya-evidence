import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir,mkdtemp,cp,readFile,writeFile,rm,symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath,pathToFileURL } from 'node:url';
import { createUniverse,forkUniverse,verifyUniverse,verifyUniverseGraph,compareUniverses,ASSESSOR_SOURCE_DIGEST,digest,canonical,hashBytes,signEvidence } from '../src/index.mjs';
import { inputs,clone,keys,payload } from './helpers.mjs';

const question='Does the frozen synthetic system meet this exact relying policy?';
const artifact={id:'source:synthetic',digest:hashBytes('synthetic source reference'),kind:'original',rights:'private'};
const root=()=>createUniverse({inputs:inputs(),question,sourceArtifacts:[artifact]});
function rehash(universe){const {universeDigest,...body}=universe;return{...body,universeDigest:digest(body)};}

test('same frozen inputs yield byte-identical universes and exact replay',()=>{
  const frozen=inputs();const left=createUniverse({inputs:frozen,question,sourceArtifacts:[artifact]});const right=createUniverse({inputs:clone(frozen),question,sourceArtifacts:clone([artifact])});
  assert.equal(canonical(left),canonical(right));assert.equal(left.universeDigest,right.universeDigest);assert.equal(left.assessorSourceDigest,ASSESSOR_SOURCE_DIGEST);
  assert.deepEqual(verifyUniverse(left),{integrity:true,replayMatched:true,universeDigest:left.universeDigest,assessorSourceDigest:ASSESSOR_SOURCE_DIGEST,authenticated:false});
  frozen.manifest.agent.name='caller mutated';assert.notEqual(left.inputs.manifest.agent.name,frozen.manifest.agent.name);assert.equal(verifyUniverse(left).replayMatched,true);
});

const tamperBindings={
  schema:u=>u.schema='kya.universe/v2',
  assessorSourceDigest:u=>u.assessorSourceDigest='a'.repeat(64),
  parentDigest:u=>u.parentDigest='b'.repeat(64),
  hypothesis:u=>u.hypothesis='forged root hypothesis',
  question:u=>u.question='changed question',
  sourceArtifacts:u=>u.sourceArtifacts[0].digest='c'.repeat(64),
  invalidates:u=>u.invalidates.push('d'.repeat(64)),
  manifest:u=>u.inputs.manifest.system.configDigest='e'.repeat(64),
  profile:u=>u.inputs.profile.checks[0].weight++,
  policy:u=>u.inputs.policy.minScore--,
  evidence:u=>u.inputs.evidence[0].payload.outcome='fail',
  evaluatorDigest:u=>u.inputs.evaluatorDigest='f'.repeat(64),
  frozenTime:u=>u.inputs.now='2026-10-13T12:00:01.000Z',
  assessment:u=>u.assessment.score.earned--,
  limitations:u=>u.limitations[0]='independently certified',
  universeDigest:u=>u.universeDigest='0'.repeat(64)
};
for(const [name,mutate] of Object.entries(tamperBindings))test(`universe digest detects changed ${name}`,()=>{
  const value=clone(root());mutate(value);assert.throws(()=>verifyUniverse(value));
});

test('refreezing the outer digest cannot launder stale or modified assessment results',()=>{
  for(const mutate of [u=>u.assessment.score.earned--,u=>u.inputs.manifest.system.configDigest='e'.repeat(64),u=>u.inputs.evidence[0].payload.outcome='fail',u=>u.inputs.now='2026-10-13T12:00:01.000Z',u=>u.limitations[0]='independent certification']){
    const value=clone(root());mutate(value);assert.throws(()=>verifyUniverse(rehash(value)),/replay differs|Policy|differs/);
  }
});

test('a hash is not an issuer signature: an honestly recomputed metadata revision can replay',()=>{
  const parent=root();const metadataOnly=createUniverse({inputs:parent.inputs,question:'A revised research question',sourceArtifacts:[{...artifact,rights:'redistributable'}]});
  assert.notEqual(parent.universeDigest,metadataOnly.universeDigest);assert.equal(verifyUniverse(metadataOnly).authenticated,false);
  assert.equal(metadataOnly.sourceArtifacts[0].rights,'redistributable'); // caller declaration, not legal verification
});

test('fork requires a hypothesis, preserves parent bytes and avoids shared mutable children',()=>{
  const parent=root(),before=canonical(parent);
  for(const patch of [{},{hypothesis:''},{hypothesis:'valid',unapprovedField:true}])assert.throws(()=>forkUniverse(parent,patch));
  const child=forkUniverse(parent,{hypothesis:'A changed name should invalidate old exact-system receipts.',manifest:{...clone(parent.inputs.manifest),agent:{...parent.inputs.manifest.agent,name:'candidate'}}});
  assert.equal(canonical(parent),before);assert.equal(child.parentDigest,parent.universeDigest);assert.equal(child.hypothesis,'A changed name should invalidate old exact-system receipts.');
  assert.equal(child.assessment.coverage,0);assert.equal(child.assessment.decision,'insufficient-evidence');assert.equal(verifyUniverse(child).replayMatched,true);
  child.inputs.manifest.agent.name='mutated child';assert.equal(canonical(parent),before);assert.throws(()=>verifyUniverse(child),/digest differs/);
});

test('graph verifies branch/correction references and refuses missing or duplicate nodes',()=>{
  const parent=root();const candidate=forkUniverse(parent,{hypothesis:'Revoke one receipt as a supported correction.',policy:{...clone(parent.inputs.policy),revokedEvidenceIds:[parent.inputs.evidence[0].payload.id]},invalidates:[parent.universeDigest]});
  const grandchild=forkUniverse(candidate,{hypothesis:'Retain the correction while assessing one second later.',now:'2026-10-13T12:00:01.000Z'});
  const graph=verifyUniverseGraph([grandchild,parent,candidate]);assert.equal(graph.nodes,3);assert.deepEqual(graph.roots,[parent.universeDigest]);assert.equal(graph.integrity,true);assert.equal(graph.replayMatched,true);assert.equal(graph.authenticated,false);
  assert.deepEqual(graph.declaredInvalidations,[parent.universeDigest]);assert.deepEqual(graph.affectedDescendants,[candidate.universeDigest,grandchild.universeDigest].sort());assert(graph.limitation.includes('distinct from authority'));
  assert.equal(candidate.invalidates[0],parent.universeDigest);assert.equal(candidate.assessment.decision,'insufficient-evidence');
  assert.throws(()=>verifyUniverseGraph([candidate]),/Missing parent/);assert.throws(()=>verifyUniverseGraph([parent,parent]),/Duplicate universe node/);assert.throws(()=>verifyUniverseGraph([]),/Invalid universe graph/);
  const unknownCorrection=createUniverse({inputs:parent.inputs,question,invalidates:['7'.repeat(64)]});assert.throws(()=>verifyUniverseGraph([unknownCorrection]),/Missing invalidated/);
  assert.throws(()=>forkUniverse(parent,{hypothesis:'Duplicate corrections',invalidates:[parent.universeDigest,parent.universeDigest]}),/duplicate/);
});
test('graph output consumes the same captured metadata and membership it replays',()=>{
  const parent=root();const proxy=new Proxy(parent,{get(t,k){return k==='invalidates'?[t.universeDigest]:Reflect.get(t,k);}});
  const nodes=new Proxy([proxy],{get(t,k){return k==='0'?{invalid:true}:Reflect.get(t,k);}});
  const graph=verifyUniverseGraph(nodes);assert.equal(graph.integrity,true);assert.deepEqual(graph.declaredInvalidations,[]);assert.deepEqual(graph.affectedDescendants,[]);
});
test('universe validates captured source rights and correction references before hashing',()=>{
  const bad={...artifact,rights:'invented'};const proxy=new Proxy(bad,{get(t,k){return k==='rights'?'private':Reflect.get(t,k);}});
  assert.throws(()=>createUniverse({inputs:inputs(),question,sourceArtifacts:[proxy]}),/rights/);
  const refs=new Proxy(['not-a-digest'],{get(t,k){return k==='0'?'a'.repeat(64):Reflect.get(t,k);}});
  assert.throws(()=>createUniverse({inputs:inputs(),question,invalidates:refs}),/SHA-256/i);
});

test('complete compatible forks compare without claiming causal improvement',()=>{
  const parent=root();const failing=clone(parent.inputs.evidence);failing[2]=signEvidence({...payload(parent.inputs.manifest,parent.inputs.profile,2),outcome:'fail'},keys.privateKey);
  const child=forkUniverse(parent,{hypothesis:'A failed noncritical check lowers the fixed-denominator result.',evidence:failing});
  const comparison=compareUniverses(parent,child);assert.equal(comparison.parentRelationship,'direct-fork');assert.equal(comparison.causalClaim,false);assert.equal(comparison.scoreDelta,-167);assert.equal(comparison.leftUniverse,parent.universeDigest);assert.equal(comparison.rightUniverse,child.universeDigest);
  assert.equal(compareUniverses(child,parent).parentRelationship,'other');
});

test('incomplete, abstained, errored and policy-incompatible comparisons refuse',()=>{
  const parent=root();
  for(const evidence of [[],parent.inputs.evidence.slice(1),parent.inputs.evidence.map((e,i)=>i?e:signEvidence({...e.payload,outcome:'abstain'},keys.privateKey)),parent.inputs.evidence.map((e,i)=>i?e:signEvidence({...e.payload,outcome:'error'},keys.privateKey))]){
    const child=forkUniverse(parent,{hypothesis:'Incomplete evidence cannot support a comparison.',evidence});assert.throws(()=>compareUniverses(parent,child),/incomplete|different evidenceMode/);
  }
  const changedPolicy=forkUniverse(parent,{hypothesis:'Changing policy is a different decision contract.',policy:{...clone(parent.inputs.policy),minScore:700}});assert.throws(()=>compareUniverses(parent,changedPolicy),/different policyDigest/);
  const changedEvaluator=forkUniverse(parent,{hypothesis:'Different evaluator invalidates frozen receipts.',evaluatorDigest:'4'.repeat(64)});assert.throws(()=>compareUniverses(parent,changedEvaluator));
});

test('source hashes and declared rights do not establish original-byte possession or legal authority',()=>{
  const value=createUniverse({inputs:inputs(),question,sourceArtifacts:[{id:'unavailable:original',digest:hashBytes('bytes deliberately not retained'),kind:'original',rights:'redistributable'}]});
  assert.equal(verifyUniverse(value).authenticated,false);assert(value.limitations.some(text=>text.includes('verify original bytes separately')));assert(value.limitations.some(text=>text.includes('not a legal rights verification')));
  assert.throws(()=>createUniverse({inputs:inputs(),question,sourceArtifacts:[artifact,artifact]}),/Duplicate source artifact/);
  assert.throws(()=>createUniverse({inputs:inputs(),question,sourceArtifacts:[{...artifact,rights:'owned-by-everyone'}]}),/Unknown artifact rights/);
});

test('modified assessor source is rejected, including rehashing source binding around stale results',async()=>{
  const lane=fileURLToPath(new URL('..',import.meta.url));const privateRoot=join(lane,'.private');await mkdir(privateRoot,{recursive:true});const directory=await mkdtemp(join(privateRoot,'universe-mutation-'));
  try{
    await cp(join(lane,'src'),join(directory,'src'),{recursive:true});await cp(join(lane,'package.json'),join(directory,'package.json'));
    const assessor=join(directory,'src','assessment','application','assess.mjs');let source=await readFile(assessor,'utf8');const altered=source.replace('Math.floor(n/d*1000)','Math.max(0,Math.floor(n/d*1000)-1)');assert.notEqual(source,altered,'control must change actual assessor source');await writeFile(assessor,altered);
    const candidate=await import(pathToFileURL(join(directory,'src','research','application','universe.mjs')).href);
    const frozen=root();assert.notEqual(candidate.ASSESSOR_SOURCE_DIGEST,ASSESSOR_SOURCE_DIGEST);assert.throws(()=>candidate.verifyUniverse(frozen),/Assessor source differs/);
    const attacker=rehash({...clone(frozen),assessorSourceDigest:candidate.ASSESSOR_SOURCE_DIGEST});assert.throws(()=>candidate.verifyUniverse(attacker),/Universe replay differs/);
    // A new snapshot honestly created with the candidate assessor is a new universe,
    // not a valid replay of the earlier artifact.
    const newlyFrozen=candidate.createUniverse({inputs:frozen.inputs,question,sourceArtifacts:[artifact]});assert.notEqual(newlyFrozen.universeDigest,frozen.universeDigest);assert.equal(candidate.verifyUniverse(newlyFrozen).replayMatched,true);
  }finally{await rm(directory,{recursive:true,force:true});}
});

test('executable import barrel bytes are part of assessor source binding',async()=>{
  const lane=fileURLToPath(new URL('..',import.meta.url)),privateRoot=join(lane,'.private');await mkdir(privateRoot,{recursive:true});const directory=await mkdtemp(join(privateRoot,'universe-barrel-mutation-'));
  try{
    await cp(join(lane,'src'),join(directory,'src'),{recursive:true});await cp(join(lane,'package.json'),join(directory,'package.json'));
    const barrel=join(directory,'src','evidence','index.mjs');const source=await readFile(barrel,'utf8');await writeFile(barrel,`${source}\nexport const sourceBindingControl = 'mutated-import-boundary';\n`);
    const candidate=await import(pathToFileURL(join(directory,'src','research','application','universe.mjs')).href);
    assert.notEqual(candidate.ASSESSOR_SOURCE_DIGEST,ASSESSOR_SOURCE_DIGEST,'an executable barrel edit must change source digest');
    assert.throws(()=>candidate.verifyUniverse(root()),/Assessor source differs/);
  }finally{await rm(directory,{recursive:true,force:true});}
});

test('package routing edits change assessor binding and source symlinks are refused',async()=>{
  const lane=fileURLToPath(new URL('..',import.meta.url)),privateRoot=join(lane,'.private');await mkdir(privateRoot,{recursive:true});const directory=await mkdtemp(join(privateRoot,'universe-package-mutation-'));
  try{
    await cp(join(lane,'src'),join(directory,'src'),{recursive:true});const packagePath=join(directory,'package.json');const packageSource=JSON.parse(await readFile(join(lane,'package.json'),'utf8'));packageSource.exports['./source-binding-control']='./src/shared/canonical.mjs';await writeFile(packagePath,JSON.stringify(packageSource));
    const candidate=await import(pathToFileURL(join(directory,'src','research','application','universe.mjs')).href);assert.notEqual(candidate.ASSESSOR_SOURCE_DIGEST,ASSESSOR_SOURCE_DIGEST);
    await symlink(join(directory,'src','shared','canonical.mjs'),join(directory,'src','alias.mjs'));
    await assert.rejects(import(`${pathToFileURL(join(directory,'src','research','application','universe.mjs')).href}?symlink-control`),/refuses symlinks/);
  }finally{await rm(directory,{recursive:true,force:true});}
});

test('resource and strict-input validation reject malformed research snapshots',()=>{
  const frozen=inputs();assert.throws(()=>createUniverse({inputs:{...frozen,additional:true},question}),/Frozen universe inputs/);assert.throws(()=>createUniverse({inputs:{...frozen,now:undefined},question}));assert.throws(()=>createUniverse({inputs:frozen,question:'x'.repeat(2049)}));
  const cyclic={};cyclic.self=cyclic;assert.throws(()=>createUniverse({inputs:cyclic,question}),/Cyclic/);assert.throws(()=>createUniverse({inputs:frozen,question,parentDigest:'a'.repeat(64)}),/Fork hypothesis/);
});
