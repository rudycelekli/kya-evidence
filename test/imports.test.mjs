import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,writeFile,mkdir,symlink,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { importDeclarations,digest } from '../src/index.mjs';
import { inspectConfiguration } from '../src/identity/infrastructure/inspect.mjs';

const openKya=()=>({'@context':['https://w3id.org/kya/v1'],id:'urn:demo',type:['VerifiablePresentation','KyaManifest'],kyaVersion:'0.1.0-alpha',agentId:'did:example:agent',verificationMethod:[],authentication:[],assertionMethod:[],capabilityInvocation:[],proof:{unverified:true},name:'Declared fixture',permissionMode:'strict',maxTransactionValue:100,currency:'EUR',deployment:{tee:'unverified'},unknownSecret:'never emit this'});
test('Open-KYA actual alpha fields import as lossy unverified declarations',()=>{
  const source=openKya(),r=importDeclarations('open-kya-alpha',source);assert.equal(r.sourceDigest,digest(source));assert.equal(r.identity.externalAgentId,'did:example:agent');assert.equal(r.declared.maxTransactionValue,100);assert.equal(r.declared.currency,'EUR');assert.ok(r.unverified.includes('hardware attestation'));assert.ok(r.unsupportedFields.includes('deployment'));assert.equal(JSON.stringify(r).includes('never emit this'),false);assert.equal(Object.hasOwn(r,'score'),false);
});
test('Open-KYA import never guesses snake_case fields or validates upstream proofs',()=>{
  const source=openKya();delete source.agentId;source.agent_id='did:wrong';assert.throws(()=>importDeclarations('open-kya-alpha',source),/Missing/);
});
test('Open-KYA rejects unrecognized context/types and primitive documents',()=>{
  const source=openKya();source['@context']=['https://fake'];assert.throws(()=>importDeclarations('open-kya-alpha',source));assert.throws(()=>importDeclarations('a2a-1',[]));assert.throws(()=>importDeclarations('anything',{}));
});
test('A2A mapping retains skill and scheme names without disclosing credentials/endpoints',()=>{
  const r=importDeclarations('a2a-1',{name:'Card',version:'1.0',skills:[{id:'research'}],capabilities:{extendedAgentCard:true},securitySchemes:{oauth:{token:'do-not-emit'}},url:'https://secret.invalid?token=x'});assert.deepEqual(r.declared.skillIds,['research']);assert.deepEqual(r.declared.securitySchemeNames,['oauth']);assert.equal(JSON.stringify(r).includes('do-not-emit'),false);assert.equal(JSON.stringify(r).includes('secret.invalid'),false);
});
test('local inventory is non-executing partial digest-only and refuses symlink escape',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'kya-inspect-')),outside=await mkdtemp(join(tmpdir(),'kya-outside-'));
  try{await writeFile(join(dir,'package.json'),'{"scripts":{"postinstall":"do-not-run"},"token":"secret-sentinel"}');await mkdir(join(dir,'.claude'));await writeFile(join(outside,'secret'),'secret-sentinel');await symlink(join(outside,'secret'),join(dir,'.claude','settings.json'));const r=await inspectConfiguration(dir);assert.equal(r.inventory.status,'partial');assert.equal(r.inventory.files.length,1);assert.equal(r.inventory.errors.length,1);assert.equal(JSON.stringify(r).includes('secret-sentinel'),false);assert.equal(JSON.stringify(r).includes('do-not-run'),false);assert.equal(r.manifest.system.harness,'unverified');}
  finally{await rm(dir,{recursive:true,force:true});await rm(outside,{recursive:true,force:true});}
});
