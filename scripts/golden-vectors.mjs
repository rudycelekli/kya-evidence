import { createPrivateKey,createPublicKey,sign } from 'node:crypto';
import { readFile,writeFile,mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { canonical,digest,hashBytes,signEvidence,signIncident,verifyIncident } from '../src/index.mjs';
import { keyId } from '../src/identity/domain/services/validation.mjs';

const cases=[null,{b:2,a:1},{array:[false,true,null,0,-0,0.25,1e-10]},{unicode:'🧭 café',escaped:'quote" slash\\ newline\n'},{nested:{z:{b:2,a:1},a:[3,2,1]}},{'é':'composed','e\u0301':'decomposed'}].map(input=>({input,canonical:canonical(input),sha256:digest(input)}));
// Public synthetic seed; never use this key or trust anchor in a real assessment.
const seedHex='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const key=createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+seedHex,'hex'),format:'der',type:'pkcs8'});
const payload={schema:'kya.evidence/v1',id:'public-vector:identity',subjectDigest:hashBytes('synthetic-subject'),scopeId:'public-vector',profileDigest:hashBytes('synthetic-profile'),evaluatorDigest:hashBytes('synthetic-evaluator'),runId:'public-vector-run',checkId:'identity.binding',outcome:'pass',observedAt:'2026-10-13T12:00:00.000Z',expiresAt:'2026-10-14T12:00:00.000Z',artifactDigest:hashBytes('synthetic trace'),source:'fixture'};
const envelope=signEvidence(payload,key);

// Incident vectors: public synthetic records under the same toy key. Negative vectors are signed raw (bypassing signIncident validation) so shape and signature failures are distinguishable.
const pem=createPublicKey(key).export({format:'pem',type:'spki'}).toString();
const rawSign=(domain,p)=>sign(null,Buffer.from(domain+'\n'+canonical(p)),key).toString('base64url');
const seal=(p,domain='kya.incident/v1')=>({payload:p,proof:{algorithm:'Ed25519',keyId:keyId(pem),publicKey:pem,signature:rawSign(domain,p)}});
const base={schema:'kya.incident/v1',id:'public-vector:incident-1',subjectDigest:hashBytes('synthetic-subject'),kind:'report',severity:'high',refId:null,reportedAt:'2026-10-14T09:00:00.000Z',detailsDigest:hashBytes('synthetic private details')};
const resolution={...base,id:'public-vector:incident-2',kind:'resolution',severity:'low',refId:base.id,reportedAt:'2026-10-14T10:00:00.000Z'};
const appeal={...base,id:'public-vector:incident-3',kind:'appeal',severity:'medium',refId:base.id,reportedAt:'2026-10-14T11:00:00.000Z'};
const good=signIncident(base,key),clone=x=>JSON.parse(JSON.stringify(x));
const withPayload=(p,env=good)=>({payload:p,proof:env.proof});
const flip=(sig,i)=>{const a='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';return sig.slice(0,i)+a[a.indexOf(sig[i])^1]+sig.slice(i+1);};
const vec=(id,expect,stage,description,envelope)=>({id,expect,stage,description,envelope,envelopeDigest:digest(envelope),...(expect==='accept'?{signingInput:'kya.incident/v1\n'+canonical(envelope.payload)}:{})});
const incidentVectors=[
  vec('report','accept',null,'Valid signed report',good),
  vec('resolution','accept',null,'Valid signed resolution referencing the report',signIncident(resolution,key)),
  vec('appeal','accept',null,'Valid signed appeal referencing the report',signIncident(appeal,key)),
  vec('wrong-kind','reject','shape','Unknown kind with a valid signature',seal({...base,kind:'dismissal'})),
  vec('wrong-severity','reject','shape','Unknown severity with a valid signature',seal({...base,severity:'urgent'})),
  vec('wrong-schema','reject','shape','Evidence schema string in an incident envelope',seal({...base,schema:'kya.evidence/v1'})),
  vec('report-with-ref','reject','shape','Report with non-null refId',seal({...base,refId:'public-vector:other'})),
  vec('resolution-null-ref','reject','shape','Resolution with null refId',seal({...resolution,refId:null})),
  vec('resolution-self-ref','reject','shape','Resolution referencing itself',seal({...resolution,refId:resolution.id})),
  vec('extra-field','reject','shape','Additional payload member',seal({...base,note:'extra'})),
  vec('missing-field','reject','shape','Missing detailsDigest',seal(Object.fromEntries(Object.entries(base).filter(([k])=>k!=='detailsDigest')))),
  vec('bad-timestamp-format','reject','shape','Timestamp without milliseconds',seal({...base,reportedAt:'2026-10-14T09:00:00Z'})),
  vec('bad-timestamp-calendar','reject','shape','Nonexistent calendar date',seal({...base,reportedAt:'2026-02-30T09:00:00.000Z'})),
  vec('bad-hash-case','reject','shape','Uppercase subject digest',seal({...base,subjectDigest:base.subjectDigest.toUpperCase()})),
  vec('bad-identifier','reject','shape','Identifier with a leading separator',seal({...base,id:'-bad'})),
  vec('noncanonical-signature-encoding','reject','shape','Same 64 signature bytes with nonzero trailing base64url bits',withPayload(base,{proof:{...good.proof,signature:flip(good.proof.signature,85)}})),
  vec('tampered-payload','reject','signature','Severity changed after signing',withPayload({...base,severity:'low'})),
  vec('altered-signature','reject','signature','First signature character changed',withPayload(base,{proof:{...good.proof,signature:flip(good.proof.signature,0)}})),
  vec('evidence-domain-signature','reject','signature','Signature made over the evidence domain prefix reused as incident',seal(base,'kya.evidence/v1')),
];
for(const v of incidentVectors){let outcome='accept',stage=null;try{verifyIncident(clone(v.envelope));}catch(e){outcome='reject';stage=/signature verification failed/.test(e.message)?'signature':'shape';}
  if(outcome!==v.expect||stage!==v.stage)throw Error('Incident vector '+v.id+' disagrees with JS: '+outcome+'/'+stage);}
const value={schema:'kya.golden-vectors/v1',canonicalSubset:'Strict sorted-key JSON subset; not RFC 8785 conformance',cases,signature:{warning:'Public toy key and fixture receipt; never a production trust anchor',publicSyntheticSeedHex:seedHex,signingInput:'kya.evidence/v1\n'+canonical(payload),envelope,envelopeDigest:digest(envelope)},incidents:{warning:'Public toy key and synthetic incident records; never a production trust anchor',signingDomain:'kya.incident/v1',vectors:incidentVectors}};
const out=fileURLToPath(new URL('../evidence/golden-vectors.json',import.meta.url));await mkdir(fileURLToPath(new URL('../evidence/',import.meta.url)),{recursive:true});
if(process.argv.includes('--check')){if(canonical(JSON.parse(await readFile(out,'utf8')))!==canonical(value))throw Error('Golden vector drift');console.log('Golden vectors match');}
else{await writeFile(out,JSON.stringify(value,null,2)+'\n');console.log('Canonical and Ed25519 golden vectors generated');}
