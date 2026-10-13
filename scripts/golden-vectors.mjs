import { createPrivateKey } from 'node:crypto';
import { readFile,writeFile,mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { canonical,digest,hashBytes,signEvidence } from '../src/index.mjs';

const cases=[null,{b:2,a:1},{array:[false,true,null,0,-0,0.25,1e-10]},{unicode:'🧭 café',escaped:'quote" slash\\ newline\n'},{nested:{z:{b:2,a:1},a:[3,2,1]}},{'é':'composed','e\u0301':'decomposed'}].map(input=>({input,canonical:canonical(input),sha256:digest(input)}));
// Public synthetic seed; never use this key or trust anchor in a real assessment.
const seedHex='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const key=createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+seedHex,'hex'),format:'der',type:'pkcs8'});
const payload={schema:'kya.evidence/v1',id:'public-vector:identity',subjectDigest:hashBytes('synthetic-subject'),scopeId:'public-vector',profileDigest:hashBytes('synthetic-profile'),evaluatorDigest:hashBytes('synthetic-evaluator'),runId:'public-vector-run',checkId:'identity.binding',outcome:'pass',observedAt:'2026-10-13T12:00:00.000Z',expiresAt:'2026-10-14T12:00:00.000Z',artifactDigest:hashBytes('synthetic trace'),source:'fixture'};
const envelope=signEvidence(payload,key);
const value={schema:'kya.golden-vectors/v1',canonicalSubset:'Strict sorted-key JSON subset; not RFC 8785 conformance',cases,signature:{warning:'Public toy key and fixture receipt; never a production trust anchor',publicSyntheticSeedHex:seedHex,signingInput:'kya.evidence/v1\n'+canonical(payload),envelope,envelopeDigest:digest(envelope)}};
const out=fileURLToPath(new URL('../evidence/golden-vectors.json',import.meta.url));await mkdir(fileURLToPath(new URL('../evidence/',import.meta.url)),{recursive:true});
if(process.argv.includes('--check')){if(canonical(JSON.parse(await readFile(out,'utf8')))!==canonical(value))throw Error('Golden vector drift');console.log('Golden vectors match');}
else{await writeFile(out,JSON.stringify(value,null,2)+'\n');console.log('Canonical and Ed25519 golden vectors generated');}
