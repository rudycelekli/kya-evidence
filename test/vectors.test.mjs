import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { canonical,digest,verifyEvidence,verifyIncident } from '../src/index.mjs';

// Same classification the vectors record: shape failures precede signature verification.
function jsIncidentOutcome(envelope){try{verifyIncident(structuredClone(envelope));return {outcome:'accept',stage:null};}catch(e){return {outcome:'reject',stage:/signature verification failed/.test(e.message)?'signature':'shape'};}}

test('incident vectors cover every record kind and each rejection class, and JS agrees with every expectation',async()=>{
  const {incidents}=JSON.parse(await readFile(new URL('../evidence/golden-vectors.json',import.meta.url),'utf8'));
  assert.equal(incidents.signingDomain,'kya.incident/v1');assert.match(incidents.warning,/never.*production/i);
  const ids=incidents.vectors.map(v=>v.id);assert.equal(new Set(ids).size,ids.length);
  assert.deepEqual(incidents.vectors.filter(v=>v.expect==='accept').map(v=>v.envelope.payload.kind),['report','resolution','appeal']);
  for(const id of ['wrong-kind','wrong-severity','report-with-ref','resolution-null-ref','extra-field','bad-timestamp-format','tampered-payload','altered-signature','noncanonical-signature-encoding','evidence-domain-signature'])assert.ok(ids.includes(id),id);
  for(const v of incidents.vectors){
    assert.equal(digest(v.envelope),v.envelopeDigest,v.id);
    const r=jsIncidentOutcome(v.envelope);assert.equal(r.outcome,v.expect,v.id);assert.equal(r.stage,v.stage,v.id);
    if(v.expect==='accept'){assert.equal(verifyIncident(v.envelope).envelopeDigest,v.envelopeDigest);assert.equal(v.signingInput,'kya.incident/v1\n'+canonical(v.envelope.payload));}
  }
});

test('portable canonical and domain-separated Ed25519 vectors reproduce exact bytes',async()=>{
  const v=JSON.parse(await readFile(new URL('../evidence/golden-vectors.json',import.meta.url),'utf8'));
  for(const c of v.cases){assert.equal(canonical(c.input),c.canonical);assert.equal(digest(c.input),c.sha256);}
  assert.equal(v.signature.envelope.payload.source,'fixture');assert.match(v.signature.warning,/never.*production/i);assert.equal(verifyEvidence(v.signature.envelope).envelopeDigest,v.signature.envelopeDigest);assert.equal(v.signature.signingInput,'kya.evidence/v1\n'+canonical(v.signature.envelope.payload));
});
