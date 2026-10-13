import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { canonical,digest,verifyEvidence } from '../src/index.mjs';

test('portable canonical and domain-separated Ed25519 vectors reproduce exact bytes',async()=>{
  const v=JSON.parse(await readFile(new URL('../evidence/golden-vectors.json',import.meta.url),'utf8'));
  for(const c of v.cases){assert.equal(canonical(c.input),c.canonical);assert.equal(digest(c.input),c.sha256);}
  assert.equal(v.signature.envelope.payload.source,'fixture');assert.match(v.signature.warning,/never.*production/i);assert.equal(verifyEvidence(v.signature.envelope).envelopeDigest,v.signature.envelopeDigest);assert.equal(v.signature.signingInput,'kya.evidence/v1\n'+canonical(v.signature.envelope.payload));
});
