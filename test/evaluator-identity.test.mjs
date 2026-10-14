import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { EVALUATOR_DIGEST } from '../src/conformance/index.mjs';

test('evaluator identity is pinned so unrelated source changes cannot silently invalidate evidence', async () => {
  const pinned = JSON.parse(await readFile(new URL('../evidence/evaluator-identity.json', import.meta.url), 'utf8'));
  assert.equal(pinned.schema, 'kya.evaluator-identity/v1');
  assert.match(pinned.evaluatorDigest, /^[a-f0-9]{64}$/);
  assert.equal(EVALUATOR_DIGEST, pinned.evaluatorDigest, 'Evaluator source changed: update evidence/evaluator-identity.json in the same change as an ADR, or move non-evaluator code out of src/conformance/');
});
