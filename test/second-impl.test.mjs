import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { runVectors } from '../scripts/run-vectors.mjs';

// Team-built second implementation (interop/second-impl). Same team as the reference: NOT independent. See its README.
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const VECTORS = join(ROOT, 'evidence/assessment-vectors.json');
const ADAPTER = join(ROOT, 'interop/second-impl/adapter.mjs');
const PUBLISHED = JSON.parse(readFileSync(VECTORS, 'utf8')).vectors;
const impl = `"${process.execPath}" "${ADAPTER}"`;
const run = (extra = {}) => runVectors({ impl, vectorsFile: VECTORS, name: 'second-impl', language: 'javascript', implVersion: '0.1', ...extra });

test('second implementation matches the decision and every semantic field of all 111 vectors', async () => {
  const { summary, outcomes } = await run({ semanticOnly: true });
  const bad = outcomes.filter(o => o.status !== 'semantic-pass').map(o => `${o.id}: ${o.detail}`);
  assert.deepEqual(bad, []);
  assert.ok(PUBLISHED.length >= 272, 'the published vector set shrank to ' + PUBLISHED.length);
  assert.equal(summary.vectors.total, PUBLISHED.length);
  assert.equal(summary.vectors.semanticPass, PUBLISHED.length);
  assert.equal(summary.vectors.unsupported, 0);
});

test('second implementation refuses every refusal vector and never crashes on an accepted vector', async () => {
  const { outcomes } = await run({ semanticOnly: true });
  const refusals = outcomes.filter(o => o.detail === 'refused as required');
  assert.equal(refusals.length, PUBLISHED.filter(v => v.expected.refused === true).length);
  assert.ok(refusals.length >= 83);
});

test('second implementation digest failures are limited to the two digest fields and are listed honestly', async () => {
  // Every published vector is byte-exact against the documented text; keep it that way.
  // This test pins that every failure is a digest-only difference and that the passing count does not regress.
  const { summary, outcomes } = await run();
  const failures = outcomes.filter(o => o.status === 'fail');
  const notDigest = failures.filter(o => !/^\$\.(reportDigest|resultDigest)\b/.test(o.detail ?? '')).map(o => `${o.id}: ${o.detail}`);
  assert.deepEqual(notDigest, []);
  assert.equal(summary.vectors.pass, PUBLISHED.length, `digest-exact passes fell to ${summary.vectors.pass}`);
  assert.equal(summary.vectors.unsupported, 0);
});
