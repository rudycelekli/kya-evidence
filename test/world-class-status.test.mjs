import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { validateStatus, renderStatus } from '../scripts/world-class-status.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const registry = JSON.parse(await readFile(new URL('../evidence/requirements.json', import.meta.url), 'utf8'));
const current = JSON.parse(await readFile(new URL('../evidence/world-class-status.json', import.meta.url), 'utf8'));
const status = () => structuredClone(current);
const ok = s => validateStatus(s, { registry, root });
const item = (s, id) => s.streams.flatMap(x => x.items).find(x => x.id === id);

test('the committed status ledger is valid, complete and renders to the committed document', async () => {
  const s = status();
  ok(s);
  assert.deepEqual(s.streams.map(x => x.id), ['WS1', 'WS2', 'WS3', 'WS4', 'WS5', 'WS6', 'WS7', 'WS8', 'WS9', 'WS10']);
  assert.equal(await readFile(new URL('../docs/WORLD-CLASS-STATUS.md', import.meta.url), 'utf8'), renderStatus(s));
});

test('an item cannot be verified without a verifier and linked evidence of the matching kind', () => {
  const s = status(), target = s.streams[0].items[0];
  target.status = 'verified'; delete target.verifiedBy; target.evidence = [];
  assert.throws(() => ok(s), /verifier|evidence/i);
  target.verifiedBy = 'CI'; target.evidence = [];
  assert.throws(() => ok(s), /evidence/i);
  target.evidence = [{ type: 'requirement', ref: 'KYA-NOPE-999' }];
  assert.throws(() => ok(s), /unknown requirement/i);
  target.evidence = [{ type: 'test', ref: 'test/does-not-exist.test.mjs' }];
  assert.throws(() => ok(s), /missing file|not found/i);
  target.evidence = [{ type: 'requirement', ref: registry.requirements[0].id }];
  assert.doesNotThrow(() => ok(s));
});

test('outside-party verification needs a named external party, an https link and a date, never internal evidence', () => {
  for (const verifiedBy of ['XREV', 'XIMP', 'XUSE']) {
    const s = status(), target = s.streams[2].items[0];
    target.status = 'verified'; target.verifiedBy = verifiedBy;
    target.evidence = [{ type: 'requirement', ref: registry.requirements[0].id }];
    assert.throws(() => ok(s), /external/i, verifiedBy);
    target.evidence = [{ type: 'external', party: 'Example Reviewer', url: 'http://insecure.example/report', date: '2026-10-15' }];
    assert.throws(() => ok(s), /https/i, verifiedBy);
    target.evidence = [{ type: 'external', party: 'Example Reviewer', url: 'https://example.org/report', date: 'last week' }];
    assert.throws(() => ok(s), /date/i, verifiedBy);
    target.evidence = [{ type: 'external', party: '', url: 'https://example.org/report', date: '2026-10-15' }];
    assert.throws(() => ok(s), /party/i, verifiedBy);
    target.evidence = [{ type: 'external', party: 'Example Reviewer', url: 'https://example.org/report', date: '2026-10-15' }];
    assert.doesNotThrow(() => ok(s), verifiedBy);
  }
});

test('no item is currently claimed verified by an outside party, and every outside-dependent item says so', () => {
  const s = status();
  for (const it of s.streams.flatMap(x => x.items)) {
    if (it.status === 'verified') assert.equal(it.verifiedBy, 'CI', `${it.id} claims outside verification without evidence`);
    if (it.needsOutside) assert.notEqual(it.status, 'verified', it.id);
  }
  assert.ok(s.streams.flatMap(x => x.items).some(x => x.needsOutside), 'the ledger must name the work that needs outsiders');
});

test('implemented items must cite something that exists, and unknown statuses, duplicate IDs and missing streams are rejected', () => {
  let s = status(); item(s, s.streams[0].items[0].id).status = 'done';
  assert.throws(() => ok(s), /status/i);
  s = status(); const t = s.streams[0].items[0]; t.status = 'implemented'; t.evidence = [];
  assert.throws(() => ok(s), /evidence/i);
  s = status(); s.streams[0].items[1].id = s.streams[0].items[0].id;
  assert.throws(() => ok(s), /duplicate/i);
  s = status(); s.streams[1].items[0].id = s.streams[0].items[0].id;
  assert.throws(() => ok(s), /must look like/i);
  s = status(); s.streams.pop();
  assert.throws(() => ok(s), /stream/i);
  s = status(); s.extra = true;
  assert.throws(() => ok(s), /unknown|unexpected/i);
});
