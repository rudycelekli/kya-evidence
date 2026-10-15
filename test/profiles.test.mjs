import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { digest, hashBytes } from '../src/index.mjs';
import { validateProfileMetadata, validateProfileRegistry, validateProfileId, profileStats } from '../src/profiles/validate-metadata.mjs';
import { generate } from '../scripts/profile-registry.mjs';

const CORE = JSON.parse(await readFile(new URL('../profiles/core-v1.json', import.meta.url), 'utf8'));
const REGISTRY = JSON.parse(await readFile(new URL('../evidence/profile-registry.json', import.meta.url), 'utf8'));
const clone = v => JSON.parse(JSON.stringify(v));
const entry = () => clone(REGISTRY.profiles[0]);
const profiles = () => new Map([['profiles/core-v1.json', clone(CORE)]]);
const refuses = (f, re) => assert.throws(f, re);

// A third-party draft over a copy of the core checks, for cases that need a non-project owner.
const thirdProfile = () => ({ ...clone(CORE), id: 'registrant.example:payments-draft', version: '0.1.0', title: 'Third party draft' });
const thirdEntry = (p = thirdProfile()) => ({ ...entry(), profileId: p.id, profileVersion: p.version, profileDigest: digest(p), file: 'profiles/payments-draft.json', status: 'draft', owner: { kind: 'third-party', contact: 'https://registrant.example/contact' }, changeLog: [{ version: p.version, date: '2026-10-14', summary: 'First draft.' }] });

test('the committed profile registry matches the generator byte for byte', async () => {
  assert.equal(await generate(), await readFile(new URL('../evidence/profile-registry.json', import.meta.url), 'utf8'));
});

test('the registry digest for the core profile is recomputed from the frozen file', () => {
  const e = REGISTRY.profiles.find(p => p.profileId === 'kya-core');
  assert.equal(e.profileDigest, digest(CORE));
  assert.equal(e.profileVersion, '1.0.0');
  assert.deepEqual({ checkCount: e.checkCount, criticalCount: e.criticalCount, totalWeight: e.totalWeight }, profileStats(CORE));
  assert.match(e.profileDigest, /^[a-f0-9]{64}$/);
});

test('every registry entry is draft or reference with no sign-off set', () => {
  for (const p of REGISTRY.profiles) {
    assert.ok(['draft', 'reference'].includes(p.status));
    assert.equal(p.signOff, null);
    assert.ok(p.knownGaps.length >= 1 && p.changeLog.length >= 1);
  }
});

test('the registry and its entries validate against the real profile files', () => {
  validateProfileRegistry(REGISTRY, { profiles: profiles() });
  validateProfileMetadata(entry(), { profile: CORE });
});

test('every policy template targets a registered profile id', async () => {
  const ids = new Set(REGISTRY.profiles.map(p => p.profileId));
  for (const t of ['agentic-payments', 'code-agent', 'read-only-assistant']) {
    const v = JSON.parse(await readFile(new URL(`../policies/templates/${t}.json`, import.meta.url), 'utf8'));
    assert.ok(ids.has(v.targetProfileId), t);
  }
});

test('a digest mismatch between metadata and the profile is refused', () => {
  const e = entry(); e.profileDigest = hashBytes('some other bytes');
  refuses(() => validateProfileMetadata(e, { profile: CORE }), /Profile digest mismatch/);
  refuses(() => validateProfileRegistry({ ...clone(REGISTRY), profiles: [e] }, { profiles: profiles() }), /Profile digest mismatch/);
});

test('a profile edited after registration no longer matches its recorded digest', () => {
  const p = clone(CORE); p.checks[0].weight = 2;
  refuses(() => validateProfileMetadata(entry(), { profile: p }), /Profile digest mismatch|differs/);
});

test('a duplicate profile id and version in the registry is refused', () => {
  const r = clone(REGISTRY); r.profiles.push(entry());
  refuses(() => validateProfileRegistry(r), /Duplicate profile ID and version/);
});

test('an id differing only by case collides with an existing id', () => {
  const e = entry(); e.profileId = 'KYA-CORE';
  refuses(() => validateProfileMetadata(e), /lowercase/);
});

test('the same digest under another id is refused', () => {
  const e2 = entry(); e2.profileId = 'core-alias';
  const r = clone(REGISTRY); r.profiles.push(e2); r.profiles.sort((a, b) => (a.profileId < b.profileId ? -1 : 1));
  refuses(() => validateProfileRegistry(r), /already registered under another ID/);
});

test('a missing known gaps field is refused', () => {
  const e = entry(); delete e.knownGaps;
  refuses(() => validateProfileMetadata(e), /Profile metadata/);
});

test('an empty known gaps list is refused', () => {
  const e = entry(); e.knownGaps = [];
  refuses(() => validateProfileMetadata(e), /Known gaps/);
});

test('a missing change log or owner or purpose is refused', () => {
  for (const k of ['changeLog', 'owner', 'purpose', 'intendedScope', 'signOff']) { const e = entry(); delete e[k]; refuses(() => validateProfileMetadata(e), /Profile metadata/, k); }
});

test('a change log without an entry for the profile version is refused', () => {
  const e = entry(); e.changeLog[0].version = '0.9.0';
  refuses(() => validateProfileMetadata(e), /no entry for the profile version/);
});

test('a sign-off object without evidence fields is refused', () => {
  const e = entry(); e.signOff = { reviewer: 'A. Reviewer', role: 'domain expert', date: '2026-10-14' };
  refuses(() => validateProfileMetadata(e), /Sign-off/);
});

test('a sign-off with a malformed evidence digest is refused', () => {
  const e = entry(); e.signOff = { reviewer: 'A. Reviewer', role: 'domain expert', date: '2026-10-14', evidenceDigest: 'not-a-digest' };
  refuses(() => validateProfileMetadata(e), /Sign-off evidence digest/);
});

test('a draft profile cannot carry a sign-off', () => {
  const p = thirdProfile(), e = thirdEntry(p); e.signOff = { reviewer: 'A. Reviewer', role: 'domain expert', date: '2026-10-14', evidenceDigest: hashBytes('review record') };
  refuses(() => validateProfileMetadata(e, { profile: p }), /draft profile cannot carry a sign-off/);
});

test('prose claiming expert sign-off without evidence is refused', () => {
  for (const k of ['purpose', 'intendedScope']) { const e = entry(); e[k] = 'Signed off by a domain expert as a sound starting point.'; refuses(() => validateProfileMetadata(e), /claims review or sign-off without evidence/); }
  const c = entry(); c.changeLog[0].summary = 'Expert-reviewed and accepted.';
  refuses(() => validateProfileMetadata(c), /claims sign-off without evidence/);
});

test('an unknown status is refused', () => {
  for (const s of ['approved', 'certified', 'reviewed', 'Draft', '', null]) { const e = entry(); e.status = s; refuses(() => validateProfileMetadata(e), /Unknown profile status/, String(s)); }
});

test('reference status is limited to project profiles', () => {
  const p = thirdProfile(), e = thirdEntry(p); e.status = 'reference';
  refuses(() => validateProfileMetadata(e, { profile: p }), /Only a project profile can have reference status/);
});

test('deprecated status needs a deprecation record and the record needs that status', () => {
  const e = entry(); e.status = 'deprecated';
  refuses(() => validateProfileMetadata(e), /requires a deprecation record/);
  const f = entry(); f.deprecation = { date: '2026-10-14', reason: 'x', supersededBy: null };
  refuses(() => validateProfileMetadata(f), /requires deprecated or retired status/);
  const p = thirdProfile(), g = thirdEntry(p); g.status = 'deprecated'; g.deprecation = { date: '2026-10-14', reason: 'Replaced by a reviewed profile.', supersededBy: null };
  validateProfileMetadata(g, { profile: p });
});

test('unknown extra fields and a wrong schema are refused', () => {
  const e = entry(); e.endorsed = true;
  refuses(() => validateProfileMetadata(e), /Profile metadata/);
  const s = entry(); s.schema = 'kya.profile-metadata/v2';
  refuses(() => validateProfileMetadata(s), /Unsupported profile metadata schema/);
});

test('profile id naming and namespace rules', () => {
  validateProfileId('kya-core', 'project'); validateProfileId('core-payments', 'project');
  validateProfileId('registrant.example:payments-draft', 'third-party');
  for (const id of ['payments', 'other', 'core-', 'kya-other']) refuses(() => validateProfileId(id, 'project'), /Project profile ID/);
  for (const id of ['payments', 'a:b:c', 'Example.com:x', 'localhost:x', 'registrant.example:Payments', 'registrant.example:core-x', 'kya.example:x', 'registrant.example:fixture-x', 'local.thing:x', 'registrant.example:' + 'a'.repeat(65)]) refuses(() => validateProfileId(id, 'third-party'), undefined, id);
});

test('an owner contact must be a placeholder or an https URL and never an email address', () => {
  for (const c of ['person@example.com', 'http://registrant.example', 'mailto:a@b.c', '']) { const e = entry(); e.owner.contact = c; refuses(() => validateProfileMetadata(e), undefined, c); }
});

test('a registry naming a profile file that was not supplied is refused', () => {
  refuses(() => validateProfileRegistry(clone(REGISTRY), { profiles: new Map() }), /not supplied/);
});

test('registry entries out of order are refused', () => {
  const p = thirdProfile(), r = clone(REGISTRY); r.profiles.push(thirdEntry(p));
  // registrant.example:... sorts after kya-core, so reversing breaks order
  r.profiles.reverse();
  refuses(() => validateProfileRegistry(r), /sorted/);
});

test('a malformed registry document is refused', () => {
  for (const bad of [null, [], 'x', { ...clone(REGISTRY), schema: 'x' }, { ...clone(REGISTRY), profiles: 'x' }, { ...clone(REGISTRY), extra: 1 }]) refuses(() => validateProfileRegistry(bad));
});
