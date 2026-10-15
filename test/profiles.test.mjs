import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { digest, hashBytes } from '../src/index.mjs';
import { validateProfileMetadata, validateProfileRegistry, validateProfileId, profileStats, digestsVerified } from '../src/profiles/validate-metadata.mjs';
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

// ---- fix lane: adversarial review findings ----
const SIGN = { reviewer: 'A. Reviewer', role: 'domain expert', date: '2026-10-14', evidenceDigest: hashBytes('review record') };
const reviewedThird = (patch = {}) => { const p = thirdProfile(), e = thirdEntry(p); e.status = 'deprecated'; e.deprecation = { date: '2026-10-15', reason: 'Replaced by a newer profile.', supersededBy: null }; e.signOff = { ...SIGN, ...patch }; return { p, e }; };

test('metadata without a profile reports that digests were not verified and can be made to require one', () => {
  const e = entry();
  assert.equal(digestsVerified(validateProfileMetadata(e)), false);
  assert.equal(digestsVerified(validateProfileMetadata(e, { profile: CORE })), true);
  refuses(() => validateProfileMetadata(e, { requireProfile: true }), /Profile is required/);
  const wrong = entry(); wrong.profileDigest = hashBytes('other');
  assert.equal(digestsVerified(validateProfileMetadata(wrong)), false);
  refuses(() => validateProfileMetadata(wrong, { requireProfile: true }), /Profile is required/);
  assert.equal(Object.keys(validateProfileMetadata(e)).includes('digestsVerified'), false);
});

test('a registry without profiles reports unverified digests and can be made to require them', () => {
  assert.equal(digestsVerified(validateProfileRegistry(clone(REGISTRY))), false);
  assert.equal(digestsVerified(validateProfileRegistry(clone(REGISTRY), { profiles: profiles() })), true);
  refuses(() => validateProfileRegistry(clone(REGISTRY), { requireProfiles: true }), /Profiles are required/);
});

test('a supplied profiles map may not hold files the registry does not list', () => {
  const m = profiles(); m.set('profiles/extra.json', clone(CORE));
  refuses(() => validateProfileRegistry(clone(REGISTRY), { profiles: m }), /not listed in the registry/);
});

test('a sign-off dated after the supplied now is refused and an unreasonable evidence digest is refused', () => {
  const { p, e } = reviewedThird({ date: '2026-12-31' });
  validateProfileMetadata(e, { profile: p });
  refuses(() => validateProfileMetadata(e, { profile: p, now: '2026-10-14T00:00:00.000Z' }), /dated in the future/);
  const ok = reviewedThird();
  validateProfileMetadata(ok.e, { profile: ok.p, now: '2026-10-15T00:00:00.000Z' });
  refuses(() => validateProfileMetadata(ok.e, { profile: ok.p, now: 'tomorrow' }), /now/);
  for (const d of ['0'.repeat(64), 'f'.repeat(64), 'ab'.repeat(32), '0123'.repeat(16), '01234567'.repeat(8)]) {
    const r = reviewedThird({ evidenceDigest: d });
    refuses(() => validateProfileMetadata(r.e, { profile: r.p }), /Sign-off evidence digest is not a real digest/, d);
  }
});

test('sign-off claims are found despite spacing case and other verbs and in every free text field', () => {
  const phrases = ['Approved by the standards board.', 'Endorsed by an expert panel.', 'Validated by domain experts.', 'Audited by a third party.', 'Attested by the owner.', 'Signed  off by a reviewer.', 'S i g n e d   o f f.', 'SIGNED-OFF.', 'signed\u2003off', 'Expert reviewed.', 'Independently certified.', 'Ratified by the board.'];
  for (const s of phrases) {
    for (const where of ['purpose', 'intendedScope', 'knownGaps', 'changeLog']) {
      const e = entry();
      if (where === 'knownGaps') e.knownGaps = [...e.knownGaps, s]; else if (where === 'changeLog') e.changeLog[0].summary = s; else e[where] = s;
      refuses(() => validateProfileMetadata(e), /claims (review or )?sign-off without evidence/, where + ' ' + s);
    }
  }
  const dep = thirdEntry(); dep.status = 'deprecated'; dep.deprecation = { date: '2026-10-15', reason: 'Approved by the board for retirement.', supersededBy: null };
  refuses(() => validateProfileMetadata(dep), /claims review or sign-off without evidence/);
  validateProfileMetadata(entry());
});

test('reserved namespaces and bare names are refused for third parties', () => {
  for (const id of ['core.example:x', 'reference.example:x', 'fixture.example:x', 'registrant.example:kya', 'registrant.example:core.thing', 'registrant.example:reference.thing', 'registrant.example:fixture.thing'])
    refuses(() => validateProfileId(id, 'third-party'), /reserved/, id);
  validateProfileId('registrant.example:kyanite', 'third-party');
});

test('owner contacts may not carry an email address in any encoding', () => {
  for (const c of ['https://registrant.example/c?e=a%40b.example', 'https://registrant.example/c?e=a%2540b.example', 'https://registrant.example/c?e=a@b.example', 'https://registrant.example/c#me@b.example', 'https://registrant.example/c?mailto=a%40b', 'https://user:pw@registrant.example/c']) {
    const e = entry(); e.owner.contact = c; refuses(() => validateProfileMetadata(e), /contact/i, c);
  }
  const ok = entry(); ok.owner.contact = 'https://registrant.example/contact?team=profiles'; validateProfileMetadata(ok);
});

test('a profile cannot be superseded by itself and a deprecation cannot predate its registration', () => {
  const { p, e } = reviewedThird(); e.signOff = null;
  e.deprecation.supersededBy = e.profileId;
  refuses(() => validateProfileMetadata(e, { profile: p }), /cannot supersede itself/);
  e.deprecation.supersededBy = e.profileId.toUpperCase();
  refuses(() => validateProfileMetadata(e, { profile: p }), /cannot supersede itself|lowercase/);
  const f = reviewedThird(); f.e.signOff = null; f.e.deprecation.date = '2026-10-13';
  refuses(() => validateProfileMetadata(f.e, { profile: f.p }), /Deprecation date precedes/);
  const g = reviewedThird(); g.e.signOff = null; g.e.deprecation.date = '2026-10-14';
  validateProfileMetadata(g.e, { profile: g.p });
});
