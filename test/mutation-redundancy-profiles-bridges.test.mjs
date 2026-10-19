import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { assess, digest, hashBytes } from '../src/index.mjs';
import { inputs, clone } from './helpers.mjs';
import { exportInTotoStatement, exportOtelAttributes, exportOAuthClaims, exportSpiffeBinding, exportA2aExtension, exportMcpMeta } from '../src/interop-bridges/index.mjs';
import { validateProfileMetadata, validateProfileRegistry } from '../src/profiles/validate-metadata.mjs';

// Second, independent killers for the bridge qualified flag and the profile metadata gates. They reach the same code
// through other entry points: every bridge exporter and the kya-bridge CLI, and the registry validator with a profile map.
const root = fileURLToPath(new URL('../', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'kya-redundancy-bridges-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
let counter = 0;
const put = (name, value) => { const p = join(dir, (counter++) + '-' + name); writeFileSync(p, JSON.stringify(value)); return p; };
const CHECK = '2026-10-13T12:10:00.000Z';

function qualifiedFlags(value, path = '') {
  const found = [];
  if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) {
    if (/qualified$/i.test(k) && typeof v === 'boolean' && !/^allow/i.test(k)) found.push([path + k, v]);
    else found.push(...qualifiedFlags(v, path + k + '.'));
  }
  return found;
}

test('every bridge export reports not qualified when currency was not checked', () => {
  const r = assess(inputs());
  const unchecked = { allowNotCurrent: true };
  const outputs = {
    intoto: exportInTotoStatement(r, unchecked), otel: exportOtelAttributes(r, unchecked), oauth: exportOAuthClaims(r, unchecked),
    spiffe: exportSpiffeBinding(r, 'spiffe://example.test/agent/two', unchecked), a2a: exportA2aExtension(r, unchecked), mcp: exportMcpMeta(r, unchecked)
  };
  for (const [kind, out] of Object.entries(outputs)) {
    const flags = qualifiedFlags(out);
    assert.ok(flags.length >= 1, kind + ' carries a qualified flag');
    for (const [name, v] of flags) assert.equal(v, false, kind + ' ' + name);
  }
  const i = inputs(), checked = exportMcpMeta(r, { manifest: i.manifest, policy: i.policy, now: CHECK });
  assert.ok(qualifiedFlags(checked).every(([, v]) => v === true));
});

test('kya-bridge export without currency inputs never prints qualified true', () => {
  const r = assess(inputs());
  const run = args => spawnSync(process.execPath, [join(root, 'scripts/kya-bridge.mjs'), 'export', ...args], { cwd: root, encoding: 'utf8', timeout: 20000 });
  const refused = run(['mcp', '--assessment', put('assessment.json', r)]);
  assert.equal(refused.status, 2);
  const p = run(['mcp', '--assessment', put('assessment.json', r), '--allow-not-current']);
  assert.equal(p.status, 0, p.stderr);
  const out = JSON.parse(p.stdout);
  assert.ok(qualifiedFlags(out).length >= 1);
  assert.ok(qualifiedFlags(out).every(([, v]) => v === false));
  assert.deepEqual(out._meta['dev.kya-evidence/assessment'].currencyCheck.asOfExport.overrides, ['allowNotCurrent']);
});

const CORE = JSON.parse(await readFile(new URL('../profiles/core-v1.json', import.meta.url), 'utf8'));
const REGISTRY = JSON.parse(await readFile(new URL('../evidence/profile-registry.json', import.meta.url), 'utf8'));
const entry = () => clone(REGISTRY.profiles[0]);
const profilesMap = () => new Map([['profiles/core-v1.json', clone(CORE)]]);
const registryWith = e => ({ ...clone(REGISTRY), profiles: [e] });
const SIGNOFF = { reviewer: 'B. Reviewer', role: 'security reviewer', date: '2026-10-15', evidenceDigest: hashBytes('another review record') };
const thirdProfile = () => ({ ...clone(CORE), id: 'registrant.example:ledger-draft', version: '0.2.0', title: 'Third party ledger draft' });
const thirdEntry = p => ({ ...entry(), profileId: p.id, profileVersion: p.version, profileDigest: digest(p), file: 'profiles/ledger-draft.json', status: 'draft', owner: { kind: 'third-party', contact: 'https://registrant.example/contact' }, changeLog: [{ version: p.version, date: '2026-10-14', summary: 'Initial draft.' }] });

test('a profile whose only change is its title no longer matches the recorded digest', () => {
  const edited = clone(CORE); edited.title = 'A different title with identical counts';
  assert.throws(() => validateProfileMetadata(entry(), { profile: edited }), /Profile digest mismatch/);
  assert.throws(() => validateProfileRegistry(REGISTRY, { profiles: new Map([['profiles/core-v1.json', edited]]) }), /Profile digest mismatch/);
  assert.doesNotThrow(() => validateProfileMetadata(entry(), { profile: CORE }));
});

test('the registry validator refuses a malformed sign-off evidence digest', () => {
  for (const bad of ['not-a-digest', hashBytes('x').toUpperCase(), hashBytes('x').slice(1), hashBytes('x') + '0', '']) {
    const e = entry(); e.signOff = { ...SIGNOFF, evidenceDigest: bad };
    assert.throws(() => validateProfileRegistry(registryWith(e), { profiles: profilesMap() }), /Sign-off evidence digest|SHA-256|digest/i, String(bad));
  }
  const ok = entry(); ok.signOff = SIGNOFF;
  assert.doesNotThrow(() => validateProfileRegistry(registryWith(ok), { profiles: profilesMap() }));
});

test('the registry validator refuses a sign-off record with a missing or unexpected member', () => {
  const extra = entry(); extra.signOff = { ...SIGNOFF, approvalLevel: 'final' };
  assert.throws(() => validateProfileRegistry(registryWith(extra), { profiles: profilesMap() }), /Sign-off/);
  const swapped = entry(); swapped.signOff = { ...SIGNOFF, comment: 'looks fine' };
  assert.throws(() => validateProfileMetadata(swapped, { profile: CORE }), /Sign-off/);
  const missing = entry(); const { role, ...partial } = SIGNOFF; missing.signOff = partial;
  assert.throws(() => validateProfileMetadata(missing, { profile: CORE }), /Sign-off/);
});

test('the registry validator refuses a sign-off on a draft third party profile', () => {
  const p = thirdProfile(), e = thirdEntry(p), map = new Map([['profiles/ledger-draft.json', p]]);
  const registry = { ...clone(REGISTRY), profiles: [e] };
  assert.doesNotThrow(() => validateProfileRegistry(registry, { profiles: map }));
  const signed = { ...e, signOff: SIGNOFF };
  assert.throws(() => validateProfileRegistry({ ...clone(REGISTRY), profiles: [signed] }, { profiles: map }), /draft profile cannot carry a sign-off/);
  assert.throws(() => validateProfileMetadata(signed), /draft profile cannot carry a sign-off/);
});
