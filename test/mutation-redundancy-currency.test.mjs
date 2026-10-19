import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { assess, checkCurrency, signIncident, keyId, hashBytes, digest } from '../src/index.mjs';
import { inputs, keys, clone } from './helpers.mjs';

// Second, independent killers for single-killer controls in the currency and incident logic.
// These drive the public kya-check CLI (currency-only mode) or use inputs the first killers do not use.
const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/kya-check.mjs');
const dir = mkdtempSync(join(tmpdir(), 'kya-redundancy-currency-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
let counter = 0;
const put = (name, value) => { const p = join(dir, (counter++) + '-' + name); writeFileSync(p, JSON.stringify(value)); return p; };
const pemOf = k => k.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const alpha = generateKeyPairSync('ed25519'), beta = generateKeyPairSync('ed25519'), gamma = generateKeyPairSync('ed25519'), outsider = generateKeyPairSync('ed25519');
const T0 = '2026-10-13T12:30:00.000Z', T1 = '2026-10-13T12:45:00.000Z', CHECK = '2026-10-13T12:59:00.000Z', LATER = '2026-10-13T13:20:00.000Z';

function world() {
  const i = inputs();
  i.policy.trustedKeys.push({ id: keyId(pemOf(alpha)), publicKey: pemOf(alpha), role: 'independent' });
  i.policy.trustedKeys.push({ id: keyId(pemOf(beta)), publicKey: pemOf(beta), role: 'independent' });
  i.policy.trustedKeys.push({ id: keyId(pemOf(gamma)), publicKey: pemOf(gamma), role: 'self' });
  const report = assess(i);
  const rec = (patch, key) => signIncident({ schema: 'kya.incident/v1', id: 'inc:z', subjectDigest: report.subjectDigest, kind: 'report', severity: 'high', refId: null, reportedAt: T0, detailsDigest: hashBytes('redundancy detail'), ...patch }, key);
  return { i, report, rec };
}
function cli(w, incidents, now = CHECK, report = w.report) {
  const args = ['--assessment', put('assessment.json', report), '--manifest', put('manifest.json', w.i.manifest), '--policy', put('policy.json', w.i.policy), '--now', now, '--allow-fixture', '--allow-unpinned-assessment'];
  if (incidents !== undefined) args.push('--incidents', put('incidents.json', incidents));
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', timeout: 20000, env: { PATH: process.env.PATH } });
}
const summary = p => JSON.parse(p.stdout.split('\n').filter(l => !l.startsWith('::')).join('\n'));
const resolution = (w, key, patch = {}) => w.rec({ id: 'res:z', kind: 'resolution', severity: 'low', refId: 'inc:z', reportedAt: T1, ...patch }, key);

test('cli keeps an incident open when a trusted self role key tries to resolve it', () => {
  const w = world();
  const s = summary(cli(w, [w.rec({}, alpha.privateKey), resolution(w, gamma.privateKey)]));
  assert.deepEqual(s.currency.incidentsOpen, ['inc:z']);
  assert.ok(s.currency.triggers.some(t => t.code === 'INCIDENT_OPEN'));
  assert.deepEqual(summary(cli(w, [w.rec({}, alpha.privateKey), resolution(w, beta.privateKey)])).currency.incidentsOpen, []);
});

test('an appeal from a key outside the trust anchors is ignored and never recorded as an appeal', () => {
  const w = world();
  const r = checkCurrency(w.report, { manifest: w.i.manifest, policy: w.i.policy, now: CHECK, incidents: [w.rec({}, alpha.privateKey), w.rec({ id: 'app:z', kind: 'appeal', severity: 'low', refId: 'inc:z' }, outsider.privateKey)] });
  assert.deepEqual(r.incidents.appealed, []);
  assert.deepEqual(r.incidents.open, ['inc:z']);
  assert.ok(r.incidents.ignored.some(x => x.id === 'app:z' && /trusted anchor/i.test(x.reason)));
});

test('a report from a key outside the trust anchors is neither observed nor open', () => {
  const w = world();
  const r = checkCurrency(w.report, { manifest: w.i.manifest, policy: w.i.policy, now: CHECK, incidents: [w.rec({ id: 'low:z', severity: 'low' }, outsider.privateKey)] });
  assert.deepEqual(r.incidents.observed, []);
  assert.deepEqual(r.incidents.open, []);
  assert.equal(r.incidents.ignored.length, 1);
});

test('cli refuses a reporter that resolves its own independent report', () => {
  const w = world();
  const s = summary(cli(w, [w.rec({}, beta.privateKey), resolution(w, beta.privateKey)]));
  assert.deepEqual(s.currency.incidentsOpen, ['inc:z']);
  assert.equal(s.reliable, false);
  assert.deepEqual(summary(cli(w, [w.rec({}, beta.privateKey), resolution(w, alpha.privateKey)])).currency.incidentsOpen, []);
});

test('cli does not honour a resolution dated after the check time', () => {
  const w = world();
  const incidents = [w.rec({}, gamma.privateKey), resolution(w, alpha.privateKey, { reportedAt: '2026-10-13T13:30:00.000Z' })];
  assert.deepEqual(summary(cli(w, incidents, CHECK)).currency.incidentsOpen, ['inc:z']);
  assert.deepEqual(summary(cli(w, incidents, '2026-10-13T13:40:00.000Z')).currency.incidentsOpen, []);
});

test('a report delivered twice does not make its own resolution ambiguous', () => {
  const w = world();
  const report = w.rec({}, gamma.privateKey), res = resolution(w, alpha.privateKey);
  const r = checkCurrency(w.report, { manifest: w.i.manifest, policy: w.i.policy, now: CHECK, incidents: [report, report, res] });
  assert.deepEqual(r.incidents.open, []);
  assert.deepEqual(r.incidents.resolved, ['inc:z']);
  assert.deepEqual(r.incidents.ignored, []);
  assert.equal(r.current, true);
});

test('cli result is stable as the clock passes a future dated duplicate report ID', () => {
  const w = world();
  const incidents = [
    w.rec({ reportedAt: '2026-10-13T12:20:00.000Z' }, gamma.privateKey),
    resolution(w, alpha.privateKey, { reportedAt: '2026-10-13T12:25:00.000Z' }),
    w.rec({ severity: 'medium', reportedAt: '2026-10-13T13:10:00.000Z', detailsDigest: hashBytes('later duplicate') }, beta.privateKey)
  ];
  const before = summary(cli(w, incidents, '2026-10-13T12:40:00.000Z')), after = summary(cli(w, incidents, LATER));
  assert.deepEqual(before.currency.incidentsOpen, ['inc:z']);
  assert.deepEqual(after.currency.incidentsOpen, ['inc:z']);
});

test('cli refuses a resealed assessment whose validity is malformed or precedes its assessment', () => {
  const w = world();
  const reseal = edit => { const r = clone(w.report); delete r.reportDigest; edit(r); return { ...r, reportDigest: digest(r) }; };
  const good = cli(w, [], CHECK);
  assert.equal(good.status, 0, good.stderr);
  for (const edit of [r => { r.validUntil = 'never'; }, r => { r.validUntil = new Date(Date.parse(r.assessedAt) - 1000).toISOString(); }, r => { delete r.validUntil; }]) {
    const p = cli(w, [], CHECK, reseal(edit));
    assert.equal(p.status, 1);
    assert.equal(p.stdout, '');
  }
});
