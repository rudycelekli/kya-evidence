import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, truncateSync, openSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, createHmac, sign } from 'node:crypto';
import { assess, digest } from '../src/index.mjs';
import { createDossier } from '../src/reporting/application/dossier.mjs';
import { renderDossierHtml, renderDossierMarkdown } from '../src/reporting/infrastructure/render.mjs';
import { exportInTotoStatement, exportOtelAttributes, exportOAuthClaims, exportA2aExtension, exportMcpMeta, exportSpiffeBinding, verifyBridgeExport, serialize } from '../src/interop-bridges/index.mjs';
import { exportAssessmentCredential, verifyAssessmentCredential } from '../src/vc-bridge/index.mjs';
import { terminalJson, stripUnsafe, terminalText } from '../src/shared/terminal.mjs';
import { clean } from '../scripts/kya-check.mjs';
import { inputs, manifest, profile, policy, bundle, NOW } from './helpers.mjs';

const cp = n => String.fromCodePoint(n);
const root = fileURLToPath(new URL('../', import.meta.url));
const EVIL = ['Agent ', cp(0x202e), 'evil', cp(0x202c), ' ', cp(0x9b), '31m ', cp(0x200b), ' ', cp(0x2066), ' ', cp(0x2028), ' end'].join('');
const BAD = new RegExp('[\\u007f-\\u009f\\u00ad\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\ufeff]');
const clip = text => text.replace(/[^\x20-\x7e\n]/g, c => 'U+' + c.codePointAt(0).toString(16));
const run = (script, args, options = {}) => spawnSync(process.execPath, [join(root, script), ...args], { encoding: 'utf8', timeout: 30000, ...options });

function evilInputs() {
  const m = manifest(), p = profile();
  m.agent.name = EVIL;
  return { manifest: m, profile: p, policy: policy(p), evidence: bundle(m, p), evaluatorDigest: inputs().evaluatorDigest, now: NOW };
}

test('fixlane9 terminal json escapes C1 bidi zero width and separators and parses back identically', () => {
  const value = { name: EVIL, tag: '\u{e0041}\u{e0042}', nested: [EVIL], plain: 'ordinary text', quote: 'say "hi"' };
  const text = terminalJson(value, null, 2);
  assert.equal(BAD.test(text), false, clip(text));
  assert.deepEqual(JSON.parse(text), value);
  assert.equal(terminalJson({ a: 1 }), '{"a":1}');
  assert.equal(terminalJson(undefined), undefined);
});

test('fixlane9 strip and text helpers neutralize every invisible or reordering character', () => {
  assert.equal(BAD.test(stripUnsafe(EVIL)), false);
  assert.equal(stripUnsafe('a\u001bb'), 'a b');
  const shown = terminalText('a' + cp(0x202e) + 'b\u001b[2Jc\nd\te');
  assert.match(shown, /\[U\+202E\]/);
  assert.match(shown, /\[U\+001B\]/);
  assert.ok(shown.includes('\n') && shown.includes('\t'));
});

test('fixlane9 kya assess output carries no raw bidi or C1 characters from an agent name', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-fl9-assess-'));
  try {
    const x = evilInputs();
    const files = {};
    for (const k of ['manifest', 'profile', 'policy', 'evidence']) { files[k] = join(dir, k + '.json'); writeFileSync(files[k], JSON.stringify(x[k])); }
    const r = run('bin/kya.mjs', ['assess', '--manifest', files.manifest, '--profile', files.profile, '--policy', files.policy, '--evidence', files.evidence, '--evaluator', x.evaluatorDigest, '--now', NOW]);
    assert.ok(r.stdout.includes('agentName'), r.stderr);
    assert.equal(BAD.test(r.stdout), false, clip(r.stdout.slice(0, 600)));
    assert.equal(JSON.parse(r.stdout).agentName, EVIL);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fixlane9 kya-vc verify output carries no raw bidi or C1 characters from a foreign credential', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-fl9-vc-'));
  try {
    const issuer = generateKeyPairSync('ed25519');
    const out = exportAssessmentCredential(assess(inputs()), { issuerKey: issuer.privateKey, validFrom: '2026-10-13T12:00:00.000Z' });
    const [h, p] = out.jwt.split('.');
    const payload = JSON.parse(Buffer.from(p, 'base64url'));
    payload.credentialSubject.note = EVIL;
    const pb = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const token = `${h}.${pb}.${sign(null, Buffer.from(`${h}.${pb}`), issuer.privateKey).toString('base64url')}`;
    const file = join(dir, 'c.jwt'); writeFileSync(file, token + '\n');
    const r = run('scripts/kya-vc.mjs', ['verify', '--jwt', file, '--now', '2026-10-13T12:30:00.000Z', '--allow-untrusted-issuer']);
    assert.ok(r.stdout.includes('note'), r.stderr);
    assert.equal(BAD.test(r.stdout), false, clip(r.stdout.slice(0, 300)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fixlane9 kya-check clean strips bidi and zero width characters', () => {
  assert.equal(BAD.test(clean(EVIL)), false);
  assert.equal(clean('a\u001bb' + cp(0x202e) + 'c'), 'a b c');
});

test('fixlane9 privacy scan text and json output neutralize control and bidi characters in file names', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-fl9-scan-'));
  try {
    writeFileSync(join(dir, 'x' + cp(0x202e) + 'y\u001b[31m.json'), JSON.stringify({ contact: 'person@example.org' }));
    for (const format of ['text', 'json']) {
      const r = run('scripts/privacy-scan.mjs', ['--format', format, '.'], { cwd: dir });
      assert.equal(r.status, 1, r.stderr);
      assert.ok(r.stdout.includes('email'), r.stdout);
      assert.equal(BAD.test(r.stdout) || r.stdout.includes('\u001b'), false, clip(r.stdout.slice(0, 400)));
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fixlane9 dossier markdown and html make invisible characters in the agent name visible', () => {
  const dossier = createDossier({ inputs: evilInputs() });
  for (const view of [renderDossierMarkdown(dossier), renderDossierHtml(dossier)]) {
    assert.equal(BAD.test(view), false, clip(view.slice(0, 300)));
    assert.match(view, /U\\?\+202E/);
  }
});

function forged(mutate) {
  const { reportDigest, ...body } = JSON.parse(JSON.stringify(assess(inputs())));
  mutate(body);
  return { ...body, reportDigest: digest(body) };
}
const ALLOW = { allowNonQualified: true, allowNotCurrent: true };
const EXPORTS = [
  ['intoto', r => exportInTotoStatement(r, ALLOW)], ['otel', r => exportOtelAttributes(r, ALLOW)], ['oauth', r => exportOAuthClaims(r, ALLOW)],
  ['a2a', r => exportA2aExtension(r, ALLOW)], ['mcp', r => exportMcpMeta(r, ALLOW)], ['spiffe', r => exportSpiffeBinding(r, 'spiffe://example.test/agent', ALLOW)]
];

test('fixlane9 bridge exports refuse a self digested report whose fields leave the report vocabulary', () => {
  const cases = {
    decision: b => { b.decision = EVIL; },
    evidenceMode: b => { b.evidenceMode = EVIL; },
    scopeId: b => { b.scopeId = EVIL; },
    profileId: b => { b.profileId = 'line one\nline two'; },
    selectedRunId: b => { b.selectedRunId = EVIL; },
    limitations: b => { b.limitations = [EVIL]; },
    limitationsMissing: b => { delete b.limitations; },
    scoreText: b => { b.score.earned = '<img src=x>'; },
    scoreMissing: b => { delete b.score; },
    coverageText: b => { b.coverage = EVIL; },
    coverageRange: b => { b.coverage = 7; }
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const report = forged(mutate);
    for (const [kind, build] of EXPORTS) assert.throws(() => build(report), /Report|report|invalid|vocabulary/i, `${name} ${kind}`);
    const verdict = verifyBridgeExport('otel', {}, { report });
    assert.equal(verdict.valid, false, name);
    assert.ok(['REPORT_INVALID', 'MALFORMED'].includes(verdict.errors[0].code), name);
  }
  const fine = assess(inputs());
  for (const [kind, build] of EXPORTS) assert.doesNotThrow(() => build(fine), kind);
});

test('fixlane9 bridge serialize escapes invisible characters without changing parsed content', () => {
  const text = serialize({ k: EVIL });
  assert.equal(BAD.test(text), false);
  assert.deepEqual(JSON.parse(text), { k: EVIL });
  assert.ok(text.endsWith('\n'));
});

test('fixlane9 kya-vc kya-bridge and conformance-report refuse an oversized input file before reading it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-fl9-big-'));
  try {
    const big = join(dir, 'big.json');
    const fd = openSync(big, 'w'); closeSync(fd); truncateSync(big, 6 * 1024 * 1024);
    const vc = run('scripts/kya-vc.mjs', ['verify', '--jwt', big, '--now', NOW, '--allow-untrusted-issuer']);
    assert.notEqual(vc.status, 0);
    assert.match(vc.stderr, /bounded regular file/);
    const br = run('scripts/kya-bridge.mjs', ['export', 'otel', '--assessment', big, '--allow-non-qualified', '--allow-not-current']);
    assert.equal(br.status, 2);
    assert.match(br.stderr, /bounded regular file/);
    const cr = run('scripts/conformance-report.mjs', ['--verify', big]);
    assert.notEqual(cr.status, 0);
    assert.match(cr.stderr, /bounded regular file/);
    const dirResult = run('scripts/kya-bridge.mjs', ['export', 'otel', '--assessment', dir, '--allow-non-qualified']);
    assert.equal(dirResult.status, 2);
    assert.match(dirResult.stderr, /bounded regular file/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- pins for attacks that were tried and refused (no code change needed) ----
const issuer = generateKeyPairSync('ed25519');
const AT = '2026-10-13T12:30:00.000Z';
const good = () => exportAssessmentCredential(assess(inputs()), { issuerKey: issuer.privateKey, validFrom: '2026-10-13T12:00:00.000Z' }).jwt;
const enc = v => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
const sig = (h, p) => sign(null, Buffer.from(`${h}.${p}`), issuer.privateKey).toString('base64url');
const codes = (token, o = {}) => { const r = verifyAssessmentCredential(token, { now: AT, ...o }); return r.valid ? ['VALID'] : r.errors.map(e => e.code); };

test('fixlane9 vc verify refuses duplicate header members even when the signature covers them', () => {
  const [h, p] = good().split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const dup = JSON.stringify(header).replace('}', ',"alg":"none"}');
  assert.deepEqual(codes(`${enc(dup)}.${p}.${sig(enc(dup), p)}`), ['MALFORMED']);
  const alias = JSON.stringify(header).replace('"alg"', '"a\\u006cg"').replace('}', ',"alg":"EdDSA"}');
  assert.deepEqual(codes(`${enc(alias)}.${p}.${sig(enc(alias), p)}`), ['MALFORMED']);
});

test('fixlane9 vc verify refuses crit b64 false jwk and HMAC with the public key as secret', () => {
  const [h, p] = good().split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  for (const extra of [{ crit: ['b64'], b64: false }, { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AA' } }, { x5u: 'https://example.test/k' }, { jku: 'https://example.test/k' }]) {
    const hb = enc({ ...header, ...extra });
    assert.deepEqual(codes(`${hb}.${p}.${sig(hb, p)}`), ['HEADER_MEMBER_NOT_ALLOWED']);
  }
  const hb = enc({ ...header, alg: 'HS256' });
  const pem = issuer.publicKey.export({ type: 'spki', format: 'pem' });
  assert.deepEqual(codes(`${hb}.${p}.${createHmac('sha256', pem).update(`${hb}.${p}`).digest('base64url')}`), ['ALG_NOT_ALLOWED']);
});

test('fixlane9 vc verify refuses detached payloads trailing dots padding and a malleable signature', () => {
  const token = good(), [h, p, s] = token.split('.');
  for (const bad of [`${h}..${s}`, token + '.', '.' + token, `${h}=.${p}.${s}`, `${h}.${p}.${s}==`, `${h}.${p}.${s.slice(0, -1)}`]) assert.deepEqual(codes(bad), ['MALFORMED'], bad.slice(0, 30));
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const raw = Buffer.from(s, 'base64url');
  const S = BigInt('0x' + Buffer.from(raw.subarray(32)).reverse().toString('hex'));
  const bumped = Buffer.from((S + L).toString(16).padStart(64, '0'), 'hex').reverse();
  assert.equal(bumped.length, 32);
  assert.deepEqual(codes(`${h}.${p}.${Buffer.concat([raw.subarray(0, 32), bumped]).toString('base64url')}`), ['SIGNATURE_INVALID']);
  assert.deepEqual(codes(`${h}.${'A'.repeat(2_000_000)}.${s}`), ['MALFORMED']);
});

test('fixlane9 vc status lookup ignores prototype keys in the supplied status list map', () => {
  const [h, p] = good().split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url'));
  for (const name of ['__proto__', 'toString', 'constructor']) {
    payload.credentialStatus = [{ type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: name }];
    const pb = enc(payload);
    const result = verifyAssessmentCredential(`${h}.${pb}.${sig(h, pb)}`, { now: AT, statusLists: {}, requireStatusCheck: true });
    assert.equal(result.valid, false, name);
    assert.equal(result.status.checked, false, name);
    assert.ok(result.errors.some(e => e.code === 'STATUS_NOT_CHECKED'), name);
  }
});

test('fixlane9 privacy scan stays linear on adversarial one hundred thousand character strings', async () => {
  const { scanString } = await import('../scripts/privacy-scan.mjs');
  const n = 100_000;
  const shapes = [' ' + 'a.'.repeat(n / 2), ' a@' + 'b.'.repeat(n / 2), ' ' + 'a@'.repeat(n / 2), ' ' + '1 '.repeat(n / 2), ' ' + '(1'.repeat(n / 2), ' /Users/' + 'a'.repeat(n) + '"', ' ' + '-----BEGIN A-----'.repeat(n / 17), ' ' + 'C:' + '/'.repeat(n), ' ' + ':'.repeat(n), ' ' + 'é.'.repeat(n / 2) + '@x'];
  const started = Date.now();
  for (const s of shapes) scanString(s);
  assert.ok(Date.now() - started < 5000, 'adversarial scan took ' + (Date.now() - started) + ' ms');
});
