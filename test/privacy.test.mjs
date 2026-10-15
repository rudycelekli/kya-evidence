import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scanString, scanContent, scanPaths } from '../scripts/privacy-scan.mjs';
import { commitField, openField } from '../src/privacy/index.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/privacy-scan.mjs');
const rules = s => scanString(s).map(f => f.rule);
const tmp = () => mkdtempSync(join(tmpdir(), 'kya-privacy-'));

// Values are assembled at run time so this file does not itself contain scannable literals.
const EMAIL = ['jane.doe', 'mail.test'].join('@') + '.org';
const CARD = '4111' + ' 1111' + ' 1111' + ' 1111';
const IBAN = 'GB82' + ' WEST' + ' 1234' + ' 5698' + ' 7654' + ' 32';
const SSN = ['123', '45', '6789'].join('-');
const IP4 = [203, 0, 113, 77].join('.');
const IP6 = '2001:db8:85a3:0:0:8a2e:370:7334';
const HOME = '/Users/' + 'janedoe' + '/Documents/x';
const PHONE = '+1 415 555 0132';
const SALT = Array.from({ length: 32 }, (_, i) => ((i * 37 + 11) % 256).toString(16).padStart(2, '0')).join('');
const SALT2 = Array.from({ length: 32 }, (_, i) => ((i * 53 + 7) % 256).toString(16).padStart(2, '0')).join('');

test('privacy scan flags an email address and a phone number', () => {
  assert.deepEqual(rules('contact ' + EMAIL + ' please'), ['email']);
  assert.deepEqual(rules('call ' + PHONE), ['phone']);
  assert.deepEqual(rules('(415) 555-0132'), ['phone']);
});

test('privacy scan flags IBAN and card numbers only when the check digits pass', () => {
  assert.deepEqual(rules(IBAN), ['iban']);
  assert.ok(!rules(IBAN.replace('32', '33')).includes('iban'));
  assert.deepEqual(rules(CARD), ['card']);
  assert.ok(!rules('4111 1111 1111 1112').includes('card'));
  assert.deepEqual(rules('1760000000000000'), []);
});

test('privacy scan flags national identifier shapes with their check rules', () => {
  assert.deepEqual(rules(SSN), ['national-id-us-ssn']);
  assert.ok(!rules('666-45-6789').includes('national-id-us-ssn'));
  assert.deepEqual(rules('AB 12 34 56 C'), ['national-id-uk-nino']);
  assert.deepEqual(rules('12345678Z'), ['national-id-es-dni-nie']);
  assert.ok(!rules('12345678A').includes('national-id-es-dni-nie'));
  assert.ok(!rules('2 84 12 75 123 456 ' + '11').includes('national-id-fr-insee'));
  assert.ok(!rules('2234 5678 9012').includes('national-id-in-aadhaar'));
});

test('privacy scan flags IP addresses and home directory paths', () => {
  assert.deepEqual(rules('host ' + IP4), ['ipv4']);
  assert.deepEqual(rules('host ' + IP6), ['ipv6']);
  assert.deepEqual(rules('::1'), ['ipv6']);
  assert.deepEqual(rules(HOME), ['home-path']);
  assert.deepEqual(rules('C:\\Users\\janedoe\\file'), ['home-path']);
  assert.deepEqual(rules('/home/janedoe/.ssh'), ['home-path']);
});

test('privacy scan flags a PEM private key block but not a public key', () => {
  const body = 'A'.repeat(64);
  assert.deepEqual(rules('-----BEGIN ' + 'PRIVATE KEY-----\n' + body + '\n-----END PRIVATE KEY-----'), ['private-key-material']);
  assert.deepEqual(rules('-----BEGIN PUBLIC KEY-----\n' + body + '\n-----END PUBLIC KEY-----'), []);
});

test('privacy scan does not flag timestamps, versions, digests, base64 or coded identifiers', () => {
  const clean = ['2026-10-13T12:00:30.000Z', '1.0.0', '0.1.0-alpha.3', 'a'.repeat(64), '0'.repeat(64), '1'.repeat(64), 'fixture:careful', 'controller:synthetic',
    'kya.incident/v1', '12:30:00', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/==', 'read', 'external-message', '1760000000000', '2026-10-13'];
  for (const s of clean) assert.deepEqual(rules(s), [], s);
});

test('privacy scan reports structural violations in coded and digest-only fields', () => {
  const record = { schema: 'kya.incident/v1', id: 'inc 1 with spaces', subjectDigest: 'ABC', kind: 'report', note: 'free narrative here', detailsDigest: 'a'.repeat(64) };
  const r = scanContent(JSON.stringify(record));
  assert.deepEqual(r.findings.map(f => f.rule).sort(), ['coded-field-free-text', 'digest-field-malformed', 'digest-only-free-text']);
  assert.deepEqual(scanContent(JSON.stringify(record), '.json', { rules: 'pii' }).findings, []);
});

test('privacy scan walks nested structures and reports JSON paths', () => {
  const doc = { a: [{ b: { c: 'x ' + EMAIL } }], d: 'fine' };
  const f = scanContent(JSON.stringify(doc)).findings;
  assert.equal(f.length, 1);
  assert.equal(f[0].path, '$.a[0].b.c');
  assert.equal(f[0].rule, 'email');
});

test('privacy scan never echoes a raw matched value in any output form', async () => {
  const dir = tmp();
  const doc = { schema: 'kya.manifest/v1', agent: { id: 'a:1', name: 'x ' + EMAIL + ' ' + PHONE + ' ' + CARD }, note: IBAN + ' ' + SSN + ' ' + IP4 + ' ' + IP6 + ' ' + HOME,
    [EMAIL]: 'key leak', runId: 'bad value ' + SSN };
  writeFileSync(join(dir, 'a.json'), JSON.stringify(doc));
  const report = await scanPaths([dir], { cwd: dir });
  assert.ok(report.findings.length >= 8);
  const out = JSON.stringify(report);
  for (const secret of [EMAIL, PHONE, CARD, CARD.replaceAll(' ', ''), IBAN, IBAN.replaceAll(' ', ''), SSN, IP4, IP6, HOME, 'janedoe', 'jane.doe', 'bad value']) assert.ok(!out.includes(secret), 'echoed ' + secret);
  const cli = spawnSync(process.execPath, [script, '--format', 'text', dir], { encoding: 'utf8' });
  for (const secret of [EMAIL, CARD, IBAN, SSN, IP4, 'janedoe', 'jane.doe']) assert.ok(!cli.stdout.includes(secret) && !cli.stderr.includes(secret), 'cli echoed ' + secret);
  assert.ok(out.includes('[key:'));
});

test('privacy scan exit code is 1 on findings, 0 when clean and 2 on usage errors', () => {
  const dir = tmp();
  writeFileSync(join(dir, 'ok.json'), JSON.stringify({ id: 'x:1', scopeId: 'synthetic:core' }));
  const clean = spawnSync(process.execPath, [script, join(dir, 'ok.json')], { encoding: 'utf8' });
  assert.equal(clean.status, 0);
  assert.equal(JSON.parse(clean.stdout).clean, true);
  writeFileSync(join(dir, 'bad.json'), JSON.stringify({ x: EMAIL }));
  assert.equal(spawnSync(process.execPath, [script, dir], { encoding: 'utf8' }).status, 1);
  assert.equal(spawnSync(process.execPath, [script], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [script, join(dir, 'missing.json')], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [script, '--bogus', dir], { encoding: 'utf8' }).status, 2);
});

test('privacy scan report is byte-stable across runs and input ordering', async () => {
  const dir = tmp();
  mkdirSync(join(dir, 'sub'));
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ x: EMAIL, y: IP4 }));
  writeFileSync(join(dir, 'sub', 'a.json'), JSON.stringify({ z: SSN }));
  const one = JSON.stringify(await scanPaths([join(dir, 'b.json'), join(dir, 'sub')], { cwd: dir }));
  const two = JSON.stringify(await scanPaths([join(dir, 'sub'), join(dir, 'b.json')], { cwd: dir }));
  assert.equal(one, two);
  assert.ok(!one.includes(dir), 'absolute paths must not appear');
});

test('privacy scan scans jsonl lines, falls back to text for non-JSON and refuses binary and symlinks loudly', async () => {
  const dir = tmp();
  writeFileSync(join(dir, 'l.jsonl'), JSON.stringify({ ok: 1 }) + '\n' + JSON.stringify({ m: EMAIL }) + '\nnot json ' + IP4 + '\n');
  writeFileSync(join(dir, 'broken.json'), '{ not valid ' + IP4);
  writeFileSync(join(dir, 'bin.json'), Buffer.from([0x7b, 0x00, 0x7d]));
  symlinkSync(join(dir, 'l.jsonl'), join(dir, 'link.json'));
  const r = await scanPaths([dir], { cwd: dir });
  assert.deepEqual(r.findings.map(f => f.file + ' ' + f.path + ' ' + f.rule).sort(),
    ['broken.json line:1 ipv4', 'l.jsonl line:2$.m email', 'l.jsonl line:3 ipv4']);
  assert.equal(r.errors.length, 2);
  assert.equal(r.clean, false);
});

test('repository example artifacts and golden fixtures scan clean', async () => {
  const strict = await scanPaths([join(root, 'examples'), join(root, 'test/fixtures'), join(root, 'profiles'), join(root, 'policies'), join(root, 'suites')], { cwd: root });
  assert.ok(strict.summary.files >= 5);
  assert.deepEqual(strict.findings, []);
  assert.deepEqual(strict.errors, []);
  const golden = await scanPaths([join(root, 'evidence'), join(root, 'interop'), join(root, 'schemas')], { cwd: root, rules: 'pii' });
  assert.ok(golden.summary.files >= 5);
  assert.deepEqual(golden.findings, []);
});

test('golden vector files raise only structural findings from their deliberately malformed refusal cases', async () => {
  const r = await scanPaths([join(root, 'evidence/golden-vectors.json'), join(root, 'evidence/assessment-vectors.json')], { cwd: root });
  const rulesSeen = r.findings.map(f => f.rule);
  assert.ok(rulesSeen.length > 0 && rulesSeen.every(x => ['digest-field-malformed', 'coded-field-free-text', 'digest-only-free-text'].includes(x)), rulesSeen.join(','));
});

test('privacy scan documentation states false positives and false negatives and the report carries them', async () => {
  const doc = readFileSync(join(root, 'docs/PRIVACY.md'), 'utf8');
  assert.ok(/False positives/.test(doc) && /False negatives/.test(doc) && /clean scan is not evidence/.test(doc));
  const r = await scanPaths([join(root, 'examples')], { cwd: root });
  assert.ok(r.limitations.length >= 3 && r.limitations.some(x => /False negatives/.test(x)));
});

test('field commitment opens with the right salt and value and is deterministic for a fixed salt', () => {
  const masterSalt = SALT;
  const a = commitField({ recordId: 'rec:1', field: 'contact', value: EMAIL, masterSalt });
  const b = commitField({ recordId: 'rec:1', field: 'contact', value: EMAIL, masterSalt });
  assert.deepEqual(a, b);
  assert.deepEqual(openField(a.commitment, a.opening), { ok: true });
  assert.ok(!JSON.stringify(a.commitment).includes('jane'));
  const fresh = commitField({ recordId: 'rec:1', field: 'contact', value: EMAIL });
  assert.notEqual(fresh.commitment.digest, a.commitment.digest);
  assert.deepEqual(openField(fresh.commitment, fresh.opening), { ok: true });
});

test('field commitment rejects a wrong value, wrong salt, other field or other record', () => {
  const c = commitField({ recordId: 'rec:1', field: 'contact', value: { a: 1, b: [2] }, masterSalt: SALT });
  const salt = c.opening.salt;
  assert.equal(openField(c.commitment, { salt, value: { b: [2], a: 1 } }).ok, true);
  assert.equal(openField(c.commitment, { salt, value: { a: 2, b: [2] } }).ok, false);
  assert.equal(openField(c.commitment, { salt: SALT2, value: c.opening.value }).ok, false);
  assert.equal(openField({ ...c.commitment, field: 'other' }, c.opening).ok, false);
  assert.equal(openField({ ...c.commitment, recordId: 'rec:2' }, c.opening).ok, false);
  assert.equal(openField({ ...c.commitment, digest: '0'.repeat(64) }, c.opening).ok, false);
});

test('field commitment is domain separated by record ID and field name with unambiguous framing', () => {
  const d = (recordId, field, value) => commitField({ recordId, field, value, masterSalt: SALT }).commitment.digest;
  const set = new Set([d('a:1', 'b', 'v'), d('a:1', 'c', 'v'), d('a:2', 'b', 'v'), d('a', '1:b', 'v'), d('a:1', 'b', 'w')]);
  assert.equal(set.size, 5);
  assert.notEqual(d('ab', 'c', 'v'), d('a', 'bc', 'v'));
});

test('field commitment refuses weak salts, bad names and unsupported values and openField never throws', () => {
  assert.throws(() => commitField({ recordId: 'r:1', field: 'f', value: 1, masterSalt: 'aa' }), /Salt/);
  assert.throws(() => commitField({ recordId: 'r:1', field: 'f', value: 1, masterSalt: 'AB'.repeat(32) }), /Salt/);
  assert.throws(() => commitField({ recordId: 'has space', field: 'f', value: 1 }), /recordId/);
  assert.throws(() => commitField({ recordId: 'r:1', field: '', value: 1 }), /field/);
  assert.throws(() => commitField({ recordId: 'r:1', field: 'f', value: undefined }));
  for (const bad of [undefined, null, 1, {}, { schema: 'x' }]) assert.equal(openField(bad, { salt: 'ab'.repeat(32), value: 1 }).ok, false);
  const c = commitField({ recordId: 'r:1', field: 'f', value: 1 });
  for (const bad of [undefined, null, 'x', {}, { salt: 'zz', value: 1 }]) assert.equal(openField(c.commitment, bad).ok, false);
});

test('field commitment derives a distinct salt per field and an opened field does not leak the master', () => {
  const a = commitField({ recordId: 'r:1', field: 'a', value: 'x', masterSalt: SALT });
  const b = commitField({ recordId: 'r:1', field: 'b', value: 'x', masterSalt: SALT });
  assert.notEqual(a.opening.salt, b.opening.salt);
  assert.notEqual(a.opening.salt, SALT);
  assert.notEqual(a.commitment.digest, b.commitment.digest);
  assert.equal(openField(b.commitment, { salt: a.opening.salt, value: 'x' }).ok, false);
});

test('field commitment refuses constant salts, short salts, a public salt parameter and null input', () => {
  for (const bad of ['00'.repeat(32), 'ff'.repeat(32), 'ab'.repeat(32), SALT.slice(0, 62), SALT + '00', 'ab'.repeat(16)])
    assert.throws(() => commitField({ recordId: 'r:1', field: 'f', value: 1, masterSalt: bad }), /Salt/);
  assert.throws(() => commitField({ recordId: 'r:1', field: 'f', value: 1, salt: SALT }), /Salt/);
  assert.throws(() => commitField(null), /commitField needs an object/);
  assert.throws(() => commitField(), /commitField needs an object/);
  const c = commitField({ recordId: 'r:1', field: 'f', value: 1, masterSalt: SALT });
  assert.equal(openField(c.commitment, { salt: '00'.repeat(32), value: 1 }).ok, false);
  assert.equal(openField(c.commitment, { salt: c.opening.salt + '00', value: 1 }).ok, false);
  assert.equal(openField(c.commitment, { salt: c.opening.salt.slice(0, 62), value: 1 }).ok, false);
});

// ---- adversarial review fixes ----
test('privacy scan flags long home paths, slugs and hyphenated card or SSN strings', () => {
  assert.deepEqual(rules('/Users/' + 'janedoe/' + 'Documents/' + 'a'.repeat(30)), ['home-path']);
  assert.deepEqual(rules('export_for_user_ssn_' + SSN + '_q3_report_final'), ['national-id-us-ssn']);
  assert.deepEqual(rules('payment-4111-1111-1111-1111-for-order-12345678901'), ['card']);
  assert.deepEqual(rules('QWxhZGRpbjpvcGVuIHNlc2FtZQQWxhZGRpbjpvcGVuIHNlc2FtZQ' + 'x'.repeat(10)), []);
  assert.deepEqual(rules('A'.repeat(20) + '0123456789'.repeat(3) + 'abc/+def=='), []);
});

test('privacy scan keeps two different files with the same base name outside cwd', async () => {
  const cwd = tmp(), a = tmp(), b = tmp();
  writeFileSync(join(a, 'same.json'), JSON.stringify({ x: EMAIL }));
  writeFileSync(join(b, 'same.json'), JSON.stringify({ x: IP4 }));
  const r = await scanPaths([join(a, 'same.json'), join(b, 'same.json')], { cwd });
  assert.equal(r.scanned.length, 2);
  assert.deepEqual(r.findings.map(f => f.rule).sort(), ['email', 'ipv4']);
  assert.equal(new Set(r.scanned.map(x => x.file)).size, 2);
  assert.ok(!JSON.stringify(r).includes(a) && !JSON.stringify(r).includes(b));
  const again = await scanPaths([join(a, 'same.json'), join(a, '.', 'same.json')], { cwd });
  assert.equal(again.scanned.length, 1);
});

test('privacy scan exits 2 when nothing was scanned and normalizes extensions', () => {
  const dir = tmp();
  writeFileSync(join(dir, 'a.txt'), 'hello');
  const none = spawnSync(process.execPath, [script, dir], { encoding: 'utf8' });
  assert.equal(none.status, 2);
  assert.equal(JSON.parse(none.stdout).clean, false);
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ x: EMAIL }));
  assert.equal(spawnSync(process.execPath, [script, '--ext', 'json', dir], { encoding: 'utf8' }).status, 1);
  assert.equal(spawnSync(process.execPath, [script, '--ext', 'txt', dir], { encoding: 'utf8' }).status, 0);
  assert.equal(spawnSync(process.execPath, [script, '--ext', 'a/b', dir], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [script, join(dir, 'nothing-here')], { encoding: 'utf8' }).status, 2);
});

test('privacy scan scans numbers in JSON and flags bare identifiers under identifying keys', () => {
  const r = scanContent(JSON.stringify({ card: 4111111111111111, ssn: 123456789, phone: 4155550132, count: 123456789, list: [4111111111111111] })).findings;
  assert.deepEqual(r.map(f => f.path + ' ' + f.rule).sort(), ['$.card card', '$.list[0] card', '$.phone numeric-identifier-by-key', '$.ssn numeric-identifier-by-key']);
});

test('privacy scan applies the coded-field rule to any key ending in Id', () => {
  const f = scanContent(JSON.stringify({ assessorKeyId: 'has free text', accountablePartyId: 'two words', fine: 'two words' })).findings;
  assert.deepEqual(f.map(x => x.path).sort(), ['$.accountablePartyId', '$.assessorKeyId']);
});

test('privacy scan finishes 300k character adversarial inputs within a linear time budget', () => {
  const n = 300000;
  const inputs = ['-----BEGIN X-----\n'.repeat(Math.ceil(n / 18)), ('-----BEGIN ' + 'PRIVATE KEY-----\n').repeat(Math.ceil(n / 28)), 'a@b.co '.repeat(Math.ceil(n / 7)),
    '1 '.repeat(n / 2), '1.2.3.4 '.repeat(Math.ceil(n / 8)), '/Users/a '.repeat(Math.ceil(n / 9)), 'a'.repeat(n), 'a.'.repeat(n / 2) + '@', '1-'.repeat(n / 2), '+1 (555) '.repeat(Math.ceil(n / 9)), 'a%40b.co '.repeat(Math.ceil(n / 9)), ':'.repeat(n)];
  const t0 = process.cpuUsage();
  for (const s of inputs) scanString(s);
  const cpu = process.cpuUsage(t0), total = (cpu.user + cpu.system) / 1000; // CPU time, so machine load does not flake the bound
  // A quadratic scanner needs minutes on these inputs, so a generous CPU budget still catches it without flaking on slow runners.
  assert.ok(total < 5000, 'took ' + total + ' ms');
});

test('privacy scan reports unreadable files without echoing the path and strips control characters', async () => {
  const dir = tmp();
  writeFileSync(join(dir, 'locked.json'), JSON.stringify({ x: 1 }), { mode: 0o000 });
  writeFileSync(join(dir, 'ok.json'), JSON.stringify({ x: 1 }));
  const r = await scanPaths([dir], { cwd: dir });
  const euid = typeof process.geteuid === 'function' ? process.geteuid() : 1;
  if (euid !== 0) { assert.equal(r.errors.length, 1); assert.ok(/unreadable/.test(r.errors[0].error)); assert.equal(r.errors[0].path, 'locked.json'); assert.equal(r.clean, false); }
  assert.ok(!JSON.stringify(r).includes(dir));
  const esc = scanString('/Users/' + 'jane\x1b[31mdoe\x07/x');
  assert.ok(esc.length >= 1);
  for (const f of esc) assert.ok(!/[\x00-\x1f\x7f]/.test(f.redacted), 'control char in mask');
  const bad = await scanPaths([join(dir, 'missing-dir', 'x.json')], { cwd: dir });
  assert.ok(!JSON.stringify(bad).includes(dir));
});

test('privacy scan uses the strict parser, strips a BOM and checks nested narrative fields', () => {
  assert.equal(scanContent('{"a":"x","a":"y"}').kind, 'text');
  assert.equal(scanContent('{"__proto__":{"x":1}}').kind, 'text');
  const bom = scanContent('﻿' + JSON.stringify({ x: EMAIL }));
  assert.equal(bom.kind, 'json'); assert.deepEqual(bom.findings.map(f => f.rule), ['email']);
  const nested = scanContent(JSON.stringify({ schema: 'kya.incident/v1', inner: { deeper: [{ note: 'some free text' }] } })).findings;
  assert.deepEqual(nested.map(f => f.rule), ['digest-only-free-text']);
  const jl = scanContent('﻿' + JSON.stringify({ m: EMAIL }) + '\n', '.jsonl');
  assert.deepEqual(jl.findings.map(f => f.rule), ['email']);
});

test('privacy scan flags dotted phone numbers, percent encoded and unicode emails but not version strings', () => {
  assert.deepEqual(rules('555.123.4567'), ['phone']);
  assert.deepEqual(rules('1.2.3'), []);
  assert.deepEqual(rules('10.0.19041.1234'), []);
  assert.deepEqual(rules('jane.doe%40mail' + '.test.org'), ['email']);
  assert.deepEqual(rules('jürgen.müller' + '@' + 'beispiel.de'), ['email']);
  assert.deepEqual(rules('jane.doe' + '＠' + 'mail.test.org'), ['email']);
});
