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
  assert.deepEqual(rules('-----BEGIN PRIVATE KEY-----\n' + body + '\n-----END PRIVATE KEY-----'), ['private-key-material']);
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
  const salt = 'ab'.repeat(32);
  const a = commitField({ recordId: 'rec:1', field: 'contact', value: EMAIL, salt });
  const b = commitField({ recordId: 'rec:1', field: 'contact', value: EMAIL, salt });
  assert.deepEqual(a, b);
  assert.deepEqual(openField(a.commitment, a.opening), { ok: true });
  assert.ok(!JSON.stringify(a.commitment).includes('jane'));
  const fresh = commitField({ recordId: 'rec:1', field: 'contact', value: EMAIL });
  assert.notEqual(fresh.commitment.digest, a.commitment.digest);
  assert.deepEqual(openField(fresh.commitment, fresh.opening), { ok: true });
});

test('field commitment rejects a wrong value, wrong salt, other field or other record', () => {
  const salt = 'cd'.repeat(32);
  const c = commitField({ recordId: 'rec:1', field: 'contact', value: { a: 1, b: [2] }, salt });
  assert.equal(openField(c.commitment, { salt, value: { b: [2], a: 1 } }).ok, true);
  assert.equal(openField(c.commitment, { salt, value: { a: 2, b: [2] } }).ok, false);
  assert.equal(openField(c.commitment, { salt: 'ce'.repeat(32), value: c.opening.value }).ok, false);
  assert.equal(openField({ ...c.commitment, field: 'other' }, c.opening).ok, false);
  assert.equal(openField({ ...c.commitment, recordId: 'rec:2' }, c.opening).ok, false);
  assert.equal(openField({ ...c.commitment, digest: '0'.repeat(64) }, c.opening).ok, false);
});

test('field commitment is domain separated by record ID and field name with unambiguous framing', () => {
  const salt = 'ef'.repeat(32);
  const d = (recordId, field, value) => commitField({ recordId, field, value, salt }).commitment.digest;
  const set = new Set([d('a:1', 'b', 'v'), d('a:1', 'c', 'v'), d('a:2', 'b', 'v'), d('a', '1:b', 'v'), d('a:1', 'b', 'w')]);
  assert.equal(set.size, 5);
  assert.notEqual(d('ab', 'c', 'v'), d('a', 'bc', 'v'));
});

test('field commitment refuses weak salts, bad names and unsupported values and openField never throws', () => {
  assert.throws(() => commitField({ recordId: 'r:1', field: 'f', value: 1, salt: 'aa' }), /Salt/);
  assert.throws(() => commitField({ recordId: 'r:1', field: 'f', value: 1, salt: 'AB'.repeat(16) }), /Salt/);
  assert.throws(() => commitField({ recordId: 'has space', field: 'f', value: 1 }), /recordId/);
  assert.throws(() => commitField({ recordId: 'r:1', field: '', value: 1 }), /field/);
  assert.throws(() => commitField({ recordId: 'r:1', field: 'f', value: undefined }));
  for (const bad of [undefined, null, 1, {}, { schema: 'x' }]) assert.equal(openField(bad, { salt: 'ab'.repeat(32), value: 1 }).ok, false);
  const c = commitField({ recordId: 'r:1', field: 'f', value: 1 });
  for (const bad of [undefined, null, 'x', {}, { salt: 'zz', value: 1 }]) assert.equal(openField(c.commitment, bad).ok, false);
});
