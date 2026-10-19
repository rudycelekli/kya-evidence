import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scanString, scanContent, scanPaths } from '../scripts/privacy-scan.mjs';

// Second, independent killers for the privacy scan echo gates. The first killers assert that a few raw values never appear;
// these use other structural fields, line oriented input, the exact shape mask and the command line in both formats.
const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/privacy-scan.mjs');
const dir = mkdtempSync(join(tmpdir(), 'kya-redundancy-privacy-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
let counter = 0;
const put = (name, text) => { const p = join(dir, (counter++) + '-' + name); writeFileSync(p, text); return p; };
const cli = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', timeout: 20000 });

// Assembled at run time so this file contains no scannable literals.
const EMAIL = ['mara.lindqvist', 'mail.test'].join('@') + '.org';
const SSN = ['219', '09', '9999'].join('-');
const PHONE = '+44 7700 900123';
const CARD = '5500' + ' 0000' + ' 0000' + ' 0004';
const SECRET = 'quarterly escalation notes about customer Brightwater';

test('exact shape masks replace letters and digits with class markers for several rules', () => {
  const only = s => { const f = scanString(s); assert.equal(f.length, 1, s); return f[0]; };
  assert.equal(only(SSN).redacted, '[REDACTED 999-99-9999]');
  assert.equal(only(CARD).redacted, '[REDACTED 9999_9999_9999_9999]');
  assert.equal(only(PHONE).redacted, '[REDACTED +99_9999_999999]');
  assert.equal(only(EMAIL).redacted, '[REDACTED aaaa.aaaaaaaaa@aaaa.aaaa...]');
  for (const s of [SSN, CARD, PHONE, EMAIL, '203.0.113.77']) assert.doesNotMatch(only(s).redacted, /[0-8]/, s);
  assert.match(only('call ' + '(415) 555-0199').redacted, /^\[REDACTED \(999\)_999-9999\]$/);
});

test('long matches are truncated in the mask and carry only the numeral class marker', () => {
  const long = 'GB82 WEST 1234 5698 7654 32';
  const f = scanString(long);
  assert.equal(f.length, 1);
  assert.equal(f[0].redacted, '[REDACTED AA99_AAAA_9999_9999_9999...]');
  assert.doesNotMatch(f[0].redacted, /[0-8]/);
});

test('digest fields in line oriented files never echo a malformed value in json or text output', () => {
  const lines = [{ evidenceBundleDigest: SECRET }, { sha256: SECRET }, { digest: SECRET }, { nested: { artifactDigest: SECRET } }].map(o => JSON.stringify(o)).join('\n') + '\n';
  const file = put('digests.jsonl', lines);
  const r = scanContent(lines, '.jsonl');
  assert.equal(r.findings.filter(f => f.rule === 'digest-field-malformed').length, 4);
  assert.ok(!JSON.stringify(r).includes('Brightwater') && !JSON.stringify(r).includes('quarterly'));
  for (const format of ['json', 'text']) {
    const p = cli('--format', format, file);
    assert.equal(p.status, 1, p.stderr);
    for (const word of ['Brightwater', 'quarterly', 'escalation']) assert.ok(!p.stdout.includes(word) && !p.stderr.includes(word), format + ' echoed ' + word);
    assert.match(p.stdout, /digest-field-malformed/);
  }
});

test('non ascii and spaced object keys never appear in finding paths', () => {
  const doc = { 'Mara Lindqvist': EMAIL, 'Müller family': PHONE, ['x'.repeat(80)]: SSN, nested: { 'Customer Brightwater': CARD } };
  const text = JSON.stringify(doc);
  const r = scanContent(text, '.json');
  assert.ok(r.findings.length >= 4);
  const out = JSON.stringify(r);
  for (const word of ['Mara', 'Lindqvist', 'ller family', 'Brightwater', 'x'.repeat(80)]) assert.ok(!out.includes(word), 'path echoed ' + word);
  assert.ok(r.findings.every(f => /^\$\.(\[key:\d+\]|nested\.\[key:\d+\]|nested)/.test(f.path)), JSON.stringify(r.findings.map(f => f.path)));
  const file = put('keys.json', text);
  const p = cli('--format', 'text', file);
  assert.equal(p.status, 1);
  assert.ok(!p.stdout.includes('Lindqvist') && !p.stdout.includes('Brightwater'));
});

test('object keys that look like personal data are replaced by a position marker', async () => {
  const doc = { [PHONE]: 'x', [SSN]: 'y', safeKey: { [EMAIL]: 'z' } };
  const file = put('pii-keys.json', JSON.stringify(doc));
  const report = await scanPaths([file], { cwd: dir });
  const out = JSON.stringify(report);
  for (const raw of [PHONE, SSN, EMAIL, 'mara.lindqvist']) assert.ok(!out.includes(raw), 'echoed ' + raw);
  assert.ok(out.includes('[key:'));
  assert.ok(report.findings.some(f => f.path.startsWith('$.safeKey.')));
});

test('narrative text in evidence and receipt records is withheld from every output form', () => {
  const docs = [
    { schema: 'kya.evidence/v1', summary: SECRET },
    { schema: 'kya.receipt/v1', reason: SECRET, inner: { transcript: SECRET } },
    { schema: 'kya.incident/v1', details: [{ comment: SECRET }, { body: SECRET }] }
  ];
  docs.forEach((doc, i) => {
    const text = JSON.stringify(doc);
    const r = scanContent(text, '.json');
    assert.ok(r.findings.some(f => f.rule === 'digest-only-free-text'), JSON.stringify(doc));
    for (const f of r.findings) assert.ok(!/Brightwater|quarterly|escalation/.test(f.redacted + f.path), 'finding echoed text');
    const p = cli('--format', 'json', put('narrative-' + i + '.json', text));
    assert.equal(p.status, 1, p.stderr);
    assert.ok(!/Brightwater|quarterly|escalation/.test(p.stdout + p.stderr), 'cli echoed text');
  });
  const plain = scanContent(JSON.stringify({ schema: 'kya.manifest/v1', summary: SECRET }), '.json');
  assert.ok(!plain.findings.some(f => f.rule === 'digest-only-free-text'));
});

test('malformed coded identifiers are masked in line oriented output', () => {
  const text = [{ runId: SECRET }, { agent: { id: SECRET } }, { ref: SECRET }].map(o => JSON.stringify(o)).join('\n');
  const r = scanContent(text, '.ndjson');
  assert.equal(r.findings.filter(f => f.rule === 'coded-field-free-text').length, 3);
  assert.ok(!JSON.stringify(r).includes('Brightwater'));
  assert.ok(r.findings.every(f => /^\[REDACTED [Aa_ ]/.test(f.redacted) || f.redacted.startsWith('[REDACTED')));
});
