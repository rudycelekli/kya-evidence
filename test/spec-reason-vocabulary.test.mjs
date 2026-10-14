import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8');
const spec = read('../docs/SPECIFICATION.md');
const section = spec.split('### Currency result layout and reason vocabulary')[1].split('## Research replay and branching')[0];
const assessSource = read('../src/assessment/application/assess.mjs');
const currencySource = read('../src/assessment/application/currency.mjs');
const validationSource = read('../src/identity/domain/services/validation.mjs');
const ticks = text => [...text.matchAll(/`([^`]+)`/g)].map(m => m[1]);

test('the specification lists every rejected evidence reason the reference emits', () => {
  const paragraph = section.split('Reasons for `rejectedEvidence` entries')[1].split('\n\n')[0];
  const reasons = ticks(paragraph).filter(t => /^[A-Z]/.test(t));
  assert.ok(reasons.length === 22);
  for (const reason of reasons) assert.ok(assessSource.includes(`'${reason}'`), `rejected reason not in reference: ${reason}`);
  const loop = assessSource.split('try {\n      insist(!capturedEvidence')[1].split('} catch (err) { reject(')[0];
  const emitted = [...loop.matchAll(/insist\([^;]*?,\s*'([^']+)'\)/g)].map(m => m[1]);
  assert.ok(emitted.length >= 16);
  for (const reason of emitted) assert.ok(reasons.includes(reason), `reference reason missing from the specification: ${reason}`);
});

test('the specification lists every ignored incident reason the reference emits', () => {
  const paragraph = section.split('Reasons for `incidents.ignored` entries')[1].split('\n\n')[0];
  const reasons = ticks(paragraph).map(r => r.replace(/ <detail>$/, '').replace(/^Invalid incident record: ?$/, 'Invalid incident record: '));
  const emitted = [...currencySource.matchAll(/(?:skip|reason:)\('?([A-Z][^'`]+?)'\)|reason:'([A-Z][^']+)'/g)].map(m => m[1] ?? m[2]);
  assert.ok(emitted.length >= 12);
  for (const reason of emitted) assert.ok(reasons.some(r => r.startsWith(reason.replace(/: $/, ''))), `incident reason missing from the specification: ${reason}`);
  for (const reason of reasons) assert.ok(currencySource.includes(reason.replace(/^Invalid incident record:?\s?.*/, 'Invalid incident record')), `incident reason not in reference: ${reason}`);
});

test('the specification names every member and trigger of the currency result in order', () => {
  const members = ['schema', 'assessmentDigest', 'checkedAt', 'current', 'reliable', 'action', 'triggers', 'incidents', 'authenticated', 'limits'];
  const returned = 'schema:' + currencySource.split('return {\n    schema:')[1].split('\n  };')[0];
  let last = -1;
  for (const m of members) {
    const at = section.indexOf('`' + m + '`');
    assert.ok(at > last, `member ${m} missing or out of order in the specification`);
    last = at;
    assert.ok(returned.includes(m), `member ${m} not returned by the reference`);
  }
  const order = [...currencySource.matchAll(/fire\('([a-z-]+)'/g)].map(m => m[1]);
  assert.ok(section.includes('Trigger firing order is: ' + order.map(o => '`' + o + '`').join(', ')));
});

test('the specification states the identifier text hash and timestamp grammars the validators enforce', () => {
  assert.ok(validationSource.includes('[A-Za-z0-9][A-Za-z0-9:._/-]*'));
  assert.ok(section.includes('`[A-Za-z0-9][A-Za-z0-9:._/-]*`'));
  assert.ok(validationSource.includes('{64}') && section.includes('64 lowercase hexadecimal'));
  assert.ok(validationSource.includes('T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z') && section.includes('YYYY-MM-DDTHH:MM:SS.mmmZ'));
});
