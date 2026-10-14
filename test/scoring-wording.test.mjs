import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { BLOCKER_CODES } from '../src/index.mjs';

const doc = readFileSync(new URL('../docs/SCORING.md', import.meta.url), 'utf8');
const source = readFileSync(new URL('../src/assessment/application/assess.mjs', import.meta.url), 'utf8');
const section = doc.split('### Blocker wording in the reference')[1].split('## Mandatory minimums')[0];
const rows = [...section.matchAll(/^\| `([A-Z_]+)` \| `(.+)` \|$/gm)].map(m => ({ code: m[1], text: m[2] }));

test('SCORING.md documents the reference wording for every blocker code exactly once', () => {
  assert.deepEqual(rows.map(r => r.code).sort(), [...BLOCKER_CODES].sort());
});

test('every documented blocker wording is the string the reference emits', () => {
  for (const { code, text } of rows) {
    const forms = ['${c.id}', '${m.checkId}'].map(id => text
      .replace('<id>', id)
      .replace('<minimum>', '${m.minimum}')
      .replace('<status>', '${c.status}'));
    const quoted = forms.some(f => source.includes(f));
    assert.ok(quoted, `wording for ${code} is not in the reference source`);
  }
});
