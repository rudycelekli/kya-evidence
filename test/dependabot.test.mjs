import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const file = join(root, '.github/dependabot.yml');

test('dependabot config exists and updates github actions weekly', () => {
  assert.ok(existsSync(file), '.github/dependabot.yml is missing');
  const src = readFileSync(file, 'utf8');
  const code = src.split('\n').filter(l => !/^\s*#/.test(l)).join('\n');
  assert.match(code, /^version:\s*2\s*$/m);
  assert.match(code, /package-ecosystem:\s*github-actions\s*$/m);
  assert.match(code, /directory:\s*"\/"\s*$/m);
  assert.match(code, /interval:\s*weekly\s*$/m);
  assert.ok(!/auto-?merge/i.test(code), 'updates must not merge themselves');
});
