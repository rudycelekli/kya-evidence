import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const BAD_FLAG = ['bin/kya.mjs', 'scripts/kya-check.mjs', 'scripts/kya-policy-init.mjs', 'scripts/privacy-scan.mjs', 'scripts/run-vectors.mjs', 'scripts/sbom.mjs'];
const CHECK = ['scripts/world-class-status.mjs', 'scripts/assessment-vectors.mjs', 'scripts/requirements.mjs', 'scripts/profile-registry.mjs'];

function viaLink(entry, args) {
  const dir = mkdtempSync(join(tmpdir(), 'kya-link-'));
  try {
    const link = join(dir, 'linked.mjs');
    symlinkSync(join(root, entry), link);
    return {
      direct: spawnSync(process.execPath, [join(root, entry), ...args], { encoding: 'utf8' }),
      linked: spawnSync(process.execPath, [link, ...args], { encoding: 'utf8' })
    };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('symlinked entries run main and fail on a bad flag', () => {
  for (const entry of BAD_FLAG) {
    const { direct, linked } = viaLink(entry, ['--no-such-flag-zz']);
    assert.notEqual(direct.status, 0, entry + ': direct run must fail on a bad flag');
    assert.equal(linked.status, direct.status, entry + ': symlinked run must behave like the direct run');
    assert.ok(linked.stderr.length > 0, entry + ': symlinked run must write to stderr');
  }
});

test('symlinked entries run main and print the same check output', () => {
  for (const entry of CHECK) {
    const { direct, linked } = viaLink(entry, ['--check']);
    assert.ok(direct.stdout.length > 0, entry + ': direct run prints output');
    assert.equal(linked.status, direct.status, entry + ': exit status matches');
    assert.equal(linked.stdout, direct.stdout, entry + ': symlinked run must print the same output as the direct run');
  }
});
