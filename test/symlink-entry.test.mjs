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

for (const entry of BAD_FLAG) {
  test(`symlinked entry runs main and fails on bad flag: ${entry}`, () => {
    const { direct, linked } = viaLink(entry, ['--no-such-flag-zz']);
    assert.notEqual(direct.status, 0, 'direct run must fail on a bad flag');
    assert.equal(linked.status, direct.status, 'symlinked run must behave like the direct run');
    assert.ok(linked.stderr.length > 0, 'symlinked run must write to stderr');
  });
}

for (const entry of CHECK) {
  test(`symlinked entry runs main and prints check output: ${entry}`, () => {
    const { direct, linked } = viaLink(entry, ['--check']);
    assert.ok(direct.stdout.length > 0);
    assert.equal(linked.status, direct.status);
    assert.equal(linked.stdout, direct.stdout, 'symlinked run must print the same output as the direct run');
  });
}
