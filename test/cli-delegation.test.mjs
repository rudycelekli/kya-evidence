import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const bin = fileURLToPath(new URL('../bin/kya.mjs', import.meta.url));
const run = args => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', timeout: 20000 });

test('the kya command delegates check, policy-init, campaign and vc to their scripts and passes their output through', () => {
  for (const [command, marker] of [['check', 'kya-check:'], ['policy-init', 'kya-policy-init:'], ['campaign', 'kya-campaign:'], ['vc', 'kya-vc:'], ['score', 'kya-score:']]) {
    const r = run([command, '--help']);
    assert.equal(r.status, 0, `${command}: ${r.stderr}`);
    assert.ok((r.stdout + r.stderr).includes(marker), `${command} help should come from its own script`);
  }
});

test('delegated commands pass arguments and exit codes through, and unknown commands still fail', () => {
  const failing = run(['check']);
  assert.notEqual(failing.status, 0);
  assert.match(failing.stderr + failing.stdout, /kya-check/);
  const unknown = run(['definitely-not-a-command']);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /Unknown command/);
  assert.match(run(['--help']).stdout, /kya check/);
});
