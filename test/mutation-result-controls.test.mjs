import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('mutation result grader detects TODO status and population admission regressions', () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const p = spawnSync(process.execPath, ['scripts/mutation-result-mutations.mjs'], {
    cwd: root, encoding: 'utf8', timeout: 60000, maxBuffer: 1048576
  });
  assert.equal(p.error, undefined);
  assert.equal(p.signal, null);
  assert.equal(p.status, 0, p.stderr + p.stdout);
  const report = JSON.parse(p.stdout);
  assert.equal(report.baseline.tests, 9);
  assert.equal(report.baseline.pass, 9);
  assert.equal(report.allKilled, true);
  assert.equal(report.controls.length, 3);
  for (const control of report.controls) {
    assert.equal(control.killed, true);
    assert.equal(control.tests, 9);
    assert.equal(control.exitCode, 1);
    assert.ok(control.fail > 0);
  }
});
