import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, cpSync, rmSync, readdirSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { verifyReleaseReceipt } from '../scripts/lib/ustar.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const sha = b => createHash('sha256').update(b).digest('hex');
const run = (cwd, cmd, args) => { const p = spawnSync(cmd, args, { cwd, encoding: 'utf8', env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' } }); assert.equal(p.status, 0, cmd + ' ' + args.join(' ') + ': ' + p.stderr); return p.stdout; };

// A throwaway Git repository holding the real pack script, its library imports and a tiny fixed file tree. pack.mjs
// derives its root from its own location, so each clean directory builds only what is committed inside it.
function cleanRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'kya-pack-'));
  mkdirSync(join(dir, 'scripts'));
  cpSync(join(root, 'scripts', 'pack.mjs'), join(dir, 'scripts', 'pack.mjs'));
  cpSync(join(root, 'scripts', 'lib'), join(dir, 'scripts', 'lib'), { recursive: true });
  cpSync(join(root, 'src'), join(dir, 'src'), { recursive: true });
  cpSync(join(root, 'profiles'), join(dir, 'profiles'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'golden-fixture', version: '0.0.0-test', files: ['README.md', 'LICENSE', 'bin/', 'docs/'] }));
  writeFileSync(join(dir, 'README.md'), 'Golden fixture readme.\n'.repeat(40));
  writeFileSync(join(dir, 'LICENSE'), 'Fixture license text.\n');
  mkdirSync(join(dir, 'bin')); writeFileSync(join(dir, 'bin', 'kya.mjs'), '#!/usr/bin/env node\nconsole.log("fixture");\n');
  mkdirSync(join(dir, 'docs')); writeFileSync(join(dir, 'docs', 'z-last.md'), 'zzz alpha beta gamma delta alpha beta gamma delta\n'); writeFileSync(join(dir, 'docs', 'a-first.md'), 'a\n');
  writeFileSync(join(dir, '.gitignore'), 'dist/\n');
  chmodSync(join(dir, 'bin', 'kya.mjs'), 0o755);
  run(dir, 'git', ['init', '-q']);
  run(dir, 'git', ['add', '--', '.']);
  run(dir, 'git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-m', 'fixture']);
  return dir;
}
function build(dir) { run(dir, process.execPath, ['scripts/pack.mjs']); return readFileSync(join(dir, 'dist', 'golden-fixture-0.0.0-test.tgz')); }

test('pack builds the release archive twice in clean directories with byte identical output', () => {
  const a = cleanRepo(), b = cleanRepo();
  try {
    const x = build(a), y = build(b);
    assert.ok(x.equals(y), 'archives differ: ' + sha(x) + ' vs ' + sha(y));
    assert.ok(x.equals(build(a)), 'a second build in the same directory differs');
    assert.equal(JSON.parse(readFileSync(join(a, 'dist', 'release-receipt.json'), 'utf8')).archiveSha256, sha(x));
  } finally { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); }
});

test('pack golden archive over a tiny fixed file tree pins the exact bytes', () => {
  const dir = cleanRepo();
  try {
    const archive = build(dir), tar = gunzipSync(archive);
    assert.equal(archive.subarray(0, 10).toString('hex'), '1f8b08000000000000ff');
    assert.equal(sha(tar), '1188b06a2ec6888dbcf667abb89bd1203d4e55d0c0a5765cb2cb51f7cad40e12');
    assert.equal(sha(archive), 'b3bfbe95b065b24b3666f94fe27fdd08516f6f78284cc34da0ed114156f30794');
    const receipt = JSON.parse(readFileSync(join(dir, 'dist', 'release-receipt.json'), 'utf8'));
    assert.deepEqual(receipt.inventory.map(f => f.path), ['LICENSE', 'README.md', 'bin/kya.mjs', 'docs/a-first.md', 'docs/z-last.md', 'package.json']);
    assert.equal(verifyReleaseReceipt(receipt, archive, { bindPackage: true }).files, 6);
    assert.deepEqual(readdirSync(join(dir, 'dist')).sort(), ['golden-fixture-0.0.0-test.tgz', 'release-receipt.json']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('pack source does not call node zlib gzip so the archive bytes do not depend on the build of zlib', () => {
  const src = readFileSync(join(root, 'scripts', 'pack.mjs'), 'utf8');
  assert.equal(/gzipSync|createGzip|node:zlib/.test(src), false);
  assert.match(src, /gzipDeterministic/);
});
