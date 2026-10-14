import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildSbom, renderSbom } from '../scripts/sbom.mjs';

const repoRoot = fileURLToPath(new URL('../', import.meta.url));
const sbomScript = fileURLToPath(new URL('../scripts/sbom.mjs', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const scratch = [];
after(() => { for (const dir of scratch) rmSync(dir, { recursive: true, force: true }); });

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' };
function git(cwd, ...args) {
  const p = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8', env: GIT_ENV });
  assert.equal(p.status, 0, p.stderr);
  return p.stdout;
}

/** A tiny committed repository with the same shape as the real one: package.json plus a frozen file list. */
function tinyRepo(packagePatch = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'kya-sbom-'));
  scratch.push(dir);
  git(dir, 'init', '-q');
  const pkg = { name: 'tiny-pkg', version: '1.2.3', description: 'x', license: 'Apache-2.0', engines: { node: '>=22' }, files: ['src/', 'README.md'], ...packagePatch };
  writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg));
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src', 'a.mjs'), 'export const a = 1;\n');
  writeFileSync(join(dir, 'src', 'b.mjs'), 'export const b = "é";\n');
  writeFileSync(join(dir, 'README.md'), '# tiny\n');
  writeFileSync(join(dir, 'not-released.txt'), 'private\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'init');
  return dir;
}

test('SBOM output is deterministic and has no timestamp unless one is supplied', () => {
  const dir = tinyRepo();
  const a = renderSbom({ root: dir }), b = renderSbom({ root: dir });
  assert.equal(a, b);
  assert.equal(JSON.parse(a).metadata.timestamp, undefined);
  assert.ok(!/\d{4}-\d{2}-\d{2}T\d{2}:/.test(a), 'no date-time anywhere in an unsupplied-timestamp SBOM');
  const stamped = JSON.parse(renderSbom({ root: dir, timestamp: '2026-10-15T00:00:00.000Z' }));
  assert.equal(stamped.metadata.timestamp, '2026-10-15T00:00:00.000Z');
  assert.throws(() => buildSbom({ root: dir, timestamp: 'now' }), /timestamp/);
  assert.throws(() => buildSbom({ root: dir, timestamp: '2026-10-15' }), /timestamp/);
});

test('SBOM has the CycloneDX 1.5 shape, lists the Node engine and declares no runtime dependencies', () => {
  const dir = tinyRepo();
  const bom = buildSbom({ root: dir });
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.5');
  assert.equal(bom.version, 1);
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  const root = bom.metadata.component;
  assert.equal(root.type, 'library');
  assert.equal(root.name, 'tiny-pkg');
  assert.equal(root.version, '1.2.3');
  assert.deepEqual(root.licenses, [{ license: { id: 'Apache-2.0' } }]);
  assert.ok(root.properties.some(p => p.name === 'kya:runtimeDependencies' && p.value === 'none'));
  const platform = bom.components.find(c => c.type === 'platform');
  assert.equal(platform.properties.find(p => p.name === 'kya:engines.node').value, '>=22');
  const refs = new Set([root['bom-ref'], ...bom.components.map(c => c['bom-ref'])]);
  assert.equal(refs.size, bom.components.length + 1, 'bom-ref values are unique');
  for (const d of bom.dependencies) { assert.ok(refs.has(d.ref)); for (const r of d.dependsOn) assert.ok(refs.has(r)); }
  assert.deepEqual(bom.dependencies.find(d => d.ref === root['bom-ref']).dependsOn, [platform['bom-ref']]);
  for (const c of bom.components.filter(x => x.type === 'file')) {
    assert.equal(c.hashes.length, 1);
    assert.equal(c.hashes[0].alg, 'SHA-256');
    assert.match(c.hashes[0].content, /^[a-f0-9]{64}$/);
  }
});

test('SBOM file list is the frozen release list in code-unit order and digests match the Git blobs', () => {
  const dir = tinyRepo();
  const bom = buildSbom({ root: dir });
  const files = bom.components.filter(c => c.type === 'file');
  assert.deepEqual(files.map(f => f.name), ['README.md', 'package.json', 'src/a.mjs', 'src/b.mjs']);
  for (const f of files) {
    const bytes = spawnSync('git', ['show', 'HEAD:' + f.name], { cwd: dir, env: GIT_ENV }).stdout;
    assert.equal(f.hashes[0].content, sha256(bytes), f.name);
    assert.equal(f.properties.find(p => p.name === 'kya:gitBlob').value, git(dir, 'rev-parse', 'HEAD:' + f.name).trim(), f.name);
  }
  assert.equal(bom.metadata.component.properties.find(p => p.name === 'kya:sourceCommit').value, git(dir, 'rev-parse', 'HEAD').trim());
});

test('SBOM reads committed blobs rather than the working tree, and a content change changes the output', () => {
  const dir = tinyRepo();
  const before = renderSbom({ root: dir });
  writeFileSync(join(dir, 'src', 'a.mjs'), 'export const a = 2;\n');
  assert.equal(renderSbom({ root: dir, allowDirty: true }), before, 'uncommitted edits are not inventoried');
  git(dir, 'commit', '-q', '-am', 'change');
  assert.notEqual(renderSbom({ root: dir }), before);
});

test('SBOM refuses a dirty tree for modified, staged and untracked files', () => {
  for (const dirty of [
    dir => writeFileSync(join(dir, 'src', 'a.mjs'), 'changed\n'),
    dir => { writeFileSync(join(dir, 'staged.txt'), 'x\n'); git(dir, 'add', 'staged.txt'); },
    dir => writeFileSync(join(dir, 'untracked.txt'), 'x\n')
  ]) {
    const dir = tinyRepo();
    dirty(dir);
    assert.throws(() => buildSbom({ root: dir }), /Commit all source files/);
  }
});

test('the SBOM command line refuses a dirty tree with a nonzero exit and prints a clean tree', () => {
  const dir = tinyRepo();
  mkdirSync(join(dir, 'scripts'));
  copyFileSync(sbomScript, join(dir, 'scripts', 'sbom.mjs'));
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'add script');
  const ok = spawnSync(process.execPath, [join(dir, 'scripts', 'sbom.mjs')], { cwd: dir, encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).bomFormat, 'CycloneDX');
  writeFileSync(join(dir, 'README.md'), 'dirty\n');
  const bad = spawnSync(process.execPath, [join(dir, 'scripts', 'sbom.mjs')], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(bad.status, 0);
  assert.equal(bad.stdout, '');
  assert.match(bad.stderr, /Commit all source files/);
  const usage = spawnSync(process.execPath, [join(dir, 'scripts', 'sbom.mjs'), '--bogus'], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(usage.status, 0);
});

test('SBOM refuses a package that declares dependencies it cannot inventory', () => {
  assert.throws(() => buildSbom({ root: tinyRepo({ dependencies: { left: '1.0.0' } }) }), /dependencies/);
  assert.throws(() => buildSbom({ root: tinyRepo({ devDependencies: { left: '1.0.0' } }) }), /devDependencies/);
  assert.equal(buildSbom({ root: tinyRepo({ dependencies: {} }) }).bomFormat, 'CycloneDX');
});

test('SBOM of this repository matches an independent read of the frozen release list at HEAD', () => {
  // The working tree may be dirty while developing; the SBOM is built from HEAD blobs, so this checks HEAD itself.
  const bom = buildSbom({ root: repoRoot, allowDirty: true });
  const pkg = JSON.parse(spawnSync('git', ['show', 'HEAD:package.json'], { cwd: repoRoot, encoding: 'utf8' }).stdout);
  const listed = spawnSync('git', ['ls-tree', '-r', '--name-only', 'HEAD', '--', 'package.json', ...pkg.files], { cwd: repoRoot, encoding: 'utf8' }).stdout.split('\n').filter(Boolean);
  const files = bom.components.filter(c => c.type === 'file');
  assert.deepEqual(files.map(f => f.name), [...listed].sort());
  for (const f of files.filter((_, i) => i % 40 === 0)) {
    const bytes = spawnSync('git', ['show', 'HEAD:' + f.name], { cwd: repoRoot, maxBuffer: 50_000_000 }).stdout;
    assert.equal(f.hashes[0].content, sha256(bytes), f.name);
  }
  assert.equal(bom.metadata.component.name, 'kya-evidence');
  assert.equal(bom.components.find(c => c.type === 'platform').properties[0].value, pkg.engines.node);
});
