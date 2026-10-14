// Deterministic CycloneDX 1.5-style SBOM for this repository.
//
// Reads only committed Git blobs (never the working tree), uses no clock and no network, and refuses a dirty
// tree exactly like scripts/pack.mjs. The package has no runtime dependencies; the SBOM lists the package, the
// Node.js engine requirement and the SHA-256 digest of every file in the frozen release list (package.json plus
// the "files" entries of package.json, as read by scripts/pack.mjs).
//
// Usage: node scripts/sbom.mjs [--out FILE] [--timestamp 2026-01-01T00:00:00.000Z]
// A timestamp appears in the output only when supplied. This is an unsigned inventory, not a provenance claim.
import { createHash } from 'node:crypto';
import { realpathSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const DEPENDENCY_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies', 'bundledDependencies'];
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const byCodeUnit = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function git(root, args, binary = false) {
  const p = spawnSync('git', args, { cwd: root, encoding: binary ? undefined : 'utf8', maxBuffer: 50_000_000 });
  if (p.status !== 0) throw new Error('Git snapshot read failed: git ' + args[0]);
  return p.stdout;
}

/** Stable, RFC 4122 shaped identifier derived from content, so identical inputs give an identical serialNumber. */
function serialFrom(hex) {
  const h = hex.slice(0, 32).split('');
  h[12] = '8'; // version nibble 8 (custom, content-derived)
  h[16] = '89ab'[parseInt(h[16], 16) % 4];
  const s = h.join('');
  return `urn:uuid:${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

export function buildSbom({ root, timestamp, allowDirty = false } = {}) {
  if (typeof root !== 'string' || root === '') throw new Error('root is required');
  if (timestamp !== undefined && !(typeof timestamp === 'string' && TIMESTAMP.test(timestamp))) throw new Error('timestamp must be an ISO UTC time with milliseconds');
  const commit = git(root, ['rev-parse', 'HEAD']).trim();
  if (!allowDirty && git(root, ['status', '--porcelain']).trim()) throw new Error('Commit all source files before creating an SBOM');
  const pkg = JSON.parse(git(root, ['show', commit + ':package.json']));
  for (const field of DEPENDENCY_FIELDS) {
    if (pkg[field] !== undefined && !(typeof pkg[field] === 'object' && Object.keys(pkg[field]).length === 0)) throw new Error(`package.json declares ${field}; this SBOM generator only supports a package with no dependencies`);
  }
  if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string' || !Array.isArray(pkg.files)) throw new Error('package.json needs name, version and files');
  const node = pkg.engines?.node;
  if (typeof node !== 'string') throw new Error('package.json needs engines.node');

  const allowed = ['package.json', ...pkg.files];
  const entries = git(root, ['ls-tree', '-r', '-z', commit, '--', ...allowed]).split('\0').filter(Boolean).map(line => {
    const m = /^(100644|100755) blob ([a-f0-9]{40,64})\t(.+)$/.exec(line);
    if (!m) throw new Error('Refusing nonregular Git tree entry');
    return { path: m[3], blob: m[2] };
  }).sort((a, b) => byCodeUnit(a.path, b.path));
  if (!entries.some(e => e.path === 'package.json')) throw new Error('package.json missing from frozen Git tree');

  const rootRef = `pkg:npm/${pkg.name}@${pkg.version}`;
  const nodeRef = 'platform:nodejs';
  const files = entries.map(e => ({
    type: 'file',
    'bom-ref': `file:${e.path}`,
    name: e.path,
    hashes: [{ alg: 'SHA-256', content: sha256(git(root, ['cat-file', 'blob', e.blob], true)) }],
    properties: [{ name: 'kya:gitBlob', value: e.blob }]
  }));

  const body = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      ...(timestamp ? { timestamp } : {}),
      tools: { components: [{ type: 'application', name: 'kya-evidence scripts/sbom.mjs', version: pkg.version }] },
      component: {
        type: 'library',
        'bom-ref': rootRef,
        name: pkg.name,
        version: pkg.version,
        ...(pkg.description ? { description: pkg.description } : {}),
        licenses: pkg.license ? [{ license: { id: pkg.license } }] : [],
        purl: rootRef,
        properties: [
          { name: 'kya:sourceCommit', value: commit },
          { name: 'kya:runtimeDependencies', value: 'none' },
          { name: 'kya:fileListSource', value: 'package.json files, as frozen by scripts/pack.mjs' },
          { name: 'kya:assurance', value: 'Unsigned inventory of committed file digests. No publisher signature, no build provenance.' }
        ]
      }
    },
    components: [
      { type: 'platform', 'bom-ref': nodeRef, name: 'nodejs', description: 'Required runtime, from package.json engines.node. Not bundled.', properties: [{ name: 'kya:engines.node', value: node }] },
      ...files
    ],
    dependencies: [
      { ref: rootRef, dependsOn: [nodeRef] },
      { ref: nodeRef, dependsOn: [] },
      ...files.map(f => ({ ref: f['bom-ref'], dependsOn: [] }))
    ]
  };
  // The serial number is derived from the content so that identical inputs give byte-identical output.
  const serialNumber = serialFrom(sha256(JSON.stringify(body)));
  return { bomFormat: body.bomFormat, specVersion: body.specVersion, serialNumber, version: body.version, metadata: body.metadata, components: body.components, dependencies: body.dependencies };
}

export function renderSbom(options) { return JSON.stringify(buildSbom(options), null, 2) + '\n'; }

function main(argv) {
  let out, timestamp;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out' && argv[i + 1] !== undefined) out = argv[++i];
    else if (argv[i] === '--timestamp' && argv[i + 1] !== undefined) timestamp = argv[++i];
    else throw new Error('Usage: node scripts/sbom.mjs [--out FILE] [--timestamp ISO-UTC-with-milliseconds]');
  }
  const text = renderSbom({ root: fileURLToPath(new URL('../', import.meta.url)), timestamp });
  if (out) writeFileSync(out, text); else process.stdout.write(text);
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(error.message + '\n'); process.exitCode = 1; }
}
