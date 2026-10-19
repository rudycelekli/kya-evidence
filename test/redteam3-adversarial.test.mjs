import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync, cpSync } from 'node:fs';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { sign, generateKeyPairSync } from 'node:crypto';
import { deflateRawSync, gzipSync, constants as zc } from 'node:zlib';
import { digest, hashBytes, parseJson } from '../src/shared/canonical.mjs';
import { gzipDeterministic, crc32 } from '../src/shared/gzip-deterministic.mjs';
import { gunzipStrict } from '../src/shared/gunzip-strict.mjs';
import { decodeList, encodeList, createBitstring, checkStatus } from '../src/vc-bridge/status.mjs';
import { signCompact } from '../src/vc-bridge/jws.mjs';
import { VC_CONTEXT } from '../src/vc-bridge/open.mjs';
import { buildScoreCard, verifyScoreCard, compareScoreCards } from '../src/kya-score/index.mjs';
import { V2_OPERATIONS } from '../interop/impl-contract/js-operations.mjs';
import { OPERATIONS as SECOND_OPERATIONS } from '../interop/second-impl/ops.mjs';
import { credentialKeys } from '../scripts/lib/vectors-credential.mjs';
import { isForbiddenPath, textMarker } from '../scripts/lib/package-guard.mjs';
import { verifyReleaseReceipt } from '../scripts/lib/ustar.mjs';
import { runVectors } from '../scripts/run-vectors.mjs';
import { checkKit, computeActuals, KIT_FILES } from '../scripts/review-kit-check.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const VECTORS = join(root, 'evidence/assessment-vectors.json');
const FILE = JSON.parse(readFileSync(VECTORS, 'utf8'));
const KEYS = credentialKeys(hashBytes);
const b64 = x => Buffer.from(x).toString('base64url');
const tmp = prefix => mkdtempSync(join(tmpdir(), prefix));

// ---------------------------------------------------------------- GZIP in status lists

const CLEAR_ID = 'verify-credential.status-both-lists-clear';
const REVOCATION = 'https://status.example.test/revocation';
const clearInputs = () => structuredClone(FILE.vectors.find(v => v.id === CLEAR_ID).inputs);
function resignList(jwt, mutate) {
  const [h, p] = jwt.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  mutate(payload);
  const input = h + '.' + b64(JSON.stringify(payload));
  return input + '.' + b64(sign(null, Buffer.from(input), KEYS.issuer.priv));
}
function withEncodedList(bytes) {
  const x = clearInputs();
  x.statusLists[REVOCATION] = resignList(x.statusLists[REVOCATION], p => { p.credentialSubject.encodedList = 'u' + b64(bytes); });
  return x;
}
const both = inputs => ({ reference: V2_OPERATIONS['verify-credential'](structuredClone(inputs)), second: SECOND_OPERATIONS['verify-credential'](structuredClone(inputs)) });
const ZEROS = Buffer.alloc(16384);
const member = (data, flags = 0, extra = Buffer.alloc(0), body = deflateRawSync(data)) => {
  const t = Buffer.alloc(8); t.writeUInt32LE(crc32(data), 0); t.writeUInt32LE(data.length, 4);
  return Buffer.concat([Buffer.from([0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 3]), extra, body, t]);
};

test('redteam3 status list decoder refuses a second gzip member and bytes after the member', () => {
  const one = gzipSync(ZEROS);
  for (const [name, bytes] of [
    ['second member', Buffer.concat([one, gzipSync(Buffer.alloc(100))])],
    ['empty first member', Buffer.concat([gzipSync(Buffer.alloc(0)), one])],
    ['trailing zero padding', Buffer.concat([one, Buffer.alloc(10)])],
    ['trailing text', Buffer.concat([one, Buffer.from('trailing text')])],
    ['one trailing byte', Buffer.concat([one, Buffer.from([0])])]
  ]) {
    assert.throws(() => decodeList('u' + b64(bytes)), /STATUS_LIST_INVALID/, name);
    const { reference, second } = both(withEncodedList(bytes));
    assert.equal(reference.valid, false, name);
    assert.equal(reference.status.entries.some(e => e.error === 'STATUS_LIST_INVALID'), true, name);
    assert.deepEqual(second, reference, name);
  }
});

test('redteam3 status list decoder accepts one member from other encoders and agrees with the second implementation', () => {
  const dynamic = gzipSync(ZEROS), stored = gzipSync(ZEROS, { level: 0 }), fixed = gzipSync(ZEROS, { strategy: zc.Z_FIXED });
  const huffman = gzipSync(ZEROS, { strategy: zc.Z_HUFFMAN_ONLY }), deterministic = gzipDeterministic(ZEROS);
  const named = member(ZEROS, 8 | 16 | 4, Buffer.concat([Buffer.from([3, 0, 1, 2, 3]), Buffer.from('list.bin\0'), Buffer.from('comment\0')]));
  for (const [name, bytes] of [['dynamic', dynamic], ['stored', stored], ['fixed', fixed], ['huffman only', huffman], ['deterministic', deterministic], ['header text and extra', named]]) {
    assert.equal(decodeList('u' + b64(bytes)).length, 16384, name);
    const { reference, second } = both(withEncodedList(bytes));
    assert.equal(reference.valid, true, name + ' ' + JSON.stringify(reference.errors));
    assert.deepEqual(second, reference, name);
  }
});

test('redteam3 status list decoder refuses damaged members and reserved header flags', () => {
  const one = gzipSync(ZEROS);
  const crcBad = Buffer.from(one); crcBad[crcBad.length - 5] ^= 1;
  const sizeBad = Buffer.from(one); sizeBad[sizeBad.length - 1] ^= 1;
  const reserved = Buffer.from(one); reserved[3] |= 0x20;
  const method = Buffer.from(one); method[2] = 7;
  const hcrc = member(ZEROS, 2); const hcrcFixed = Buffer.concat([hcrc.subarray(0, 10), Buffer.from([0, 0]), hcrc.subarray(10)]); hcrcFixed[3] = 2;
  for (const [name, bytes] of [['bad crc', crcBad], ['bad size', sizeBad], ['truncated trailer', one.subarray(0, one.length - 1)], ['truncated body', one.subarray(0, one.length - 12)], ['reserved flag', reserved], ['method', method], ['header crc', hcrcFixed], ['empty', Buffer.alloc(0)], ['raw deflate', deflateRawSync(ZEROS)]]) {
    assert.throws(() => decodeList('u' + b64(bytes)), /STATUS_LIST_INVALID/, name);
    assert.throws(() => gunzipStrict(bytes), Error, name);
    const { reference, second } = both(withEncodedList(bytes));
    assert.equal(reference.valid, false, name);
    assert.deepEqual(second, reference, name);
  }
});

test('redteam3 status list decoder bounds deflate bombs including across members', () => {
  assert.throws(() => decodeList('u' + b64(gzipSync(Buffer.alloc(3 * 1024 * 1024)))), /exceeds/);
  assert.throws(() => decodeList('u' + b64(Buffer.concat([gzipSync(Buffer.alloc(1.5 * 1024 * 1024)), gzipSync(Buffer.alloc(1.5 * 1024 * 1024))]))), /STATUS_LIST_INVALID/);
  assert.equal(decodeList('u' + b64(gzipSync(Buffer.alloc(2 * 1024 * 1024)))).length, 2 * 1024 * 1024);
});

test('redteam3 deterministic encoder stays near linear on repetitive and matcher hostile input', () => {
  const n = 1_000_000;
  const shapes = {
    zeros: new Uint8Array(n),
    period7: Uint8Array.from({ length: n }, (_, i) => (i % 7 === 0 ? 1 : 0)),
    nearperiod: Uint8Array.from({ length: n }, (_, i) => (i % 300 < 299 ? 7 : 9)),
    noise: Uint8Array.from({ length: n }, (_, i) => (i * i >> 3) & 0xff)
  };
  for (const [name, data] of Object.entries(shapes)) {
    const t = Date.now();
    const out = encodeList(data);
    assert.ok(Date.now() - t < 8000, name + ' took ' + (Date.now() - t) + ' ms');
    assert.deepEqual(Buffer.from(decodeList(out, { maxBytes: n })), Buffer.from(data), name);
  }
});

// ---------------------------------------------------------------- status entry versus list identity

test('redteam3 status check refuses a list without an id when the entry names no list', () => {
  const issuerKey = generateKeyPairSync('ed25519').privateKey;
  const credential = { '@context': [VC_CONTEXT], type: ['VerifiableCredential', 'BitstringStatusListCredential'], validFrom: '2026-10-13T12:00:00.000Z', validUntil: '2026-10-20T12:00:00.000Z', credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: encodeList(createBitstring()) } };
  const { token, issuer } = signCompact({ ...credential, issuer: signCompact({}, issuerKey).issuer }, issuerKey);
  const entry = { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '0' };
  assert.throws(() => checkStatus(token, entry, { now: '2026-10-14T12:00:00.000Z', expectedIssuerKeys: [issuer] }), /STATUS_VERIFICATION_ERROR/);
});

// ---------------------------------------------------------------- score card

const hex = c => c.repeat(64);
const manifest = (over = {}) => ({ subject: { id: 's', version: '1', digest: hex('a') }, suite: { id: 'su', version: '1', digest: hex('b') }, evaluatorDigest: hex('c'), judge: null, holdoutCommitment: hex('d'), environment: { runtime: 'node', offlineDeclared: true }, bootstrap: { seed: 'seed', resamples: 200 }, ...over });
const runs = (n = 30, r = 3, held = 10, f = () => 'pass') => Array.from({ length: r }, (_, k) => ({ runId: 'r' + k, items: Array.from({ length: n }, (_, i) => ({ id: 'i' + String(i).padStart(4, '0'), outcome: f(k, i), heldOut: i < held, durationMs: 1.5, costUsd: 0.001 })) }));

test('redteam3 score card refuses non finite numbers prototype keys and duplicate item ids', () => {
  const bad = (mutate, pattern) => { const r = runs(); mutate(r); assert.throws(() => buildScoreCard({ manifest: manifest(), runs: r }), pattern); };
  bad(r => { r[0].items[0].durationMs = NaN; }, /Unsafe JSON number/);
  bad(r => { r[1].items[2].costUsd = Infinity; }, /Unsafe JSON number/);
  bad(r => { r[0].items[0].durationMs = -1; }, /Invalid item duration/);
  bad(r => { r[0].items[3].id = r[0].items[2].id; }, /Duplicate item id/);
  bad(r => { r[2].runId = r[0].runId; }, /Duplicate run id/);
  bad(r => { r[0].items[0] = JSON.parse('{"__proto__":1,"id":"q","outcome":"pass","heldOut":true,"durationMs":1,"costUsd":null}'); }, /JSON member/);
  assert.throws(() => buildScoreCard({ manifest: JSON.parse('{"__proto__":1}'), runs: runs() }), /JSON member/);
  assert.throws(() => buildScoreCard({ manifest: manifest(), runs: runs(), options: JSON.parse('{"floor":{"__proto__":{"minItems":1}}}') }), /JSON member/);
  assert.throws(() => parseJson('{"__proto__":1}'), /JSON member/);
});

test('redteam3 score card floor cannot be lowered or bypassed by editing a card or by held out flags', () => {
  const card = buildScoreCard({ manifest: manifest(), runs: runs() });
  assert.equal(verifyScoreCard(card).valid, true);
  for (const k of ['minItems', 'minRepeats', 'minHeldOutItems']) {
    const c = structuredClone(card); c.floor[k] -= 1;
    const r = verifyScoreCard(c);
    assert.equal(r.valid, false, k);
    assert.ok(r.problems.includes('floor-below-hard-minimum'), k);
  }
  const extra = structuredClone(card); extra.floor.extra = 1;
  assert.ok(verifyScoreCard(extra).problems.includes('floor-below-hard-minimum'));
  assert.throws(() => buildScoreCard({ manifest: manifest(), runs: runs(30, 3, 9) }), /HELDOUT_BELOW_FLOOR/);
  assert.throws(() => buildScoreCard({ manifest: manifest(), runs: runs(29, 3, 10) }), /ITEMS_BELOW_FLOOR/);
  assert.throws(() => buildScoreCard({ manifest: manifest(), runs: runs(30, 2, 10) }), /REPEATS_BELOW_FLOOR/);
  assert.throws(() => buildScoreCard({ manifest: manifest({ holdoutCommitment: null }), runs: runs() }), /HOLDOUT_COMMITMENT_MISSING/);
  assert.throws(() => buildScoreCard({ manifest: manifest(), runs: runs(), options: { floor: { minItems: 29 } } }), /cannot be lowered/);
  const moved = runs(); moved[1].items[0].heldOut = false;
  assert.throws(() => buildScoreCard({ manifest: manifest(), runs: moved }), /held out flags/);
});

test('redteam3 score card normalises negative zero and editing any derived number fails verification', () => {
  const r = runs(); r[0].items[0].durationMs = -0; r[0].items[0].costUsd = -0;
  const card = buildScoreCard({ manifest: manifest(), runs: r });
  assert.equal(Object.is(card.runs[0].items[0].durationMs, -0), false);
  assert.equal(verifyScoreCard(JSON.parse(JSON.stringify(card))).valid, true);
  const forged = structuredClone(card); forged.results.headline.score = 1; forged.results.headline.ci95 = { low: 0, high: 2 };
  const { cardDigest, ...body } = forged; forged.cardDigest = digest(body);
  const v = verifyScoreCard(forged);
  assert.equal(v.valid, false);
  assert.ok(v.problems.includes('results-differ-from-recomputation'));
  assert.equal(compareScoreCards(card, forged).comparable, false);
  assert.equal(compareScoreCards(card, null).comparable, false);
  const proto = JSON.parse(JSON.stringify(card).replace('{"schema"', '{"__proto__":{"a":1},"schema"'));
  assert.deepEqual(verifyScoreCard(proto).problems, ['unexpected-or-missing-fields']);
});

// ---------------------------------------------------------------- harness and hostile implementations

function oneVectorFile(dir) {
  const file = join(dir, 'one.json');
  writeFileSync(file, JSON.stringify({ ...FILE, vectors: [FILE.vectors.find(v => v.operation === 'canonicalize')] }));
  return file;
}
const gone = pid => { try { process.kill(pid, 0); return false; } catch { return true; } };
const runHarness = (dir, script, extra = [], options = {}) => spawnSync(process.execPath, [join(root, 'scripts/run-vectors.mjs'), '--impl', `"${process.execPath}" "${script}"`, '--vectors', oneVectorFile(dir), ...extra], { encoding: 'utf8', timeout: 40000, ...options });

test('redteam3 harness settles on timeout when the implementation leaves a child holding its pipes', () => {
  const dir = tmp('kya-rt3-hang-');
  try {
    const pidFile = join(dir, 'child.pid'), script = join(dir, 'impl.mjs');
    writeFileSync(script, `import { spawn } from 'node:child_process'; import { writeFileSync } from 'node:fs'; const c = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'inherit' }); writeFileSync(${JSON.stringify(pidFile)}, String(c.pid)); setInterval(() => {}, 1000);\n`);
    const started = Date.now();
    const r = runHarness(dir, script, ['--timeout-ms', '1500']);
    assert.notEqual(r.status, null, 'harness did not return before the test limit');
    assert.ok(Date.now() - started < 20000, 'took ' + (Date.now() - started) + ' ms');
    assert.equal(r.status, 1);
    assert.match(JSON.parse(r.stdout).failures[0].detail, /timeout after 1500 ms/);
    const pid = Number(readFileSync(pidFile, 'utf8'));
    for (let i = 0; i < 20 && !gone(pid); i++) spawnSync('sleep', ['0.1']);
    assert.equal(gone(pid), true, 'the grandchild survived the timeout');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('redteam3 harness does not wait for a background child after the implementation exits', () => {
  const dir = tmp('kya-rt3-exit-');
  try {
    const script = join(dir, 'impl.mjs');
    writeFileSync(script, `import { spawn } from 'node:child_process'; spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'inherit' }); process.stdout.write('{}'); process.exit(0);\n`);
    const started = Date.now();
    const r = runHarness(dir, script, ['--timeout-ms', '30000']);
    assert.notEqual(r.status, null, 'harness did not return before the test limit');
    assert.ok(Date.now() - started < 15000, 'took ' + (Date.now() - started) + ' ms');
    assert.equal(r.status, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('redteam3 harness gives the implementation a minimal environment', () => {
  const dir = tmp('kya-rt3-env-');
  try {
    const seen = join(dir, 'env.json'), script = join(dir, 'impl.mjs');
    writeFileSync(script, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(seen)}, JSON.stringify(Object.keys(process.env).sort())); process.stdout.write('{}');\n`);
    runHarness(dir, script, [], { env: { ...process.env, KYA_REDTEAM3_PROBE: 'x', NODE_OPTIONS: '--no-warnings', GITHUB_TOKEN: 'x', NPM_TOKEN: 'x' } });
    const names = JSON.parse(readFileSync(seen, 'utf8'));
    for (const k of ['KYA_REDTEAM3_PROBE', 'NODE_OPTIONS', 'GITHUB_TOKEN', 'NPM_TOKEN']) assert.equal(names.includes(k), false, k);
    assert.ok(names.includes('PATH'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('redteam3 harness reports an implementation that cannot start instead of crashing', async () => {
  const dir = tmp('kya-rt3-nul-');
  try {
    const { outcomes } = await runVectors({ impl: 'node\u0000broken', vectorsFile: oneVectorFile(dir), root });
    assert.equal(outcomes[0].status, 'fail');
    assert.match(outcomes[0].detail, /cannot start implementation/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('redteam3 harness fails every hostile output shape instead of passing or crashing', async () => {
  const dir = tmp('kya-rt3-shapes-');
  try {
    const vectorsFile = oneVectorFile(dir);
    const shapes = {
      duplicate: "process.stdout.write('{\"schema\":\"a\",\"schema\":\"b\"}')",
      proto: "process.stdout.write('{\"__proto__\":{\"x\":1}}')",
      binary: 'process.stdout.write(Buffer.from([0xff, 0xfe, 0x00, 0x80]))',
      array: "process.stdout.write('[]')",
      empty: "process.stdout.write('')",
      two: "process.stdout.write('{}\\n{}')",
      bom: "process.stdout.write('\\ufeff{}')",
      refusalWithOutput: "process.stdout.write('{}'); process.exit(3)",
      signal: "process.kill(process.pid, 'SIGKILL')"
    };
    for (const [name, body] of Object.entries(shapes)) {
      const script = join(dir, name + '.mjs');
      writeFileSync(script, body + '\n');
      const { outcomes } = await runVectors({ impl: `"${process.execPath}" "${script}"`, vectorsFile, root, timeoutMs: 20000 });
      assert.equal(outcomes[0].status, 'fail', name + ': ' + outcomes[0].detail);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('redteam3 harness bounds a flood of output and of stderr', () => {
  const dir = tmp('kya-rt3-flood-');
  try {
    const script = join(dir, 'impl.mjs');
    writeFileSync(script, `const big = Buffer.alloc(65536, 65); const t = setInterval(() => { process.stderr.write(big); process.stdout.write(big); }, 0); setTimeout(() => clearInterval(t), 20000);\n`);
    const r = runHarness(dir, script, ['--timeout-ms', '15000']);
    assert.equal(r.status, 1);
    assert.match(JSON.parse(r.stdout).failures[0].detail, /output exceeds 1048576 bytes/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------- package guard

const cat = (...parts) => parts.join('');

test('redteam3 package guard matches private paths regardless of case and for more credential files', () => {
  for (const p of ['.ENV', '.Env.local', 'docs/.Claude/x.md', 'NODE_MODULES/x/index.js', '.Swarm/state', '.NPMRC', '.Kya/k.json', '.envrc', '.env-prod', '.env_local', '.aws/credentials', 'a/.ssh/config', '.gnupg/pubring.kbx', '.netrc', '.pypirc', '.docker/config.json', '.git/config', 'x/server.JKS', 'x/store.keystore', 'a/ID_RSA.pub'])
    assert.equal(isForbiddenPath(p), true, p);
  for (const p of ['.github/workflows/ci.yml', '.gitignore', '.gitattributes', 'docs/environment.md', 'docs/gitignore-notes.md', 'src/envelope.mjs', 'README.md'])
    assert.equal(isForbiddenPath(p), false, p);
});

test('redteam3 package guard flags more secret shapes and home paths written in other styles', () => {
  const cases = [
    cat('sk', '-ant-', 'api03-', 'a'.repeat(20), '_-', 'b'.repeat(20)),
    cat('sk', '-proj-', 'a'.repeat(20), '_-', 'b'.repeat(20)),
    cat('github', '_pat_', 'A'.repeat(30)),
    cat('xo', 'xb-', '123456789012-', 'a'.repeat(24)),
    cat('AS', 'IA', 'A'.repeat(16)),
    cat('AI', 'za', 'A'.repeat(35)),
    cat('sk', '_live_', 'a'.repeat(24)),
    cat('-----BEGIN ', 'PGP PRIVATE KEY BLOCK-----'),
    cat('C:', '\\', 'Users', '\\', 'jsmith', '\\', 'project'),
    cat('C:', '\\\\', 'Users', '\\\\', 'jsmith'),
    cat('/', 'users', '/', 'jsmith', '/project'),
    cat('/', 'USERS', '/', 'jsmith'),
    cat('/', 'HOME', '/', 'deploy', '/.ssh'),
    cat('C:', '/', 'Users', '/', 'jsmith')
  ];
  for (const t of cases) assert.equal(textMarker('see ' + t + ' here'), true, t.slice(0, 20));
  for (const t of ['task-coordination-and-planning-guide-for-long-names', 'sk-learn', cat('C:', '\\', 'Users', '\\', 'you', '\\', 'x'), cat('/', 'users', '/', 'you'), 'A' + 'KIA' + 'A'.repeat(15), cat('github', '_pat_', 'short'), 'the home directory and users guide', 'ASIA' + 'a'.repeat(16)])
    assert.equal(textMarker(t), false, t.slice(0, 24));
});

// ---------------------------------------------------------------- release receipt verification

function tarRecord(name, bytes) {
  const header = Buffer.alloc(512);
  const octal = (offset, length, value) => header.write(value.toString(8).padStart(length - 1, '0') + '\0', offset, length, 'ascii');
  header.write('package/' + name, 0, 100, 'utf8'); octal(100, 8, 0o644); octal(108, 8, 0); octal(116, 8, 0); octal(124, 12, bytes.length); octal(136, 12, 0);
  header.fill(32, 148, 156); header.write('0', 156, 1); header.write('ustar\0', 257, 6); header.write('00', 263, 2);
  header.write(header.reduce((s, n) => s + n, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return Buffer.concat([header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512)]);
}
function release(files, over = {}) {
  const inventory = files.map(([path, text]) => ({ path, bytes: Buffer.byteLength(text), sha256: hashBytes(Buffer.from(text)) }));
  const archive = gzipDeterministic(Buffer.concat([...files.map(([path, text]) => tarRecord(path, Buffer.from(text))), Buffer.alloc(1024)]));
  const receipt = { schema: 'kya.release-receipt/v1', package: 'p', version: '1.0.0', sourceCommit: 'a'.repeat(40), archive: 'p-1.0.0.tgz', archiveSha256: hashBytes(archive), inventoryDigest: digest(inventory), inventory, build: {}, status: 'prepared-local-unpublished', assurance: 'test', ...over };
  return { receipt, archive };
}
const PKG = ['package.json', '{"name":"p","version":"1.0.0"}'];

test('redteam3 release verification accepts a minimal well formed archive', () => {
  const { receipt, archive } = release([PKG, ['README.md', 'hello']]);
  assert.equal(verifyReleaseReceipt(receipt, archive, { bindPackage: true, expectCommit: 'a'.repeat(40) }).files, 2);
});

test('redteam3 release verification refuses entries that differ only in letter case', () => {
  const { receipt, archive } = release([PKG, ['README.md', 'one'], ['readme.md', 'two']]);
  assert.throws(() => verifyReleaseReceipt(receipt, archive, { bindPackage: true }), /duplicate tar path/i);
});

test('redteam3 release verification refuses a receipt commit that is not a Git object name', () => {
  for (const sourceCommit of ['a'.repeat(40) + '\u202e', '\u009b31m' + 'a'.repeat(40), 'A'.repeat(40), 'abc', 'a'.repeat(41), '', 5]) {
    const { receipt, archive } = release([PKG], { sourceCommit });
    assert.throws(() => verifyReleaseReceipt(receipt, archive, { bindPackage: true }), /not a Git object name|Invalid|insist|differs/i, JSON.stringify(sourceCommit).slice(0, 20));
  }
});

test('redteam3 release verification refuses traversal absolute duplicate and link entries and a swapped archive', () => {
  for (const name of ['../x', 'a/../x', '/abs', 'a//b', './x', 'a/./b', 'a\\b', 'caf\u00e9.md', 'a b.md']) {
    const { receipt, archive } = release([PKG, [name, 'x']].map(([p, t]) => [p, t]));
    assert.throws(() => verifyReleaseReceipt(receipt, archive, { bindPackage: true }), /Unsafe/, name);
  }
  const { receipt, archive } = release([PKG, ['README.md', 'x']]);
  const other = release([PKG, ['README.md', 'y']]).archive;
  assert.throws(() => verifyReleaseReceipt(receipt, other, { bindPackage: true }), /digest differs/);
  assert.throws(() => verifyReleaseReceipt(receipt, archive, { bindPackage: true, expectCommit: 'b'.repeat(40) }), /expected commit/);
  assert.throws(() => verifyReleaseReceipt({ ...receipt, version: '9.9.9' }, archive, { bindPackage: true }), /Receipt package or version differs/);
});

test('redteam3 verify-release script refuses a receipt that is not a regular file instead of waiting on it', { skip: process.platform === 'win32' }, () => {
  const dir = tmp('kya-rt3-fifo-');
  try {
    mkdirSync(join(dir, 'scripts')); mkdirSync(join(dir, 'dist'));
    cpSync(join(root, 'scripts', 'verify-release.mjs'), join(dir, 'scripts', 'verify-release.mjs'));
    cpSync(join(root, 'scripts', 'lib'), join(dir, 'scripts', 'lib'), { recursive: true });
    cpSync(join(root, 'src'), join(dir, 'src'), { recursive: true });
    cpSync(join(root, 'profiles'), join(dir, 'profiles'), { recursive: true });
    cpSync(join(root, 'package.json'), join(dir, 'package.json'));
    const made = spawnSync('mkfifo', [join(dir, 'dist', 'release-receipt.json')]);
    assert.equal(made.status, 0);
    const r = spawnSync(process.execPath, [join(dir, 'scripts', 'verify-release.mjs')], { encoding: 'utf8', timeout: 15000 });
    assert.notEqual(r.status, null, 'verify-release blocked on a FIFO');
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /bounded regular file/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------- review kit checker

const actuals = await computeActuals(root);
const REVIEW = KIT_FILES[0];
const kitText = () => readFileSync(join(root, REVIEW), 'utf8');

test('redteam3 review kit checker stays fast on a kit with a very long run of blank lines', async () => {
  const started = Date.now();
  const r = await checkKit({ root, actuals, text: { [REVIEW]: kitText() + '\n'.repeat(150000) } });
  assert.ok(Date.now() - started < 6000, 'took ' + (Date.now() - started) + ' ms');
  assert.equal(r.ok, true, r.problems.join('; '));
});

test('redteam3 review kit checker does not count a path outside the checkout as present', async () => {
  const dir = tmp('kya-rt3-kit-');
  try {
    const outside = join(dir, 'outside.txt'); writeFileSync(outside, 'x');
    const rel = relative(root, outside).split('\\').join('/');
    assert.ok(rel.startsWith('..'));
    const cite = '\nSee `docs/../' + rel + '`.\n';
    const r = await checkKit({ root, actuals, text: { [REVIEW]: kitText() + cite } });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some(p => p.includes('referenced path') && p.includes('does not exist')), r.problems.join('; '));
    const script = '\nRun `node scripts/../' + rel.replace(/\.txt$/, '.mjs') + '`.\n';
    writeFileSync(outside.replace(/\.txt$/, '.mjs'), '');
    const s = await checkKit({ root, actuals, text: { [REVIEW]: kitText() + script } });
    assert.equal(s.ok, false);
    assert.ok(s.problems.some(p => p.includes('missing script')), s.problems.join('; '));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('redteam3 review kit checker refuses a quoted number named like an inherited property', async () => {
  const bad = kitText().replace(/(\| `requirements` \| `)\d+(`)/, '| `constructor` | `1` |\n$1' + actuals.requirements + '$2');
  const r = await checkKit({ root, actuals, text: { [REVIEW]: bad } });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some(p => p.includes('constructor')), r.problems.join('; '));
});
