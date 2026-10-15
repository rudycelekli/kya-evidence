import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// Mechanical guards for documentation claims that a cold reader found wrong. They read markdown and a few source
// file names; they do not judge whether the prose is good.
const root = fileURLToPath(new URL('../', import.meta.url));
const read = (p) => readFileSync(join(root, p), 'utf8');
const SKIP = new Set(['node_modules', '.git', '.claude', 'dist', 'artifacts']);

function markdownFiles(dir = root, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) markdownFiles(full, out);
    else if (e.isFile() && e.name.endsWith('.md')) out.push(full);
  }
  return out;
}
const files = markdownFiles();

test('the action README example carries the pin inputs and says a bare call needs pins', () => {
  const doc = read('action/README.md');
  const example = doc.split('## Usage')[1].split('## Inputs')[0];
  for (const input of ['policy:', 'profile:', 'evaluator:', 'expect-policy-digest:', 'expect-evaluator-digest:', 'manifest:', 'evidence:', 'now:']) {
    assert.ok(example.includes(input), `example lacks ${input}`);
  }
  assert.ok(!example.includes('assessment-inputs: kya/inputs.json'), 'example must not be the unpinned form');
  assert.ok(example.includes('PINS_REQUIRED') && example.includes('require-pins'), 'example must explain PINS_REQUIRED');
});

test('the policy pin is described as the canonical policy digest and not the file hash', () => {
  for (const p of ['docs/GITHUB-ACTION.md', 'docs/examples/kya-check.workflow.yml', 'action/README.md']) {
    const text = read(p);
    assert.ok(text.includes('policyDigest'), `${p} does not name policyDigest`);
    assert.ok(/sha256sum/.test(text), `${p} does not warn against the file hash`);
  }
});

test('no markdown file references a nonexistent docs lane integration or requirements proposal note', () => {
  const bad = [];
  for (const f of files) {
    const text = readFileSync(f, 'utf8');
    for (const m of text.matchAll(/docs\/(lane-[a-z0-9-]+\.(?:md|json))/g)) {
      if (!existsSync(join(root, 'docs', m[1]))) bad.push(`${relative(root, f)} -> docs/${m[1]}`);
    }
    for (const m of text.matchAll(/\blane-[a-z0-9]+-(?:integration\.md|requirements-proposal\.json)/g)) {
      bad.push(`${relative(root, f)} -> ${m[0]}`);
    }
  }
  assert.deepEqual(bad, []);
});

test('README does not call the manifest a passport or promise portable passports', () => {
  const readme = read('README.md');
  assert.ok(!/passports/i.test(readme), 'README still says passports');
  assert.ok(!/passports/i.test(read('docs/ROADMAP.md')), 'ROADMAP still says passports');
  assert.ok(readme.includes('a declaration, not a passport or identity credential'));
});

test('CONFORMANCE no longer says no second implementation has run the vectors', () => {
  const doc = read('docs/CONFORMANCE.md');
  assert.ok(!/No second implementation has run/i.test(doc));
  assert.ok(doc.includes('No outside implementation has run them'));
  assert.ok(doc.includes('not independent'));
});

test('the implementers guide reports all 111 vectors byte for byte for the second implementation', () => {
  const doc = read('docs/IMPLEMENTERS-GUIDE.md');
  assert.ok(doc.includes('now matches all 111 byte for byte'));
  assert.ok(doc.includes('43') && doc.includes('79'));
});

test('the six-gate detection claim is labelled as not reproducible from the repository', () => {
  for (const p of ['README.md', 'docs/VALIDATION.md', 'docs/BENCHMARKS.md']) {
    const text = read(p);
    assert.ok(text.includes('not reproducible from this repository') || text.includes('cannot be reproduced from this repository'), `${p} lacks the reproducibility caveat`);
    assert.ok(text.includes('scripts/mutation-check.mjs'), `${p} does not point at the mutation check`);
  }
});

test('the stated mutation control count matches the mutation check script', () => {
  const run = spawnSync(process.execPath, ['scripts/mutation-check.mjs', '--preflight'], { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const count = JSON.parse(run.stdout).controls;
  assert.ok(count > 0);
  for (const p of ['README.md', 'docs/VALIDATION.md', 'docs/BENCHMARKS.md']) {
    assert.ok(read(p).includes(`${count} targeted gate mutations`), `${p} does not state ${count} targeted gate mutations`);
  }
});

test('every VC bridge command in the documentation resolves to an existing script or subcommand', () => {
  assert.ok(existsSync(join(root, 'scripts/kya-vc.mjs')));
  const bad = [];
  for (const f of files) {
    const text = readFileSync(f, 'utf8');
    for (const m of text.matchAll(/(^|[^\w/.-])kya-vc (\S+)/gm)) bad.push(`${relative(root, f)}: kya-vc ${m[2]}`);
  }
  assert.deepEqual(bad, [], 'use `kya vc ...` or `node scripts/kya-vc.mjs ...`');
});

test('the credential bridge is described as implemented but unvalidated in the roadmap', () => {
  const doc = read('docs/ROADMAP.md');
  assert.ok(!doc.includes('No credential bridge'));
  assert.ok(doc.includes('VC 2.0 export bridge implemented'));
});

test('the relying party quickstart lists observations.json and shows how to authenticate a received assessment', () => {
  const doc = read('docs/QUICKSTART-RELYING-PARTY.md');
  assert.ok(doc.includes('seven files') && doc.includes('`observations.json`'));
  assert.ok(doc.includes('### Authenticate a received assessment'));
});

test('the implementers guide says an unsupported reply to a refusal vector fails', () => {
  assert.ok(read('docs/IMPLEMENTERS-GUIDE.md').includes('`unsupported` reply to a vector whose expected result is a refusal is a `fail`'));
  assert.ok(read('interop/impl-contract/README.md').includes('so it is a **fail** there'));
});
