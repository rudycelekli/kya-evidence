import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// Mechanical guards for documentation claims that a cold reader found wrong. They read markdown and a few source
// file names; they do not judge whether the prose is good.
const root = fileURLToPath(new URL('../', import.meta.url));
const read = (p) => readFileSync(join(root, p), 'utf8');
const SKIP = new Set(['node_modules', '.git', '.claude', 'dist', 'artifacts']);

// Only tracked files count: scratch copies and other tools' working folders are not part of the repository.
function markdownFiles() {
  const r = spawnSync('git', ['ls-files', '*.md'], { cwd: root, encoding: 'utf8' });
  assert.equal(r.status, 0, 'git ls-files failed');
  return r.stdout.split('\n').filter(Boolean).filter(f => !SKIP.has(f.split('/')[0])).map(f => join(root, f));
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

test('the implementers guide reports every vector byte for byte for the second implementation', () => {
  const doc = read('docs/IMPLEMENTERS-GUIDE.md');
  const published = JSON.parse(read('evidence/assessment-vectors.json')).vectors.length;
  assert.ok(doc.includes(`now matches all ${published} byte for byte`), 'the guide does not state the published vector count ' + published);
  assert.ok(doc.includes('43') && doc.includes('79'));
});

test('the six-gate detection claim is labelled as not reproducible from the repository', () => {
  // The claim itself was removed; if wording about an unreproducible run ever returns it must carry the caveat.
  for (const p of ['README.md', 'docs/VALIDATION.md', 'docs/BENCHMARKS.md']) {
    const text = read(p);
    assert.ok(text.includes('scripts/mutation-check.mjs'), `${p} does not point at the mutation check`);
    if (/private same-team|six[- ]gate detection|Six assessor mutations were reported/i.test(text)) {
      assert.ok(text.includes('not reproducible from this repository') || text.includes('cannot be reproduced from this repository'), `${p} lacks the reproducibility caveat`);
    }
  }
});

test('no public doc cites a private same-team detection run', () => {
  for (const p of ['README.md', 'docs/VALIDATION.md', 'docs/BENCHMARKS.md']) {
    const text = read(p);
    assert.ok(!/private same-team/i.test(text), `${p} cites a private run that cannot be reproduced`);
    assert.ok(!/six[- ]gate detection/i.test(text) && !/Six assessor mutations were reported/i.test(text), `${p} cites an unreproducible detection result`);
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
  assert.ok(read('docs/IMPLEMENTERS-GUIDE.md').includes('`unsupported` reply to a vector of `assess` or `currency` whose expected result is a refusal is a `fail`'));
  assert.ok(read('docs/IMPLEMENTERS-GUIDE.md').includes('refusal vector of one of the four newer operations, the exact `unsupported` reply for that operation is `not-run`'));
  assert.ok(read('interop/impl-contract/README.md').includes('so it is a **fail** there'));
});

test('every relative markdown link in top-level and docs markdown files resolves to a tracked path', () => {
  const ls = spawnSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' });
  assert.equal(ls.status, 0, 'git ls-files failed');
  const tracked = new Set(ls.stdout.split('\n').filter(Boolean));
  const folders = new Set();
  for (const p of tracked) { const parts = p.split('/'); for (let i = 1; i < parts.length; i++) folders.add(parts.slice(0, i).join('/')); }
  const generated = /^(?:dist|artifacts|node_modules|\.git|\.claude)(?:\/|$)/;
  const bad = [];
  for (const abs of files) {
    const rel = relative(root, abs).split('\\').join('/');
    if (rel.includes('/') && !rel.startsWith('docs/')) continue;
    const text = readFileSync(abs, 'utf8').replace(/```[\s\S]*?```/g, '');
    for (const m of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
      const target = m[1];
      if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#') || target.startsWith('//')) continue;
      const pathPart = target.split('#')[0].split('?')[0];
      if (!pathPart) continue;
      const parts = [];
      for (const seg of (pathPart.startsWith('/') ? pathPart.slice(1) : [...rel.split('/').slice(0, -1), pathPart].join('/')).split('/')) {
        if (seg === '' || seg === '.') continue;
        if (seg === '..') parts.pop(); else parts.push(seg);
      }
      const resolved = parts.join('/');
      if (generated.test(resolved)) continue;
      if (!tracked.has(resolved) && !folders.has(resolved)) bad.push(`${rel} -> ${target}`);
    }
  }
  assert.deepEqual(bad, []);
});

test('no tracked markdown file carries an owner placeholder except the file the readiness gate watches', () => {
  // scripts/release-readiness.mjs reads only SECURITY.md for the security-contact-form gate and treats a placeholder
  // there as "no real contact". docs/security.txt is a text draft (not markdown) and keeps its owner values on purpose.
  const allowed = new Set(['SECURITY.md']);
  const pattern = /[<\[](?:SET-BY-OWNER|SECURITY CONTACT|ENFORCEMENT CONTACT)/;
  const bad = [];
  for (const abs of files) {
    const rel = relative(root, abs).split('\\').join('/');
    if (allowed.has(rel)) continue;
    if (pattern.test(readFileSync(abs, 'utf8'))) bad.push(rel);
  }
  assert.deepEqual(bad, []);
  assert.ok(existsSync(join(root, 'docs/security.txt')), 'the draft security.txt must stay');
});

test('the README assess example carries no hardcoded --now and the demo path it describes is qualified', () => {
  const readme = read('README.md');
  const start = readme.indexOf('kya.mjs assess');
  assert.ok(start > 0, 'README has no assess example');
  const block = readme.slice(start, readme.indexOf('```', start));
  assert.ok(!/--now\b/.test(block), 'the assess example must not pin --now: kya demo stamps its manifest with the real clock');
  assert.ok(/stamps its manifest and evidence with the current clock/.test(readme) && /leave `--now` out/.test(readme), 'README must explain the demo clock and --now');
  const dir = mkdtempSync(join(tmpdir(), 'kya-readme-'));
  try {
    const d = spawnSync(process.execPath, ['bin/kya.mjs', 'demo', '--out', dir], { cwd: root, encoding: 'utf8' });
    assert.equal(d.status, 0, d.stderr);
    const evaluator = JSON.parse(read('evidence/evaluator-identity.json')).evaluatorDigest;
    const a = spawnSync(process.execPath, ['bin/kya.mjs', 'assess', '--manifest', join(dir, 'manifest.json'), '--profile', 'profiles/core-v1.json', '--policy', join(dir, 'policy.json'), '--evidence', join(dir, 'evidence.json'), '--evaluator', evaluator, '--out', join(dir, 'assessment')], { cwd: root, encoding: 'utf8' });
    assert.equal(a.status, 0, a.stderr);
    assert.equal(JSON.parse(a.stdout).decision, 'qualified');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('every requirement and vector count quoted in the alpha release notes equals the repository value', () => {
  const notes = read('docs/RELEASE-NOTES-ALPHA.md');
  const req = JSON.parse(spawnSync(process.execPath, ['scripts/requirements.mjs'], { cwd: root, encoding: 'utf8' }).stdout).requirements;
  const vectors = JSON.parse(read('evidence/assessment-vectors.json')).vectors.length;
  const mut = JSON.parse(spawnSync(process.execPath, ['scripts/mutation-check.mjs', '--preflight'], { cwd: root, encoding: 'utf8' }).stdout).controls;
  const found = {
    requirements: [...notes.matchAll(/(\d+) (?:traced )?requirements/g)].map(m => +m[1]),
    vectors: [...notes.matchAll(/(\d+) (?:\w+ )?vectors/g)].map(m => +m[1]),
    mutation: [...notes.matchAll(/(\d+) mutation controls/g)].map(m => +m[1])
  };
  assert.ok(found.requirements.length >= 1 && found.vectors.length >= 2 && found.mutation.length >= 1, 'release notes quote no counts');
  for (const n of found.requirements) assert.equal(n, req, 'requirement count');
  for (const n of found.vectors) assert.equal(n, vectors, 'vector count');
  for (const n of found.mutation) assert.equal(n, mut, 'mutation control count');
  assert.ok(!/\d+ tests passing/.test(notes), 'release notes must not quote a CI test count');
});

test('top-level documents do not claim clean-room, a pending review or a published contact', () => {
  for (const p of ['README.md', 'CONTRIBUTING.md', 'NOTICE', 'AGENTS.md', 'docs/governance/IPR-POLICY.md']) {
    assert.ok(!/clean-room/i.test(read(p)), `${p} still says clean-room, which conflicts with ADR-0016 and NOTICE`);
  }
  assert.ok(!/review is pending/.test(read('SECURITY.md')) && /no independent security review has taken place/.test(read('SECURITY.md')));
  for (const p of ['docs/review/REVIEW-KIT.md', 'docs/pilot/IMPLEMENTER-INVITATION.md', 'docs/pilot/PILOT-KIT.md']) {
    assert.ok(/no monitored channel exists/.test(read(p)), `${p} must say no monitored channel exists`);
  }
  assert.ok(!/alpha incubation/.test(read('README.md')), 'README characterizes a project docs/VC-BRIDGE.md says was not fetched');
});

test('SUPPLY-CHAIN.md does not deny build provenance while release.yml has an attest-build-provenance step', () => {
  const release = read('.github/workflows/release.yml');
  const doc = read('docs/SUPPLY-CHAIN.md');
  assert.ok(/actions\/attest-build-provenance@/.test(release), 'release.yml lost its attestation step');
  assert.ok(!/\bNo build provenance(?! has)/.test(doc), 'SUPPLY-CHAIN.md denies build provenance that the workflow implements');
  assert.ok(/never (?:been )?run/.test(doc), 'SUPPLY-CHAIN.md must say the workflow has never run');
  assert.ok(!/How a release SHOULD be signed/.test(doc) && !/Generate a build-provenance attestation/.test(doc), 'stale not-implemented wording remains');
  assert.ok(!/Pin `actions\/checkout`/.test(doc), 'pinning is done and must not be backlog');
  const unpinned = [...release.matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)].filter(m => !/@[0-9a-f]{40}$/.test(m[1]));
  assert.deepEqual(unpinned.map(m => m[1]), [], 'release.yml has an action that is not SHA-pinned');
});
