import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Text level checks of .github/workflows/release.yml. The package has no YAML parser and no dependencies, so
// these read the file by indentation. They guard the properties that make a release a single reviewed decision.
const root = fileURLToPath(new URL('../', import.meta.url));
const src = readFileSync(join(root, '.github/workflows/release.yml'), 'utf8');
const lines = src.split('\n');
const code = lines.filter(l => !/^\s*#/.test(l));

/** Lines of a top-level or nested block: everything after `header` that is indented deeper than it. */
function block(allLines, headerIndex) {
  const indent = allLines[headerIndex].match(/^ */)[0].length;
  const out = [];
  for (let i = headerIndex + 1; i < allLines.length; i++) {
    const l = allLines[i];
    if (l.trim() === '') { out.push(l); continue; }
    if (l.match(/^ */)[0].length <= indent) break;
    out.push(l);
  }
  return out;
}
const topIndex = key => code.findIndex(l => l === key + ':' || l.startsWith(key + ':'));
const jobs = () => {
  const j = block(code, topIndex('jobs'));
  const names = j.map((l, i) => [l, i]).filter(([l]) => /^ {2}[a-z][a-z0-9_-]*:\s*$/.test(l));
  return names.map(([l, i], n) => ({ name: l.trim().slice(0, -1), body: j.slice(i, n + 1 < names.length ? names[n + 1][1] : j.length) }));
};
const stepsOf = job => {
  const out = [];
  let cur = null;
  let inSteps = false;
  for (const l of job.body) {
    if (/^ {4}steps:\s*$/.test(l)) { inSteps = true; continue; }
    if (!inSteps) continue;
    if (/^ {6}- /.test(l)) { cur = [l]; out.push(cur); } else if (cur) cur.push(l);
  }
  return out.map(s => s.join('\n'));
};

test('the workflow runs only on manual dispatch and has no push tag schedule or pull request trigger', () => {
  const on = block(code, topIndex('on'));
  const keys = on.filter(l => /^ {2}[A-Za-z_]+:/.test(l)).map(l => l.trim().split(':')[0]);
  assert.deepEqual(keys, ['workflow_dispatch']);
  for (const banned of ['push', 'tags', 'schedule', 'pull_request', 'pull_request_target', 'release', 'workflow_run', 'workflow_call', 'repository_dispatch', 'create']) {
    assert.ok(!keys.includes(banned), banned);
  }
  assert.ok(!/^on:[ \t]*\S/m.test(src), 'on must be a block, not an inline value');
});

test('the dry run input is a boolean that defaults to true', () => {
  const dispatch = block(code, code.findIndex(l => l === '  workflow_dispatch:'));
  const input = block(dispatch, dispatch.findIndex(l => l.trim() === 'dry_run:'));
  const text = input.join('\n');
  assert.ok(/type:\s*boolean/.test(text));
  assert.ok(/default:\s*true\s*$/m.test(text));
  assert.ok(!/default:\s*false/.test(text));
  assert.ok(!/required:\s*false/.test(text) || /default:\s*true/.test(text));
});

test('every action reference is pinned to a full commit SHA and none is local or unpinned', () => {
  const uses = code.filter(l => /\buses:/.test(l));
  assert.ok(uses.length >= 6);
  for (const l of uses) {
    assert.ok(/uses:\s*[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}(\s+#.*)?$/.test(l.trim().replace(/^- /, '')), 'not SHA pinned: ' + l.trim());
  }
  assert.ok(uses.some(l => l.includes('actions/attest-build-provenance@')));
  assert.ok(!code.some(l => /uses:\s*\.\//.test(l)));
  assert.ok(!code.some(l => /docker:\/\//.test(l)));
});

test('npm publish appears only in steps gated on a real run, in a job that needs the release environment', () => {
  const all = jobs();
  const publishJobs = all.filter(j => /\bnpm publish\s/.test(j.body.join('\n')));
  assert.equal(publishJobs.length, 1);
  const job = publishJobs[0];
  const jobText = job.body.join('\n');
  assert.ok(/^ {4}environment:\s*release\s*$/m.test(jobText), 'publish job needs the release environment');
  assert.ok(/^ {4}if:.*inputs\.dry_run == false/m.test(jobText), 'publish job must be gated on dry_run == false');
  assert.ok(/^ {4}needs:\s*build\s*$/m.test(jobText));
  const publishSteps = stepsOf(job).filter(s => /\bnpm publish\s/.test(s));
  assert.ok(publishSteps.length >= 1);
  for (const s of publishSteps) {
    assert.ok(/^\s+if:.*inputs\.dry_run == false/m.test(s), 'publish step must be gated on dry_run == false');
    assert.ok(/steps\.cfg\.outputs\.mode == '(?:trusted|token)'/.test(s), 'publish step must be gated on a configured publisher');
    assert.ok(s.includes('--provenance') && s.includes('--access public'));
  }
  const build = all.find(j => j.name === 'build');
  assert.ok(build && !/\bnpm publish\s/.test(build.body.join('\n')));
  assert.ok(!build.body.join('\n').includes('environment:'));
});

test('the build job runs the gates and builds verifies and attests the tarball', () => {
  const build = jobs().find(j => j.name === 'build').body.join('\n');
  for (const needle of ['scripts/check.mjs', 'privacy:scan', '--test', 'scripts/mutation-check.mjs', 'scripts/requirements.mjs --check', 'scripts/release-readiness.mjs', 'scripts/pack.mjs', 'scripts/verify-release.mjs', 'scripts/sbom.mjs', 'actions/attest-build-provenance@', 'actions/upload-artifact@', "'# skipped 0'", "'# todo 0'"]) {
    assert.ok(build.includes(needle), 'build job lacks ' + needle);
  }
  assert.ok(build.indexOf('scripts/pack.mjs') < build.indexOf('scripts/verify-release.mjs'));
  assert.ok(build.indexOf('scripts/verify-release.mjs') < build.indexOf('actions/attest-build-provenance@'));
});

test('permissions are least privilege with read only contents by default', () => {
  const top = block(code, topIndex('permissions')).map(l => l.trim()).filter(Boolean);
  assert.deepEqual(top, ['contents: read']);
  for (const job of jobs()) {
    const i = job.body.findIndex(l => /^ {4}permissions:\s*$/.test(l));
    assert.ok(i >= 0, job.name + ' must declare permissions');
    const perms = block(job.body, i).map(l => l.trim()).filter(Boolean);
    assert.ok(perms.includes('contents: read'), job.name);
    for (const p of perms) assert.ok(['contents: read', 'id-token: write', 'attestations: write'].includes(p), job.name + ': ' + p);
  }
  assert.ok(!/write-all|contents:\s*write|packages:\s*write|pull-requests:\s*write/.test(src));
});

test('the workflow never tags pushes or creates releases and keeps untrusted context out of the file', () => {
  for (const banned of ['git tag', 'git push', 'gh release', 'gh api', 'curl ', 'wget ']) assert.ok(!code.join('\n').includes(banned), banned);
  for (const l of code) {
    if (l.includes('github.event') || l.includes('github.head_ref') || l.includes('github.ref_name')) assert.fail('untrusted context in workflow text: ' + l.trim());
  }
  assert.ok(!code.some(l => /persist-credentials:\s*true/.test(l)));
  assert.ok(code.filter(l => l.includes('actions/checkout@')).length === code.filter(l => l.includes('persist-credentials: false')).length);
});
