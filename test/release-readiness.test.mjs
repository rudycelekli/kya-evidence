import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { OUTSIDE_GATES, buildReport, evaluateAutomated, hasRealSecurityContact, main, parseArgs, renderText } from '../scripts/release-readiness.mjs';

// None of these tests runs the real collector: it would run the whole test suite again. They feed the pure
// evaluation and the command line fixed observations instead, so they are fast, offline and deterministic.
const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'scripts/release-readiness.mjs');
const scratch = mkdtempSync(join(tmpdir(), 'kya-readiness-'));
after(() => rmSync(scratch, { recursive: true, force: true }));

const good = () => ({
  gitStatus: '',
  branch: 'main',
  expectedBranch: 'main',
  versions: { package: '0.1.0-alpha.4', bin: '0.1.0-alpha.4', versioning: '0.1.0-alpha.4', readme: '0.1.0-alpha.4' },
  changelog: '# Changelog\n\n## [Unreleased]\n\n## [0.1.0-alpha.4] - 2026-10-20\n',
  tests: { exit: 0, tests: 10, pass: 10, fail: 0, cancelled: 0, skipped: 0, todo: 0 },
  check: { exit: 0 },
  requirements: { exit: 0 },
  goldenVectors: { exit: 0 },
  assessmentVectors: { exit: 0 },
  profileRegistry: { exit: 0 },
  pack: { exit: 0 },
  verify: { exit: 0 },
  privateMarkers: { scanned: 40, hits: [] },
  files: { LICENSE: 11000, NOTICE: 200, 'SECURITY.md': 900 },
  securityText: 'Report privately to security@kya-evidence.dev (a made up test address).',
  readme: '# KYA\n\n## What this is not\n\n- Not a certification.\n',
  mutationPreflight: { exit: 0, ok: true, controls: 12 }
});
const status = (gates, id) => gates.find(g => g.id === id).status;
function capture(argv) {
  const out = [], err = [];
  const code = main(argv, { out: s => out.push(s), err: s => err.push(s) });
  return { code, out: out.join('\n'), err: err.join('\n') };
}
function observedFile(name, value) {
  const path = join(scratch, name);
  writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
  return path;
}

test('all automated gates pass for complete good observations and the report is ready', () => {
  const report = buildReport(good());
  assert.equal(report.failedAutomated, 0);
  assert.equal(report.ready, true);
  assert.ok(report.automated.length >= 15);
  assert.ok(report.automated.every(g => g.status === 'pass'));
  assert.equal(report.verdict, 'READY FOR OWNER DECISION: automated gates pass; ' + OUTSIDE_GATES.length + ' outside gates open');
});

test('each broken observation fails its own gate and the report is not ready', () => {
  const cases = [
    ['git-clean', o => { o.gitStatus = ' M README.md\n'; }],
    ['git-branch', o => { o.branch = 'feature-x'; }],
    ['version-consistent', o => { o.versions.bin = '0.1.0-alpha.3'; }],
    ['version-consistent', o => { o.versions.readme = '0.1.0-alpha.3'; }],
    ['version-consistent', o => { delete o.versions.readme; }],
    ['version-consistent', o => { o.versions.package = 'not-a-version'; o.versions.bin = 'not-a-version'; o.versions.versioning = 'not-a-version'; }],
    ['changelog-heading', o => { o.changelog = '## [Unreleased]\n## [0.1.0-alpha.3]\n'; }],
    ['tests', o => { o.tests.fail = 1; }],
    ['tests', o => { o.tests.exit = 1; }],
    ['tests', o => { o.tests.skipped = 1; }],
    ['tests', o => { o.tests.todo = 2; }],
    ['tests', o => { o.tests.pass = 0; o.tests.tests = 0; }],
    ['tests', o => { o.tests.tests = 11; }],
    ['check', o => { o.check.exit = 1; }],
    ['requirements', o => { o.requirements.exit = 1; }],
    ['golden-vectors', o => { o.goldenVectors.exit = 1; }],
    ['assessment-vectors', o => { o.assessmentVectors.exit = 1; }],
    ['profile-registry', o => { o.profileRegistry.exit = 1; }],
    ['pack-and-verify', o => { o.pack.exit = 1; }],
    ['pack-and-verify', o => { o.verify.exit = 1; }],
    ['no-private-markers', o => { o.privateMarkers.hits = ['docs/x.md']; }],
    ['no-private-markers', o => { o.privateMarkers.scanned = 0; }],
    ['legal-files-present', o => { o.files.NOTICE = 0; }],
    ['security-contact-form', o => { o.securityText = 'No mailbox is promised.'; }],
    ['readme-not-claims', o => { o.readme = '# KYA\n'; }],
    ['mutation-preflight', o => { o.mutationPreflight.exit = 1; }],
    ['mutation-preflight', o => { o.mutationPreflight.ok = false; }]
  ];
  for (const [id, mutate] of cases) {
    const o = good();
    mutate(o);
    const report = buildReport(o);
    assert.equal(status(report.automated, id), 'fail', id + ' should fail');
    assert.equal(report.ready, false, id + ' must make the report not ready');
    assert.ok(report.failedAutomated >= 1);
    assert.ok(report.verdict.startsWith('NOT READY'), report.verdict);
    assert.ok(!renderText(report).includes('READY FOR OWNER DECISION'), id + ' must never print the ready line');
  }
});

test('missing or malformed observations fail closed', () => {
  for (const bad of [undefined, null, {}, [], 'x', 7]) {
    const gates = evaluateAutomated(bad);
    assert.ok(gates.length >= 15);
    assert.ok(gates.every(g => g.status === 'fail'), 'every gate must fail without observations');
    assert.equal(buildReport(bad).ready, false);
  }
  const o = good();
  delete o.tests;
  assert.equal(status(evaluateAutomated(o), 'tests'), 'fail');
  const p = good();
  p.tests = { exit: 0, tests: '10', pass: '10', fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  assert.equal(status(evaluateAutomated(p), 'tests'), 'fail');
});

test('outside gates are always open whatever the observations claim', () => {
  const claims = { ...good(), outside: Object.fromEntries(OUTSIDE_GATES.map(g => [g.id, 'pass'])), outsideGates: 'all passed', ownerGoAhead: true };
  for (const o of [claims, good(), {}, null]) {
    const report = buildReport(o);
    assert.equal(report.outside.length, OUTSIDE_GATES.length);
    assert.ok(report.outside.length >= 8);
    assert.ok(report.outside.every(g => g.status === 'OPEN' && typeof g.needs === 'string' && g.needs.length > 0));
    assert.ok(!renderText(report).includes('[PASS] owner-go-ahead'));
  }
  const ids = OUTSIDE_GATES.map(g => g.id);
  for (const wanted of ['security-contact-monitored', 'legal-counsel-review', 'external-security-review', 'independent-implementation', 'relying-party-pilots', 'domain-expert-profile-signoff', 'npm-account-and-trusted-publisher', 'owner-go-ahead']) {
    assert.ok(ids.includes(wanted), wanted);
  }
  assert.ok(Object.isFrozen(OUTSIDE_GATES));
});

test('the text report has an automated section and an outside section', () => {
  const text = renderText(buildReport(good()));
  const a = text.indexOf('AUTOMATED gates');
  const b = text.indexOf('OUTSIDE gates');
  assert.ok(a >= 0 && b > a);
  assert.ok(text.indexOf('[PASS] tests') > a && text.indexOf('[PASS] tests') < b);
  assert.ok(text.indexOf('[OPEN] owner-go-ahead') > b);
  assert.ok(text.trimEnd().endsWith('READY FOR OWNER DECISION: automated gates pass; 8 outside gates open'));
});

test('exit code is 0 with the ready line when every automated gate passes', () => {
  const r = capture(['--observed', observedFile('good.json', good())]);
  assert.equal(r.code, 0);
  assert.ok(r.out.includes('READY FOR OWNER DECISION: automated gates pass; 8 outside gates open'));
  assert.ok(r.out.includes('not a real run'));
  assert.ok(r.out.includes('"schema": "kya.release-readiness/v1"'));
});

test('exit code is 1 and no ready line when an automated gate fails', () => {
  const o = good();
  o.tests.fail = 3;
  const r = capture(['--observed', observedFile('bad.json', o)]);
  assert.equal(r.code, 1);
  assert.ok(!r.out.includes('READY FOR OWNER DECISION'));
  assert.ok(r.out.includes('NOT READY: 1 of'));
  assert.ok(r.out.includes('[FAIL] tests'));
  const j = capture(['--json', '--observed', observedFile('bad2.json', o)]);
  assert.equal(j.code, 1);
  assert.equal(JSON.parse(j.out).ready, false);
});

test('exit code is 2 for usage errors', () => {
  assert.equal(capture(['--nope']).code, 2);
  assert.equal(capture(['--branch']).code, 2);
  assert.equal(capture(['--observed']).code, 2);
  assert.equal(capture(['--observed', join(scratch, 'missing.json')]).code, 2);
  assert.equal(capture(['--observed', observedFile('garbage.json', '{not json')]).code, 2);
  assert.equal(capture(['--observed', observedFile('array.json', '[]')]).code, 2);
  assert.equal(capture(['extra']).code, 2);
  assert.ok(parseArgs(['--branch', 'x']).branch === 'x');
  assert.equal(capture(['--help']).code, 0);
});

test('the command line process exits with the documented codes and prints the report', () => {
  const run = args => spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', timeout: 20000 });
  const ok = run(['--observed', observedFile('cli-good.json', good())]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.ok(ok.stdout.includes('READY FOR OWNER DECISION: automated gates pass; 8 outside gates open'));
  const o = good();
  o.securityText = '';
  const failing = run(['--observed', observedFile('cli-bad.json', o)]);
  assert.equal(failing.status, 1);
  assert.ok(failing.stdout.includes('no real contact found'));
  assert.equal(run(['--unknown']).status, 2);
});

test('security contact check accepts a real looking contact and rejects placeholders and silence', () => {
  assert.equal(hasRealSecurityContact('Write to security@kya-evidence.dev'), true);
  assert.equal(hasRealSecurityContact('Use https://github.com/acme/kya/security/advisories/new to report.'), true);
  assert.equal(hasRealSecurityContact('Contact: <SET-BY-OWNER: an address>'), false);
  assert.equal(hasRealSecurityContact('Write to security@example.com'), false);
  assert.equal(hasRealSecurityContact('Write to security@kya.test'), false);
  assert.equal(hasRealSecurityContact('Contact: security@kya-evidence.dev TBD'), false);
  assert.equal(hasRealSecurityContact('No security mailbox or response SLA is promised.'), false);
  assert.equal(hasRealSecurityContact(''), false);
  assert.equal(hasRealSecurityContact(null), false);
});

test('the script uses no network and publishes nothing', () => {
  const src = readFileSync(script, 'utf8');
  const forbidden = ['node:http', 'node:https', 'node:net', 'node:dns', 'node:tls', 'node:dgram', 'fetch' + '(', 'XMLHttpRequest', 'WebSocket', 'npm ' + 'publish', 'git ' + 'push', 'git ' + 'tag', 'gh ' + 'release', 'curl', 'wget'];
  for (const word of forbidden) assert.ok(!src.includes(word), 'script must not contain ' + word);
  const imports = [...src.matchAll(/^import .* from '([^']+)';$/gm)].map(m => m[1]);
  assert.deepEqual(imports.sort(), ['./lib/is-main.mjs', 'node:child_process', 'node:fs', 'node:path', 'node:url']);
  // The only commands it spawns are node and read-only git.
  const spawned = [...src.matchAll(/run\('([a-z]+)'/g)].map(m => m[1]);
  assert.ok(spawned.every(c => c === 'git'));
  const gitArgs = [...src.matchAll(/run\('git', \[([^\]]*)\]/g)].map(m => m[1]);
  assert.ok(gitArgs.length >= 2);
  for (const a of gitArgs) assert.ok(/'(status|rev-parse|ls-files)'/.test(a), a);
});

test('the package defines the readiness script and nothing else changed in its scripts contract', () => {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts['release:readiness'], 'node scripts/release-readiness.mjs');
  assert.ok(pkg.files.includes('scripts/') && pkg.files.includes('docs/'));
});
