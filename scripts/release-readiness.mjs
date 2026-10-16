// Release readiness report for KYA Evidence.
//
// Two sections. AUTOMATED gates are observed by running local commands and reading local files; each is pass or
// fail. OUTSIDE gates need a person or party this repository cannot stand in for; they are always listed as OPEN.
// This script never marks an outside gate as passed, whatever its inputs say, and it never prints the READY line
// while any automated gate fails.
//
// Exit codes: 0 all automated gates pass (outside gates may be open), 1 an automated gate failed, 2 usage error.
// Exit 0 means "ready for an owner decision", not "approved". Nothing here publishes, tags, pushes or uses the
// network: it spawns only node and read-only git commands.
//
// Usage: node scripts/release-readiness.mjs [--branch NAME] [--json] [--observed FILE]
//   --branch NAME    branch the release must be cut from (default main)
//   --json           print only the JSON report
//   --observed FILE  evaluate injected observations from a JSON file instead of running anything (test use);
//                    the report says so, and the observations are never trusted as a real run.
import { readFileSync, existsSync, readdirSync, rmSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMain } from './lib/is-main.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

/** Outside gates: listed, never evaluated. Each needs a party this repository cannot be. */
export const OUTSIDE_GATES = Object.freeze([
  { id: 'security-contact-monitored', title: 'A security contact exists, is private, is monitored and has been tested', needs: 'owner' },
  { id: 'legal-counsel-review', title: 'Counsel has reviewed IPR terms, trademark and claims rules, crosswalks and safe-harbour wording', needs: 'legal counsel' },
  { id: 'external-security-review', title: 'An independent security review has been done and its findings retested', needs: 'independent security reviewer' },
  { id: 'independent-implementation', title: 'An implementation by a party outside this team passes the published vectors', needs: 'outside implementer' },
  { id: 'relying-party-pilots', title: 'At least one relying party has piloted the evidence on a real decision', needs: 'relying parties' },
  { id: 'domain-expert-profile-signoff', title: 'Domain experts have signed off the profiles they would be used for', needs: 'domain experts' },
  { id: 'npm-account-and-trusted-publisher', title: 'npm account with 2FA, package name and trusted publisher or token are configured', needs: 'owner' },
  { id: 'owner-go-ahead', title: 'The owner has reviewed this report and explicitly decided to publish', needs: 'owner' }
].map(g => Object.freeze(g)));

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const PLACEHOLDER = /SET-BY-OWNER|TO BE SET|TO BE DETERMINED|\bTBD\b|\bTODO\b|placeholder|<[^>\n]*(?:contact|owner|email|address)[^>\n]*>|\[SECURITY CONTACT/i;
const EMAIL = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b/g;
const FAKE_DOMAINS = /(?:^|\.)(?:example\.(?:com|org|net)|invalid|test|localhost)$/i;
const ADVISORY_URL = /https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/security\/advisories\/new/;

/** Form check only: a recognizable, non-placeholder contact. It cannot show that anyone reads the mailbox. */
export function hasRealSecurityContact(text) {
  if (typeof text !== 'string' || !text.trim()) return false;
  if (PLACEHOLDER.test(text)) return false;
  for (const m of text.matchAll(EMAIL)) if (!FAKE_DOMAINS.test(m[1])) return true;
  return ADVISORY_URL.test(text);
}

const isInt = n => Number.isInteger(n) && n >= 0;
const text = v => typeof v === 'string';

/** Pure evaluation of observations into automated gate results. Anything not observed fails. */
export function evaluateAutomated(o) {
  o = o && typeof o === 'object' ? o : {};
  const gates = [];
  const gate = (id, title, fn) => {
    let ok = false, detail = 'not observed';
    try { const r = fn(); if (r) { ok = r[0] === true; detail = String(r[1]); } } catch { ok = false; detail = 'observation malformed'; }
    gates.push({ id, title, status: ok ? 'pass' : 'fail', detail });
  };
  gate('git-clean', 'Git working tree is clean', () => text(o.gitStatus) && [o.gitStatus.trim() === '', o.gitStatus.trim() === '' ? 'no uncommitted or untracked files' : 'uncommitted or untracked files present']);
  gate('git-branch', 'Release is cut from the expected branch', () => text(o.branch) && text(o.expectedBranch) && [o.branch === o.expectedBranch, `on ${o.branch}, expected ${o.expectedBranch}`]);
  gate('version-consistent', 'Package version matches bin/kya.mjs, docs/governance/VERSIONING.md and the README', () => {
    const v = o.versions; if (!v) return null;
    const ok = text(v.package) && SEMVER.test(v.package) && v.package === v.bin && v.package === v.versioning && v.package === v.readme;
    return [ok, `package.json ${v.package}, bin/kya.mjs ${v.bin}, VERSIONING.md ${v.versioning}, README ${v.readme}`];
  });
  gate('changelog-heading', 'CHANGELOG.md has a heading for the current version', () => {
    if (!text(o.changelog) || !o.versions || !text(o.versions.package)) return null;
    const heading = '## [' + o.versions.package + ']';
    return [o.changelog.split('\n').some(l => l.trim() === heading || l.startsWith(heading + ' ')), `looked for "${heading}"`];
  });
  gate('tests', 'Full test suite passes with nothing skipped or pending', () => {
    const t = o.tests; if (!t) return null;
    const ok = t.exit === 0 && isInt(t.pass) && t.pass > 0 && t.fail === 0 && t.cancelled === 0 && t.skipped === 0 && t.todo === 0 && t.pass === t.tests;
    return [ok, `exit ${t.exit}; tests ${t.tests}, pass ${t.pass}, fail ${t.fail}, cancelled ${t.cancelled}, skipped ${t.skipped}, todo ${t.todo}`];
  });
  const exit0 = (id, title, key, what) => gate(id, title, () => o[key] && [o[key].exit === 0, `${what} exit ${o[key].exit}`]);
  exit0('check', 'npm run check (syntax, JSON, schemas, requirements, status ledger)', 'check', 'scripts/check.mjs');
  exit0('requirements', 'Requirement traceability matches the registry', 'requirements', 'scripts/requirements.mjs --check');
  exit0('golden-vectors', 'Golden vectors match', 'goldenVectors', 'scripts/golden-vectors.mjs --check');
  exit0('assessment-vectors', 'Assessment vectors match', 'assessmentVectors', 'scripts/assessment-vectors.mjs --check');
  exit0('profile-registry', 'Profile registry matches the profiles', 'profileRegistry', 'scripts/profile-registry.mjs --check');
  gate('pack-and-verify', 'Package builds and verify-release passes', () => o.pack && o.verify && [o.pack.exit === 0 && o.verify.exit === 0, `pack exit ${o.pack.exit}, verify-release exit ${o.verify.exit}`]);
  gate('no-private-markers', 'No private-path or private-key markers in package text', () => {
    const p = o.privateMarkers; if (!p) return null;
    const ok = isInt(p.scanned) && p.scanned > 0 && Array.isArray(p.hits) && p.hits.length === 0;
    return [ok, `${p.scanned} files scanned, ${Array.isArray(p.hits) ? p.hits.length : 'unknown'} with markers${ok ? '' : ': ' + (p.hits || []).slice(0, 5).join(', ')}`];
  });
  gate('legal-files-present', 'LICENSE, NOTICE and SECURITY.md are present and non-empty', () => {
    const f = o.files; if (!f) return null;
    const missing = ['LICENSE', 'NOTICE', 'SECURITY.md'].filter(n => !(isInt(f[n]) && f[n] > 0));
    return [missing.length === 0, missing.length ? 'missing or empty: ' + missing.join(', ') : 'all three present'];
  });
  gate('security-contact-form', 'SECURITY.md names a non-placeholder contact (form check only)', () => text(o.securityText) && [hasRealSecurityContact(o.securityText), hasRealSecurityContact(o.securityText) ? 'a contact is present; whether it is monitored stays an outside gate' : 'no real contact found: the owner must supply one before publishing']);
  gate('readme-not-claims', 'README has the "What this is not" section', () => text(o.readme) && [/^## What this is not\s*$/m.test(o.readme), 'looked for the heading "## What this is not"']);
  gate('mutation-preflight', 'Mutation controls pass the preflight (anchors present, mutants parse)', () => o.mutationPreflight && [o.mutationPreflight.exit === 0 && o.mutationPreflight.ok === true, `preflight exit ${o.mutationPreflight.exit}, controls ${o.mutationPreflight.controls}`]);
  return gates;
}

/** Build the full report from observations. Outside gates are fixed as OPEN; observations cannot change them. */
export function buildReport(observed, meta = {}) {
  const automated = evaluateAutomated(observed);
  const failed = automated.filter(g => g.status !== 'pass').length;
  const outside = OUTSIDE_GATES.map(g => ({ id: g.id, title: g.title, status: 'OPEN', needs: g.needs }));
  const verdict = failed === 0
    ? `READY FOR OWNER DECISION: automated gates pass; ${outside.length} outside gates open`
    : `NOT READY: ${failed} of ${automated.length} automated gates fail; ${outside.length} outside gates open`;
  return { schema: 'kya.release-readiness/v1', source: meta.source || 'run', version: observed && observed.versions ? observed.versions.package ?? null : null, automated, outside, failedAutomated: failed, ready: failed === 0, verdict };
}

export function renderText(report) {
  const lines = ['KYA Evidence release readiness' + (report.version ? ' for ' + report.version : ''), ''];
  if (report.source !== 'run') lines.push('INPUT SOURCE: injected observations (' + report.source + '); this is not a real run', '');
  lines.push('AUTOMATED gates (observed by this script)');
  for (const g of report.automated) lines.push(`  [${g.status === 'pass' ? 'PASS' : 'FAIL'}] ${g.id}: ${g.title} -- ${g.detail}`);
  lines.push('', 'OUTSIDE gates (cannot be checked here; all OPEN)');
  for (const g of report.outside) lines.push(`  [OPEN] ${g.id}: ${g.title} -- needs: ${g.needs}`);
  lines.push('', report.verdict);
  return lines.join('\n');
}

// ---- collection (the only part that touches the machine) ----

function run(cmd, args, opts = {}) {
  const p = spawnSync(cmd, args, { cwd: root, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: opts.timeout || 600_000, env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' } });
  return { exit: p.status === null ? -1 : p.status, stdout: p.stdout || '', stderr: p.stderr || '' };
}
const node = (script, ...args) => run(process.execPath, [join(root, 'scripts', script), ...args]);
const read = rel => { try { return readFileSync(join(root, rel), 'utf8'); } catch { return null; } };
const size = rel => { try { return statSync(join(root, rel)).size; } catch { return 0; } };

function parseTap(out) {
  const n = k => { const m = new RegExp('^# ' + k + ' (\\d+)$', 'm').exec(out); return m ? Number(m[1]) : null; };
  return { tests: n('tests'), pass: n('pass'), fail: n('fail'), cancelled: n('cancelled'), skipped: n('skipped'), todo: n('todo') };
}

/** Scan the files pack.mjs would package, using markers built by concatenation so this file carries none. */
function scanMarkers() {
  const home = '/Users/' + 'rudycelekli', pk = '-----BEGIN (?:RSA |EC |OPENSSH )?' + 'PRIVATE KEY-----';
  const marker = new RegExp(home + '|sk-(?:proj-)?[A-Za-z0-9]{24,}|' + pk);
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const ls = run('git', ['ls-files', '-z', '--', 'package.json', ...pkg.files]);
  const paths = ls.stdout.split('\0').filter(Boolean).filter(p => /\.(?:mjs|js|json|md|html|css|svg|ts)$/.test(p));
  const hits = [];
  for (const p of paths) { const t = read(p); if (t !== null && marker.test(t)) hits.push(p); }
  return { scanned: paths.length, hits };
}

export function collect({ expectedBranch = 'main' } = {}) {
  const o = { expectedBranch };
  o.gitStatus = run('git', ['status', '--porcelain']).stdout;
  o.branch = run('git', ['rev-parse', '--abbrev-ref', 'HEAD']).stdout.trim();
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const bin = /KYA Evidence (\S+)/.exec(read('bin/kya.mjs') || ''), ver = /currently `([^`]+)`/.exec(read('docs/governance/VERSIONING.md') || '');
  const rd = /reference implementation, \*\*v([^*\s]+)\*\*/.exec(read('README.md') || '');
  o.versions = { package: pkg.version, bin: bin ? bin[1] : null, versioning: ver ? ver[1] : null, readme: rd ? rd[1] : null };
  o.changelog = read('CHANGELOG.md');
  o.securityText = read('SECURITY.md');
  o.readme = read('README.md');
  o.files = { LICENSE: size('LICENSE'), NOTICE: size('NOTICE'), 'SECURITY.md': size('SECURITY.md') };
  o.privateMarkers = scanMarkers();
  const testFiles = readdirSync(join(root, 'test')).filter(f => f.endsWith('.test.mjs')).sort().map(f => join('test', f));
  const t = run(process.execPath, ['--test', '--test-reporter=tap', ...testFiles], { timeout: 1_800_000 });
  o.tests = { exit: t.exit, ...parseTap(t.stdout) };
  o.check = node('check.mjs');
  o.requirements = node('requirements.mjs', '--check');
  o.goldenVectors = node('golden-vectors.mjs', '--check');
  o.assessmentVectors = node('assessment-vectors.mjs', '--check');
  o.profileRegistry = node('profile-registry.mjs', '--check');
  const pre = node('mutation-check.mjs', '--preflight');
  let parsed = null; try { parsed = JSON.parse(pre.stdout.trim().split('\n').pop()); } catch { /* leave null */ }
  o.mutationPreflight = { exit: pre.exit, ok: !!parsed && parsed.preflight === 'ok', controls: parsed ? parsed.controls : null };
  // Pack reads the committed tree and refuses a dirty one; build output goes to the git-ignored dist/ and is removed again if this run created it.
  const hadDist = existsSync(join(root, 'dist'));
  o.pack = node('pack.mjs');
  o.verify = o.pack.exit === 0 ? node('verify-release.mjs') : { exit: -1 };
  if (!hadDist) rmSync(join(root, 'dist'), { recursive: true, force: true });
  return o;
}

// ---- command line ----

export function parseArgs(argv) {
  const out = { branch: 'main', json: false, observed: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '--branch' || a === '--observed') { const v = argv[++i]; if (!v || v.startsWith('--')) return { error: a + ' needs a value' }; out[a.slice(2)] = v; }
    else if (a === '--help' || a === '-h') out.help = true;
    else return { error: 'unknown argument ' + a };
  }
  return out;
}

const USAGE = 'Usage: node scripts/release-readiness.mjs [--branch NAME] [--json] [--observed FILE]\nExit 0: automated gates pass (outside gates stay open). 1: an automated gate fails. 2: usage error.';

export function main(argv, io = { out: s => process.stdout.write(s + '\n'), err: s => process.stderr.write(s + '\n') }) {
  const args = parseArgs(argv);
  if (args.error) { io.err(args.error + '\n' + USAGE); return 2; }
  if (args.help) { io.out(USAGE); return 0; }
  let observed, source = 'run';
  if (args.observed) {
    try { observed = JSON.parse(readFileSync(args.observed, 'utf8')); } catch { io.err('cannot read observations from ' + args.observed); return 2; }
    if (!observed || typeof observed !== 'object' || Array.isArray(observed)) { io.err('observations must be a JSON object'); return 2; }
    source = 'file ' + args.observed;
  } else observed = collect({ expectedBranch: args.branch });
  const report = buildReport(observed, { source });
  if (args.json) io.out(JSON.stringify(report, null, 2));
  else { io.out(renderText(report)); io.out(''); io.out('JSON report'); io.out(JSON.stringify(report, null, 2)); }
  return report.ready ? 0 : 1;
}

if (isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2));
