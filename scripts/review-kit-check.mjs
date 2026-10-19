import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { isMain } from './lib/is-main.mjs';

// Review kit checker. Read-only, no network, no dependencies. It checks three things about the review and pilot kits:
//   1. every command and file path they name exists in this checkout;
//   2. every number the review kit quotes (the table under "Numbers quoted by this kit") equals what the repository
//      reports now, recomputed here from the repository and not copied from any document;
//   3. a few required plain statements are still present (no outside review exists, no publication without owner approval).
// A passing run says the kit is not stale. It says nothing about the quality of the code the kit describes.

const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const KIT_FILES = ['docs/review/REVIEW-KIT.md', 'docs/pilot/PILOT-KIT.md', 'docs/pilot/IMPLEMENTER-INVITATION.md'];
const TOP = /^(?:src|test|scripts|docs|evidence|interop|profiles|examples|schemas|policies|suites|bin|action|dashboard|assets|\.github)\//;
const TOP_FILES = new Set(['README.md', 'SECURITY.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'AGENTS.md', 'LICENSE', 'NOTICE', 'package.json', 'DESIGN.md', 'PRODUCT.md']);

const read = (root, p) => readFileSync(join(root, p), 'utf8');
function walk(dir, ext, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, ext, out); else if (e.isFile() && p.endsWith(ext)) out.push(p);
  }
  return out;
}
function run(root, args) {
  const r = spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024 });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// Recompute every quoted number. `deep` also runs the reference implementation over all vectors (about ten seconds).
export async function computeActuals(root = ROOT, { deep = false } = {}) {
  const a = {};
  const req = run(root, ['scripts/requirements.mjs']);
  if (req.status !== 0) throw new Error('requirements script failed: ' + req.stderr.slice(0, 200));
  const rj = JSON.parse(req.stdout);
  a.requirements = rj.requirements;
  a.requirementsRegistryDigest = rj.registryDigest;
  const vec = JSON.parse(read(root, 'evidence/assessment-vectors.json')).vectors;
  a.vectorsTotal = vec.length;
  for (const op of ['assess', 'currency', 'canonicalize', 'digest', 'verify-envelope', 'compare']) a['vectors.' + op] = vec.filter(v => (v.operation ?? v.op) === op).length;
  const mut = run(root, ['scripts/mutation-check.mjs', '--preflight']);
  if (mut.status !== 0) throw new Error('mutation preflight failed: ' + mut.stderr.slice(0, 200));
  a.mutationControls = JSON.parse(mut.stdout).controls;
  const tests = readdirSync(join(root, 'test')).filter(f => f.endsWith('.test.mjs'));
  a.testFiles = tests.length;
  a.testDeclarations = tests.reduce((n, f) => n + (read(root, 'test/' + f).match(/^test\(/gm) || []).length, 0);
  a.adrs = readdirSync(join(root, 'docs/adr')).filter(f => /^\d{4}-.*\.md$/.test(f)).length;
  a.coreProfileChecks = JSON.parse(read(root, 'profiles/core-v1.json')).checks.length;
  const src = walk(join(root, 'src'), '.mjs');
  a.srcFiles = src.length;
  a.srcLines = src.reduce((n, f) => n + (readFileSync(f, 'utf8').match(/\n/g) || []).length, 0);
  a.evaluatorDigestPinned = JSON.parse(read(root, 'evidence/evaluator-identity.json')).evaluatorDigest;
  const mod = await import(pathToFileURL(join(root, 'src/conformance/index.mjs')).href);
  a.evaluatorDigestComputed = mod.EVALUATOR_DIGEST;
  if (deep) {
    const h = run(root, ['scripts/run-vectors.mjs', '--impl', 'node interop/impl-contract/js-reference.mjs']);
    const j = JSON.parse(h.stdout);
    a['harness.vectorsPass'] = j.vectors.pass;
    a['harness.vectorsFail'] = j.vectors.fail;
    a['harness.requirementsPass'] = j.requirements.pass;
    a['harness.requirementsNotRun'] = j.requirements.notRun;
  }
  return a;
}

// Parse the quoted-number table: rows of | key | value | command |, under the heading "Numbers quoted by this kit".
export function parseNumbers(text) {
  const h = /^## (?:\d+\. )?Numbers quoted by this kit[^\n]*$/m.exec(text);
  if (!h) return null;
  const rest = text.slice(h.index + 1);
  const j = rest.indexOf('\n## ');
  const body = j < 0 ? rest : rest.slice(0, j);
  const rows = [];
  for (const line of body.split('\n')) {
    const m = /^\|\s*`([A-Za-z0-9.-]+)`\s*\|\s*`?([^|`]+?)`?\s*\|/.exec(line);
    if (m) rows.push({ key: m[1], value: m[2].trim() });
  }
  return rows;
}

function commandsIn(text) {
  const out = [];
  for (const m of text.matchAll(/`([^`\n]+)`|^\s*((?:node|npm|git)\s[^\n]*)$/gm)) {
    const s = (m[1] ?? m[2] ?? '').trim();
    if (/^(?:node|npm)\s/.test(s)) out.push(s);
  }
  return out;
}

function pathsIn(text) {
  const out = new Set();
  for (const m of text.matchAll(/`([^`\n]+)`/g)) {
    const s = m[1].trim().replace(/[.,;:]+$/, '');
    if (/[\s<>${}|]/.test(s)) continue;
    if (TOP.test(s) || TOP_FILES.has(s)) out.add(s);
  }
  return [...out];
}

// text: optional in-memory replacement of kit documents, keyed by path, used by tests to prove drift is caught.
export async function checkKit({ root = ROOT, text = {}, actuals = null, deep = false } = {}) {
  const problems = [], checked = [], notChecked = [];
  const get = p => (p in text ? text[p] : (existsSync(join(root, p)) ? read(root, p) : null));
  const docs = {};
  for (const p of KIT_FILES) { docs[p] = get(p); if (docs[p] === null) problems.push('missing kit file ' + p); }
  if (problems.length) return { ok: false, problems, checked, notChecked };
  const act = actuals ?? await computeActuals(root, { deep });

  // 1. numbers
  const rows = parseNumbers(docs[KIT_FILES[0]]);
  if (!rows || !rows.length) problems.push('REVIEW-KIT.md has no quoted-number table');
  else {
    const seen = new Set();
    for (const { key, value } of rows) {
      seen.add(key);
      if (!(key in act)) {
        if (key.startsWith('harness.')) { notChecked.push(`${key} (needs --deep)`); continue; }
        problems.push(`quoted number ${key} is not one the checker can recompute`); continue;
      }
      if (String(act[key]) !== value) problems.push(`quoted number ${key} is ${value} but the repository reports ${act[key]}`);
      else checked.push(`${key} = ${value}`);
    }
    for (const must of Object.keys(act)) if (!must.startsWith('harness.') && must !== 'evaluatorDigestComputed' && !seen.has(must)) problems.push('quoted-number table lacks ' + must);
  }
  if (act.evaluatorDigestPinned !== act.evaluatorDigestComputed) problems.push(`pinned evaluator digest ${act.evaluatorDigestPinned} differs from the computed ${act.evaluatorDigestComputed}`);
  else checked.push('pinned evaluator digest equals the computed digest');
  const opSum = ['assess', 'currency', 'canonicalize', 'digest', 'verify-envelope', 'compare'].reduce((n, op) => n + act['vectors.' + op], 0);
  if (opSum !== act.vectorsTotal) problems.push(`vector operation counts sum to ${opSum}, not ${act.vectorsTotal}`);

  // 2. commands and files
  const pkg = JSON.parse(read(root, 'package.json'));
  let help = null;
  for (const p of KIT_FILES) {
    for (const c of commandsIn(docs[p])) {
      const w = c.split(/\s+/);
      if (w[0] === 'npm') {
        if (w[1] === 'run' && w[2] && !(w[2] in pkg.scripts)) problems.push(`${p}: npm script ${w[2]} does not exist`);
        else if (w[1] === 'test' && !pkg.scripts.test) problems.push(`${p}: npm test does not exist`);
        continue;
      }
      if (w[1] === '--check' || w[1] === '--input-type=module' || w[1] === '--test') continue;
      const target = w[1];
      if (!target || target.startsWith('-')) continue;
      const rel = target.replace(/^"?\$KYA\//, '').replace(/"$/, '');
      if (/[<$]/.test(rel)) continue;
      if (/\.(?:mjs|js)$/.test(rel) && !existsSync(join(root, rel))) { problems.push(`${p}: command names missing script ${rel}`); continue; }
      if (rel === 'bin/kya.mjs' && w[2] && !w[2].startsWith('-') && !/[<$]/.test(w[2])) {
        help ??= run(root, ['bin/kya.mjs', '--help']).stdout;
        if (!new RegExp('^\\s+kya ' + w[2].replace(/[^A-Za-z0-9-]/g, '') + '\\b', 'm').test(help)) problems.push(`${p}: kya has no subcommand ${w[2]}`);
      }
    }
    for (const f of pathsIn(docs[p])) {
      const g = f.replace(/[)\]]+$/, '');
      if (g.includes('*')) { const d = g.slice(0, g.indexOf('*')).replace(/\/[^/]*$/, ''); if (!existsSync(join(root, d))) problems.push(`${p}: glob base ${d} does not exist`); continue; }
      if (!existsSync(join(root, g)) && !existsSync(join(root, g.replace(/\/$/, '')))) problems.push(`${p}: referenced path ${g} does not exist`);
    }
    checked.push(`commands and paths in ${p}`);
  }

  // 3. base commit, if git is available
  const base = /Frozen commit to review: `([0-9a-f]{7,40})`/.exec(docs[KIT_FILES[0]]);
  if (!base) problems.push('REVIEW-KIT.md does not name the frozen commit to review');
  else {
    const g = spawnSync('git', ['merge-base', '--is-ancestor', base[1], 'HEAD'], { cwd: root, encoding: 'utf8' });
    if (g.error || g.status === 128) notChecked.push('frozen commit ancestry (git unavailable or commit unknown here)');
    else if (g.status !== 0) problems.push(`frozen commit ${base[1]} is not an ancestor of HEAD`);
    else checked.push(`frozen commit ${base[1]} is an ancestor of HEAD`);
  }

  // 4. required plain statements
  const must = [
    [KIT_FILES[0], 'There is no outside security review today'],
    [KIT_FILES[0], 'does not cover'],
    [KIT_FILES[1], 'No result, score or log from a pilot may be published'],
    [KIT_FILES[1], 'without the written approval of the pilot owner'],
    [KIT_FILES[2], 'No outside implementation has run the vectors'],
  ];
  for (const [p, s] of must) if (!docs[p].includes(s)) problems.push(`${p} lacks the required statement: ${s}`);
  for (const p of KIT_FILES) {
    if (/[<\[](?:SET-BY-OWNER|SECURITY CONTACT|ENFORCEMENT CONTACT)/.test(docs[p])) problems.push(`${p} carries an owner placeholder`);
    if (/(^|[^\w/.-])kya-vc \S+/m.test(docs[p])) problems.push(`${p} has a bare kya-vc command`);
    if (/[^\x09\x0a\x20-\x7e]/.test(docs[p])) problems.push(`${p} is not plain ASCII`);
  }
  notChecked.push('the quality, completeness or correctness of anything the kit describes', 'that the commands pass (only that the scripts, subcommands and npm scripts exist)');
  return { ok: problems.length === 0, problems, checked, notChecked };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    console.log('usage: review-kit-check.mjs [--print] [--deep]\n  default: check the kit against this checkout (exit 0 ok, 1 problems)\n  --print  print every recomputed number as a table row to paste into the kit\n  --deep   also run the reference implementation over all vectors (about ten seconds) and check the harness rows');
    return 0;
  }
  const unknown = args.filter(a => !['--print', '--deep'].includes(a));
  if (unknown.length) { console.error('unknown argument ' + unknown[0]); return 2; }
  if (args.includes('--print')) {
    const a = await computeActuals(ROOT, { deep: args.includes('--deep') });
    for (const [k, v] of Object.entries(a)) console.log(`| \`${k}\` | \`${v}\` |`);
    return 0;
  }
  const r = await checkKit({ deep: args.includes('--deep') });
  console.log(JSON.stringify({ ok: r.ok, problems: r.problems, checkedCount: r.checked.length, notChecked: r.notChecked }, null, 2));
  return r.ok ? 0 : 1;
}
if (isMain(import.meta.url)) process.exitCode = await main();
