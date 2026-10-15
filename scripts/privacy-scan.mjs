#!/usr/bin/env node
// KYA privacy scan: a deterministic, dependency-free heuristic scanner that looks for strings that resemble
// personal data in KYA artifacts (manifests, evidence, assessments, incident records, dossiers).
//
// It NEVER prints a matched value. A finding carries the file, a JSON path, a rule ID, the match length and a
// shape mask in which letters and digits are replaced by class markers. The report is stable: same inputs,
// same bytes. Exit code: 0 clean, 1 at least one finding, 2 usage or I/O error.
//
// FALSE POSITIVES (flagged but not personal): four-part version strings that parse as IPv4, long digit runs that
// pass the Luhn check and start with 2 to 6, numbers shaped like a phone number, hex-like words that parse as
// IPv6, any email-shaped test fixture (reserved domains are NOT exempt).
// FALSE NEGATIVES (personal data not flagged): names, postal addresses, free text without a structured
// identifier, national IDs of formats not listed, lowercase IBANs, unspaced Aadhaar numbers, PII hidden inside
// opaque encoded tokens (base64, hex, PEM bodies) or split across fields, values in images or binaries, and
// anything an attacker deliberately obfuscates. A clean scan is NOT evidence that an artifact has no personal data.
import { readFile, readdir, lstat } from 'node:fs/promises';
import { join, relative, basename, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCAN_SCHEMA = 'kya.privacy-scan/v1';
export const MAX_FILE_BYTES = 32 * 1024 * 1024;
const DEFAULT_EXT = ['.json', '.jsonl', '.ndjson'];
const SKIP_DIRS = new Set(['node_modules', '.git']);

export const LIMITATIONS = Object.freeze([
  'Heuristic pattern matching only; not a privacy review, a DPIA or legal advice.',
  'False positives are possible: IPv4-like four-part version strings, Luhn-valid digit runs starting 2 to 6, phone-shaped numbers, email-shaped fixtures.',
  'False negatives are expected: names, addresses, free text, unlisted ID formats, lowercase IBANs, unspaced Aadhaar numbers, data inside opaque encoded tokens, obfuscated or split values.',
  'A clean scan does not show an artifact is free of personal data.'
]);

// ---------- validators ----------
function luhn(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}
function ibanValid(raw) {
  const s = raw.replace(/ /g, '');
  if (s.length < 15 || s.length > 34) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = /[0-9]/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const c of v) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}
const VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function verhoeff(digits) {
  let c = 0;
  const rev = [...digits].reverse();
  for (let i = 0; i < rev.length; i++) c = VERHOEFF_D[c][VERHOEFF_P[i % 8][rev[i].charCodeAt(0) - 48]];
  return c === 0;
}
const DNI_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';
function esIdValid(s) {
  const body = s[0] === 'X' ? '0' + s.slice(1, 8) : s[0] === 'Y' ? '1' + s.slice(1, 8) : s[0] === 'Z' ? '2' + s.slice(1, 8) : s.slice(0, 8);
  return DNI_LETTERS[Number(body) % 23] === s[s.length - 1];
}
function inseeValid(raw) {
  const s = raw.replace(/ /g, '');
  let first13 = s.slice(0, 13);
  let adj = 0n;
  if (first13.slice(5, 7) === '2A') { first13 = first13.slice(0, 5) + '00' + first13.slice(7); adj = 1000000n; }
  else if (first13.slice(5, 7) === '2B') { first13 = first13.slice(0, 5) + '00' + first13.slice(7); adj = 2000000n; }
  if (!/^\d{13}$/.test(first13)) return false;
  const key = 97n - ((BigInt(first13) - adj) % 97n);
  return Number(key) === Number(s.slice(13));
}
function ipv6Valid(t) {
  if (!/^[0-9A-Fa-f:]+$/.test(t) || (t.match(/:/g) || []).length < 2 || /:::/.test(t)) return false;
  const dbl = t.split('::');
  if (dbl.length > 2) return false;
  const groups = part => (part === '' ? [] : part.split(':'));
  const ok = g => g.every(x => /^[0-9A-Fa-f]{1,4}$/.test(x));
  if (dbl.length === 1) { const g = groups(t); return g.length === 8 && ok(g); }
  const a = groups(dbl[0]), b = groups(dbl[1]);
  return ok(a) && ok(b) && a.length + b.length <= 7;
}

// ---------- rules (priority order; earlier rules claim a span, later rules skip overlaps) ----------
const B = '(?<![A-Za-z0-9_])', E = '(?![A-Za-z0-9_])';
const RULES = [
  { id: 'email', category: 'contact', re: /(?<![\w.+%-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g },
  { id: 'iban', category: 'financial', re: new RegExp(`${B}[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{2,4}){3,8}${E}`, 'g'), check: ibanValid },
  { id: 'card', category: 'financial', re: /(?<![\w.-])\d(?:[ -]?\d){12,18}(?![\w-])/g,
    check: m => { const d = m.replace(/[ -]/g, ''); return d.length >= 13 && d.length <= 19 && /^[2-6]/.test(d) && luhn(d); } },
  { id: 'national-id-us-ssn', category: 'national-id', re: new RegExp(`${B}(?!000|666|9\\d\\d)\\d{3}[- ](?!00)\\d{2}[- ](?!0000)\\d{4}${E}`, 'g') },
  { id: 'national-id-uk-nino', category: 'national-id', re: new RegExp(`${B}[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\\d{2} ?\\d{2} ?\\d{2} ?[A-D]${E}`, 'g'),
    check: m => !/^(BG|GB|NK|KN|TN|NT|ZZ)/.test(m) },
  { id: 'national-id-es-dni-nie', category: 'national-id', re: new RegExp(`${B}(?:\\d{8}|[XYZ]\\d{7})[A-HJ-NP-TV-Z]${E}`, 'g'), check: esIdValid },
  { id: 'national-id-fr-insee', category: 'national-id', re: new RegExp(`${B}[12] ?\\d{2} ?(?:0[1-9]|1[0-2]) ?(?:\\d{2}|2[AB]) ?\\d{3} ?\\d{3} ?\\d{2}${E}`, 'g'), check: inseeValid },
  { id: 'national-id-in-aadhaar', category: 'national-id', re: new RegExp(`${B}[2-9]\\d{3} \\d{4} \\d{4}${E}`, 'g'), check: m => verhoeff(m.replace(/ /g, '')) },
  { id: 'ipv6', category: 'network', re: /(?<![A-Za-z0-9:._])[0-9A-Fa-f:]{2,45}(?![A-Za-z0-9:_])/g, check: ipv6Valid },
  { id: 'ipv4', category: 'network', re: /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w]|\.\d)/g },
  { id: 'home-path', category: 'path', re: /(?<![\w])(?:\/(?:Users|home)\/[^/\\\s"'<>:;,]+|[A-Za-z]:[\\/]+Users[\\/]+[^/\\\s"'<>:;,]+)(?=[/\\\s]|$)/g },
  { id: 'phone', category: 'contact', re: /(?<![\w+.-])\+?\(?\d[\d ().-]{6,18}\d(?![\w])/g,
    check: m => {
      const digits = m.replace(/\D/g, '');
      if (digits.length < 8 || digits.length > 15) return false;
      if (/^\d{4}-\d{2}-\d{2}$/.test(m) || /^\d{1,2}[./-]\d{1,2}[./-]\d{2,4}$/.test(m)) return false;
      if (/^\d+(?:\.\d+){1,3}$/.test(m)) return false;
      const seps = (m.match(/[ ().-]/g) || []).length;
      return m.startsWith('+') || m.includes('(') || seps >= 2;
    } }
];

function shapeMask(s) {
  const cut = s.length > 24 ? s.slice(0, 24) : s;
  let out = '';
  for (const ch of cut) out += /[A-Z]/.test(ch) ? 'A' : /[a-z]/.test(ch) ? 'a' : /[0-9]/.test(ch) ? '9' : /[^\x00-\x7f]/.test(ch) ? 'u' : /\s/.test(ch) ? '_' : ch;
  return `[REDACTED ${out}${s.length > 24 ? '...' : ''}]`;
}

const HEX64 = /^[a-f0-9]{64}$/;
const OPAQUE = /^[A-Za-z0-9+/_=-]{40,}$/;
const PEM = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;

// Scan one string. Returns [{rule, category, offset, length, redacted}] without the matched value.
export function scanString(input) {
  const found = [];
  if (typeof input !== 'string' || input.length === 0) return found;
  let text = input;
  for (const m of input.matchAll(PEM)) {
    if (/PRIVATE KEY/.test(m[1])) found.push({ rule: 'private-key-material', category: 'secret', offset: m.index, length: m[0].length, redacted: '[REDACTED private key block]' });
  }
  text = text.replace(PEM, x => ' '.repeat(x.length));
  if (HEX64.test(text) || (!/\s/.test(text) && OPAQUE.test(text))) return found;
  const claimed = [];
  const overlaps = (a, b) => claimed.some(([s, e]) => a < e && b > s);
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.re)) {
      const start = m.index, end = start + m[0].length;
      if (overlaps(start, end)) continue;
      if (rule.check && !rule.check(m[0])) continue;
      claimed.push([start, end]);
      found.push({ rule: rule.id, category: rule.category, offset: start, length: m[0].length, redacted: shapeMask(m[0]) });
    }
  }
  return found.sort((a, b) => a.offset - b.offset || (a.rule < b.rule ? -1 : 1));
}

// ---------- structured rules ----------
const CODED_ID = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;
const DIGEST_KEY = /(?:Digest|^digest|^sha256)$/;
const ID_KEY = /^(?:id|ref|refId|scopeId|runId|checkId|[a-z]+Id)$/;
const RECORD_SCHEMA = /^kya\.(?:incident|evidence|receipt)\//;
const NARRATIVE_KEYS = new Set(['note', 'notes', 'comment', 'comments', 'narrative', 'details', 'detail', 'description', 'message', 'text', 'summary', 'body', 'transcript', 'trace', 'prompt', 'response', 'output', 'reason']);
const SAFE_KEY = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

function pathKey(parent, key, index) {
  return SAFE_KEY.test(key) && scanString(key).length === 0 ? `${parent}.${key}` : `${parent}.[key:${index}]`;
}

function walkValue(value, path, out, depth = 0, structural = true) {
  if (depth > 64) { out.push({ path, rule: 'depth-limit', category: 'structure', offset: 0, length: 0, redacted: '[not scanned]' }); return; }
  if (typeof value === 'string') { for (const f of scanString(value)) out.push({ path, ...f }); return; }
  if (Array.isArray(value)) { value.forEach((v, i) => walkValue(v, `${path}[${i}]`, out, depth + 1, structural)); return; }
  if (value === null || typeof value !== 'object') return;
  const keys = Object.keys(value).sort();
  const recordLike = typeof value.schema === 'string' && RECORD_SCHEMA.test(value.schema);
  keys.forEach((k, i) => {
    const p = pathKey(path, k, i);
    for (const f of scanString(k)) out.push({ path: p, ...f, rule: f.rule, location: 'key' });
    const v = value[k];
    if (structural && typeof v === 'string') {
      if (DIGEST_KEY.test(k) && !HEX64.test(v)) out.push({ path: p, rule: 'digest-field-malformed', category: 'structure', offset: 0, length: v.length, redacted: shapeMask(v) });
      else if (ID_KEY.test(k) && !CODED_ID.test(v)) out.push({ path: p, rule: 'coded-field-free-text', category: 'structure', offset: 0, length: v.length, redacted: shapeMask(v) });
      if (recordLike && NARRATIVE_KEYS.has(k) && v.length > 0 && !HEX64.test(v)) out.push({ path: p, rule: 'digest-only-free-text', category: 'structure', offset: 0, length: v.length, redacted: shapeMask(v) });
    }
    walkValue(v, p, out, depth + 1, structural);
  });
}

// Scan text of one file. Returns {kind, findings}. JSON is parsed; anything else is scanned line by line.
export function scanContent(text, ext = '.json', { rules = 'all' } = {}) {
  const structural = rules !== 'pii';
  const findings = [];
  const lineScan = (line, n, prefix = '') => { for (const f of scanString(line)) findings.push({ path: `${prefix}line:${n}`, ...f }); };
  if (ext === '.jsonl' || ext === '.ndjson') {
    text.split('\n').forEach((line, i) => {
      if (!line.trim()) return;
      try { walkValue(JSON.parse(line), `line:${i + 1}$`, findings, 0, structural); } catch { lineScan(line, i + 1); }
    });
    return { kind: 'jsonl', findings };
  }
  try { walkValue(JSON.parse(text), '$', findings, 0, structural); return { kind: 'json', findings }; } catch { /* fall through to text */ }
  text.split('\n').forEach((line, i) => lineScan(line, i + 1));
  return { kind: 'text', findings };
}

// ---------- files ----------
async function collect(target, exts, files, errors) {
  let st;
  try { st = await lstat(target); } catch { errors.push({ path: target, error: 'not found' }); return; }
  if (st.isSymbolicLink()) { errors.push({ path: target, error: 'symbolic link skipped' }); return; }
  if (st.isFile()) { files.push({ path: target, explicit: true }); return; }
  if (!st.isDirectory()) { errors.push({ path: target, error: 'not a regular file or directory' }); return; }
  for (const e of (await readdir(target, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = join(target, e.name);
    if (e.isDirectory()) await collect(p, exts, files, errors);
    else if (e.isSymbolicLink()) errors.push({ path: p, error: 'symbolic link skipped' });
    else if (e.isFile() && exts.includes(extname(e.name).toLowerCase())) files.push({ path: p, explicit: false });
  }
}
function display(p, cwd) {
  const abs = resolve(p), rel = relative(cwd, abs);
  return !rel.startsWith('..') && !rel.startsWith(sep) && rel !== '' ? rel.split(sep).join('/') : basename(abs);
}

export async function scanPaths(targets, { exts = DEFAULT_EXT, cwd = process.cwd(), rules = 'all' } = {}) {
  const files = [], errors = [];
  for (const t of targets) await collect(t, exts, files, errors);
  const seen = new Set(), scanned = [], findings = [];
  for (const f of files.sort((a, b) => (display(a.path, cwd) < display(b.path, cwd) ? -1 : 1))) {
    const name = display(f.path, cwd);
    if (seen.has(name)) continue;
    seen.add(name);
    const st = await lstat(f.path);
    if (st.size > MAX_FILE_BYTES) { errors.push({ path: name, error: 'file larger than limit, not scanned' }); continue; }
    const buf = await readFile(f.path);
    if (buf.includes(0)) { errors.push({ path: name, error: 'binary file, not scanned' }); continue; }
    const r = scanContent(buf.toString('utf8'), extname(f.path).toLowerCase(), { rules });
    scanned.push({ file: name, kind: r.kind });
    for (const x of r.findings) findings.push({ file: name, ...x });
  }
  findings.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.path < b.path ? -1 : a.path > b.path ? 1 : a.offset - b.offset || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0)));
  errors.sort((a, b) => (a.path < b.path ? -1 : 1));
  const byRule = {};
  for (const f of findings) byRule[f.rule] = (byRule[f.rule] || 0) + 1;
  return {
    schema: SCAN_SCHEMA,
    rules,
    clean: findings.length === 0 && errors.length === 0,
    summary: { files: scanned.length, findings: findings.length, errors: errors.length, byRule: Object.fromEntries(Object.entries(byRule).sort()) },
    scanned, findings, errors, limitations: LIMITATIONS
  };
}

function text(report) {
  const lines = [`privacy scan: ${report.summary.files} files, ${report.summary.findings} findings, ${report.summary.errors} errors`];
  for (const f of report.findings) lines.push(`${f.file} ${f.path} ${f.rule} len=${f.length} ${f.redacted}`);
  for (const e of report.errors) lines.push(`error ${e.path}: ${e.error}`);
  lines.push('A clean scan is not evidence of absence. See docs/PRIVACY.md for limits.');
  return lines.join('\n') + '\n';
}

async function main(argv) {
  const targets = []; let format = 'json'; let rules = 'all'; let exts = DEFAULT_EXT;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--format') format = argv[++i];
    else if (a === '--rules') rules = argv[++i];
    else if (a === '--ext') exts = String(argv[++i] || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
    else if (a === '--help' || a === '-h') { process.stdout.write('usage: privacy-scan.mjs [--format json|text] [--rules all|pii] [--ext .json,.jsonl] <file-or-dir>...\nexit 0 clean, 1 findings, 2 error\n'); return 0; }
    else if (a.startsWith('--')) { process.stderr.write(`unknown option ${a}\n`); return 2; }
    else targets.push(a);
  }
  if (!targets.length || !['json', 'text'].includes(format) || !['all', 'pii'].includes(rules) || !exts.length) { process.stderr.write('usage: privacy-scan.mjs [--format json|text] [--rules all|pii] [--ext .json,.jsonl] <file-or-dir>...\n'); return 2; }
  const report = await scanPaths(targets, { exts, rules });
  process.stdout.write(format === 'json' ? JSON.stringify(report, null, 2) + '\n' : text(report));
  if (report.findings.length) return 1;
  return report.errors.length ? 2 : 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).then(c => { process.exitCode = c; }, e => { process.stderr.write(`privacy-scan failed: ${e.message}\n`); process.exitCode = 2; });
}
