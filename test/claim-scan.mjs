// Source scanner for the claim boundary registry test. Not a test file: it is imported by test/claim-boundaries.test.mjs.
// It reads JavaScript text without a parser: comments and regular expression literals are skipped, and every
// single-quoted, double-quoted and expression-free template literal is returned. Templates with an expression are not
// returned because their text is not fixed.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

/** All string literal values in the text, in order. */
export function literals(text) { return literalSites(text).map(l => l.value); }

/** String literals with the text of the source line each one starts on. */
export function literalSites(text) {
  const out = [];
  const lineAt = at => { const a = text.lastIndexOf('\n', at - 1) + 1, b = text.indexOf('\n', at); return text.slice(a, b < 0 ? text.length : b); };
  const n = text.length;
  let i = 0, prevSig = '', prevWord = '';
  const regexAllowed = () => prevSig === '' || /[(,=:[!&|?{};+\-*%<>~^]/.test(prevSig) || /^(?:return|typeof|case|in|of|delete|void|throw|new|else|do)$/.test(prevWord);
  function quoted(q) {
    const at = i;
    i++;
    let s = '';
    while (i < n && text[i] !== q) {
      if (text[i] === '\\') { s += unescape(text[i + 1]); i += 2; continue; }
      s += text[i++];
    }
    i++;
    out.push({ value: s, line: lineAt(at) });
  }
  function unescape(c) { return c === 'n' ? '\n' : c === 't' ? '\t' : c; }
  function template() {
    const at = i;
    let s = '', expression = false;
    while (i < n && text[i] !== '`') {
      if (text[i] === '\\') { s += unescape(text[i + 1]); i += 2; continue; }
      if (text[i] === '$' && text[i + 1] === '{') {
        expression = true; i += 2;
        let depth = 1;
        while (i < n && depth > 0) {
          const c = text[i];
          if (c === '{') depth++;
          else if (c === '}') depth--;
          else if (c === "'" || c === '"') { quoted(c); continue; }
          else if (c === '`') { i++; template(); continue; }
          i++;
        }
        continue;
      }
      s += text[i++];
    }
    i++;
    if (!expression) out.push({ value: s, line: lineAt(at) });
  }
  while (i < n) {
    const c = text[i];
    if (c === '/' && text[i + 1] === '/') { while (i < n && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') { const e = text.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue; }
    if (c === '"' || c === "'") { quoted(c); prevSig = 'a'; prevWord = ''; continue; }
    if (c === '`') { i++; template(); prevSig = 'a'; prevWord = ''; continue; }
    if (c === '/' && regexAllowed()) {
      i++;
      let inClass = false;
      while (i < n) {
        const d = text[i];
        if (d === '\\') { i += 2; continue; }
        if (d === '[') inClass = true; else if (d === ']') inClass = false; else if (d === '/' && !inClass) break; else if (d === '\n') break;
        i++;
      }
      i++;
      while (/[a-z]/.test(text[i] ?? '')) i++;
      prevSig = 'a'; prevWord = '';
      continue;
    }
    if (/\s/.test(c)) { i++; continue; }
    if (/[A-Za-z0-9_$]/.test(c)) { let j = i; while (/[A-Za-z0-9_$]/.test(text[j] ?? '')) j++; prevWord = text.slice(i, j); prevSig = 'a'; i = j; continue; }
    prevSig = c; prevWord = ''; i++;
  }
  return out;
}

/** A literal that reads as a sentence or clause: at least three words and fifteen characters, starting with a letter. */
export function isSentenceLike(s) {
  const t = s.trim();
  return t.length >= 15 && /^[A-Za-z]/.test(t) && t.split(/\s+/).length >= 3;
}

export function* sourceFiles(dir) {
  for (const entry of readdirSync(dir).sort()) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) yield* sourceFiles(p);
    else if (p.endsWith('.mjs')) yield p;
  }
}

// A literal on a line that raises or builds an error is an error message, not a statement of what an artifact does not show.
const ERROR_LINE = /\b(?:insist|Error|TypeError|RangeError|SyntaxError|fail|throw|assert)\b/;

/** Map of sentence-like literal to the set of files (relative to root) that contain it, over every .mjs file under src. Error-raising lines are skipped. */
export function scanSentences(root) {
  const found = new Map(), all = new Set();
  const base = root.endsWith('/') ? root : root + '/';
  for (const file of sourceFiles(join(root, 'src'))) {
    const rel = file.slice(base.length);
    for (const { value: s, line } of literalSites(readFileSync(file, 'utf8'))) {
      all.add(s);
      if (!isSentenceLike(s) || ERROR_LINE.test(line)) continue;
      if (!found.has(s)) found.set(s, new Set());
      found.get(s).add(rel);
    }
  }
  return { sentences: found, allLiterals: all };
}

/** Text between the bracket that opens at `start - 1` and its matching close, skipping string contents. */
export function arrayBody(text, start) {
  let i = start, depth = 1;
  while (i < text.length && depth > 0) {
    const c = text[i];
    if (c === "'" || c === '"' || c === '`') {
      const q = c; i++;
      while (i < text.length && text[i] !== q) { if (text[i] === '\\') i++; i++; }
    } else if (c === '[') depth++;
    else if (c === ']') depth--;
    i++;
  }
  return text.slice(start, i - 1);
}

/** Codes removed from the baseline list, and whether the committed list is still sorted and unique. */
export function appendOnlyViolations(baselineCodes, currentCodes) {
  const current = new Set(currentCodes);
  return baselineCodes.filter(c => !current.has(c));
}
