import { createHash } from 'node:crypto';

const MAX_BYTES = 1_048_576;
const MAX_DEPTH = 32;
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);

export function insist(condition, message) {
  if (!condition) throw new Error(message);
}

export function canonical(value) {
  let nodes = 0;
  const ancestors = new Set();
  function visit(v, depth) {
    insist(++nodes <= 100_000 && depth <= MAX_DEPTH, 'JSON resource limit');
    if (v === null) return 'null';
    if (typeof v === 'string') {
      insist(v.length <= MAX_BYTES, 'JSON string too large');
      return JSON.stringify(v);
    }
    if (typeof v === 'boolean') return String(v);
    if (typeof v === 'number') {
      insist(Number.isFinite(v) && (!Number.isInteger(v) || Number.isSafeInteger(v)), 'Unsafe JSON number');
      return JSON.stringify(v);
    }
    insist(typeof v === 'object', 'Unsupported JSON value');
    insist(!ancestors.has(v), 'Cyclic JSON');
    ancestors.add(v);
    let result;
    if (Array.isArray(v)) {
      insist(v.length <= 100_000, 'JSON array too large');
      const keys = Reflect.ownKeys(v);
      insist(keys.length === v.length + 1 && keys.includes('length'), 'Sparse or extended JSON array');
      const parts = [];
      for (let i = 0; i < v.length; i++) {
        const d = Object.getOwnPropertyDescriptor(v, String(i));
        insist(d && 'value' in d && d.enumerable, 'JSON accessors are forbidden');
        parts.push(visit(d.value, depth + 1));
      }
      result = '[' + parts.join(',') + ']';
    } else {
      insist(Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null, 'Expected plain JSON object');
      const keys = Reflect.ownKeys(v);
      insist(keys.every(k => typeof k === 'string' && !forbidden.has(k)), 'Forbidden JSON member');
      result = '{' + keys.sort().map(k => {
        const d = Object.getOwnPropertyDescriptor(v, k);
        insist(d && 'value' in d && d.enumerable, 'JSON accessors or hidden members are forbidden');
        return JSON.stringify(k) + ':' + visit(d.value, depth + 1);
      }).join(',') + '}';
    }
    ancestors.delete(v);
    insist(result.length <= MAX_BYTES, 'JSON value too large');
    return result;
  }
  const result = visit(value, 0);
  insist(Buffer.byteLength(result, 'utf8') <= MAX_BYTES, 'JSON byte limit');
  return result;
}

export function hashBytes(bytes) {
  insist(typeof bytes === 'string' || bytes instanceof Uint8Array, 'Expected bytes or text');
  return createHash('sha256').update(bytes).digest('hex');
}

export function digest(value) { return hashBytes(canonical(value)); }

/** Capture dense array membership without invoking element getters or Proxy GET views. */
export function captureArrayItems(value, max, label = 'JSON array') {
  insist(Array.isArray(value), `${label}: expected array`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const length = descriptors.length?.value;
  insist(Number.isSafeInteger(length) && length >= 0 && length <= max, `${label}: exceeds limit`);
  const keys = Reflect.ownKeys(descriptors);
  insist(keys.length === length + 1 && keys.includes('length'), `${label}: sparse or extended array`);
  const items = [];
  for (let i = 0; i < length; i++) {
    const d = descriptors[String(i)];
    insist(d && 'value' in d && d.enumerable, `${label}: accessors are forbidden`);
    items.push(d.value);
  }
  return items;
}

/** Strict JSON parser: rejects duplicates before JSON.parse can erase them. */
export function parseJson(text) {
  insist(typeof text === 'string' && Buffer.byteLength(text, 'utf8') <= MAX_BYTES, 'JSON byte limit');
  let p = 0, nodes = 0;
  const ws = () => { while (/^[\x20\t\r\n]$/.test(text[p] ?? '')) p++; };
  function string() {
    const start = p++;
    while (p < text.length) {
      if (text[p] === '"') { p++; return JSON.parse(text.slice(start, p)); }
      if (text[p] === '\\') { p += 2; } else p++;
    }
    throw new Error('Unterminated JSON string');
  }
  function value(depth) {
    ws();
    insist(++nodes <= 100_000 && depth <= MAX_DEPTH, 'JSON resource limit');
    const c = text[p];
    if (c === '"') return string();
    if (c === '{') {
      p++; ws();
      const obj = {}, keys = new Set();
      if (text[p] === '}') { p++; return obj; }
      while (true) {
        ws(); insist(text[p] === '"', 'Expected JSON member');
        const k = string();
        insist(!keys.has(k) && !forbidden.has(k), 'Duplicate or forbidden JSON member');
        keys.add(k); ws(); insist(text[p++] === ':', 'Expected JSON colon');
        obj[k] = value(depth + 1); ws();
        if (text[p] === '}') { p++; return obj; }
        insist(text[p++] === ',', 'Expected JSON comma');
      }
    }
    if (c === '[') {
      p++; ws(); const arr = [];
      if (text[p] === ']') { p++; return arr; }
      while (true) {
        arr.push(value(depth + 1)); ws();
        if (text[p] === ']') { p++; return arr; }
        insist(text[p++] === ',', 'Expected JSON comma');
      }
    }
    for (const [token, v] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(token, p)) { p += token.length; return v; }
    }
    const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(p));
    insist(m, 'Invalid JSON token'); p += m[0].length;
    const n = Number(m[0]);
    insist(Number.isFinite(n) && (!Number.isInteger(n) || Number.isSafeInteger(n)), 'Unsafe JSON number');
    return n;
  }
  const result = value(0); ws(); insist(p === text.length, 'Trailing JSON content');
  canonical(result);
  return result;
}

export function exactKeys(v, expected, label = 'Object') {
  insist(v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype, `${label}: expected object`);
  insist(Object.keys(v).length === expected.length && expected.every(k => Object.hasOwn(v, k)), `${label}: unexpected or missing fields`);
}
