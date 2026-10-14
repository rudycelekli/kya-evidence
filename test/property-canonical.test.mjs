import assert from 'node:assert/strict';
import { canonical, digest, parseJson } from '../src/index.mjs';
import { property, randomJson, randomKey, randomString, randomNumber, reorderKeys, clone } from './helpers-fuzz.mjs';

const MAX_BYTES = 1_048_576;
const throwsAny = (fn, label) => assert.throws(fn, Error, label);

property('canonical is deterministic under random key insertion order and matches digest', 250, (rng) => {
  const x = randomJson(rng, 0, { surrogates: true });
  const y = reorderKeys(rng, x);
  assert.equal(canonical(x), canonical(y));
  assert.equal(digest(x), digest(y));
});

property('canonical is idempotent through JSON.parse and parseJson', 250, (rng) => {
  const x = randomJson(rng, 0, { surrogates: true });
  const c = canonical(x);
  const viaJson = JSON.parse(c);
  assert.equal(canonical(viaJson), c);
  assert.equal(canonical(parseJson(c)), c);
  assert.equal(digest(viaJson), digest(x));
  // the output is pure ASCII-safe JSON text: no raw control characters
  assert.ok(!new RegExp('[\\u0000-\\u001f]').test(c));
  assert.equal(Buffer.from(c, 'utf8').toString('utf8'), c);
});

property('digest equality holds if and only if canonical equality', 250, (rng) => {
  const x = randomJson(rng);
  let y;
  const mode = rng.int(0, 3);
  if (mode === 0) y = reorderKeys(rng, x);
  else if (mode === 1) y = randomJson(rng);
  else { y = clone([x])[0]; (function perturb(v, parent, key) {
    if (Array.isArray(v) && v.length) perturb(rng.pick(v), v, rng.int(0, v.length - 1));
    else if (v && typeof v === 'object' && Object.keys(v).length) { const k = rng.pick(Object.keys(v)); perturb(v[k], v, k); }
    else if (parent) parent[key] = typeof v === 'string' ? v + 'x' : typeof v === 'number' ? (v + 1 > Number.MAX_SAFE_INTEGER ? v - 1 : v + 1) : v === null ? false : typeof v === 'boolean' ? !v : 'changed';
    else y = [y];
  })(y, null, null); }
  assert.equal(canonical(x) === canonical(y), digest(x) === digest(y));
  if (mode === 0) assert.equal(digest(x), digest(y));
});

property('canonical separates values that merely look alike', 120, (rng) => {
  const s = randomString(rng, { max: 6 });
  const forms = [{ a: s }, { a: [s] }, { a: s + ' ' }, { a: { b: s } }, [s], s, { a: s, b: null }, { a: s, b: false }, { a: 1 }, { a: '1' }, { a: [1] }, { a: true }, { a: 'true' }, { a: null }, { a: 'null' }];
  const seen = new Map();
  for (const f of forms) {
    const d = digest(f), c = canonical(f);
    if (seen.has(d)) assert.equal(seen.get(d), c, 'digest collision between different canonical texts');
    seen.set(d, c);
  }
  assert.equal(new Set(forms.map(canonical)).size, new Set(forms.map(digest)).size);
});

property('parseJson accepts pretty printed text and agrees with canonical', 200, (rng) => {
  const x = randomJson(rng);
  const text = JSON.stringify(x, null, rng.pick([undefined, 0, 1, 2, '\t']));
  assert.equal(canonical(parseJson(text)), canonical(x));
  assert.equal(canonical(parseJson(' \n\t\r' + text + '\r\n ')), canonical(x));
});

const escapeKey = (rng, k) => '"' + [...k].map(ch => rng.bool(0.4) ? Array.from({ length: ch.length }, (_, i) => '\\u' + ch.charCodeAt(i).toString(16).padStart(4, '0')).join('') : JSON.stringify(ch).slice(1, -1)).join('') + '"';

property('parseJson rejects duplicate keys including escaped spellings of the same key', 200, (rng) => {
  const k = randomKey(rng);
  const v1 = randomJson(rng, 3), v2 = randomJson(rng, 3);
  const dupFirst = rng.bool();
  const members = [`${escapeKey(rng, k)}:${JSON.stringify(v1)}`, `${escapeKey(rng, 'other' + k)}:0`, `${escapeKey(rng, k)}:${JSON.stringify(v2)}`];
  const text = '{' + (dupFirst ? members : [members[0], members[2], members[1]]).join(',') + '}';
  throwsAny(() => parseJson(text), text);
  // the same document nested one level down must be rejected too
  throwsAny(() => parseJson(`[{"x":${text}}]`), text);
  // whereas distinct keys are fine
  assert.equal(typeof parseJson(`{${members[0]},${members[1]}}`), 'object');
});

property('forbidden members are rejected by parseJson and canonical in every spelling', 60, (rng) => {
  const name = rng.pick(['__proto__', 'prototype', 'constructor']);
  const spelled = rng.bool() ? JSON.stringify(name) : escapeKey(rng, name);
  const text = rng.bool() ? `{${spelled}:${JSON.stringify(randomJson(rng, 4))}}` : `{"ok":[{${spelled}:null}]}`;
  throwsAny(() => parseJson(text), text);
  const own = JSON.parse(text); // JSON.parse creates a real own property, canonical must refuse it
  throwsAny(() => canonical(own), text);
  const o = {}; Object.defineProperty(o, name, { value: 1, enumerable: true, configurable: true, writable: true });
  throwsAny(() => canonical({ nested: [o] }));
  const viaSet = Object.create(null); Object.defineProperty(viaSet, name, { value: 1, enumerable: false });
  throwsAny(() => canonical(viaSet));
});

property('canonical rejects accessors, hidden members, symbols, exotic objects and sparse arrays', 120, (rng) => {
  const wrap = v => rng.pick([() => v, () => [v], () => ({ k: v }), () => [{ k: [v] }]])();
  const bad = [];
  const getter = {}; Object.defineProperty(getter, 'g', { get: () => 1, enumerable: true }); bad.push(getter);
  const hidden = { visible: 1 }; Object.defineProperty(hidden, 'h', { value: 2, enumerable: false }); bad.push(hidden);
  const arrGetter = [0, 1]; Object.defineProperty(arrGetter, 1, { get: () => 5, enumerable: true }); bad.push(arrGetter);
  bad.push({ [Symbol('s')]: 1 }, { k: Symbol('v') }, [Symbol.iterator]);
  bad.push([1, , 3], Object.assign([1, 2], { extra: 3 }), new Array(3));
  bad.push(undefined, () => 1, 10n, new Date(0), new Map(), new Set(), /x/, new (class A { constructor() { this.a = 1; } })(), Object.create({ inherited: 1 }), new Uint8Array(2), Buffer.from('a'), new String('s'), new Number(1), new Boolean(true));
  bad.push({ k: undefined }, [undefined], { k() {} });
  const cyc = { a: {} }; cyc.a.back = cyc; bad.push(cyc);
  const cycArr = [[]]; cycArr[0].push(cycArr); bad.push(cycArr);
  const self = []; self.push(self); bad.push(self);
  for (const b of bad) throwsAny(() => canonical(wrap(b)));
  // a shared (non cyclic) reference is legal and must not be mistaken for a cycle
  const shared = { s: 1 };
  assert.equal(canonical({ a: shared, b: shared, c: [shared, shared] }), '{"a":{"s":1},"b":{"s":1},"c":[{"s":1},{"s":1}]}');
  // a null-prototype object is a plain object
  assert.equal(canonical(Object.assign(Object.create(null), { z: 1, a: 2 })), '{"a":2,"z":1}');
});

property('canonical and parseJson reject unsupported numbers and accept the documented safe range', 150, (rng) => {
  const bad = [NaN, Infinity, -Infinity, 2 ** 53, -(2 ** 53), 2 ** 53 + 2, 1e21, -1e21, 1e300, 2 ** 60, Number.MAX_VALUE,
    rng.int(1, 1000) * 2 ** 53 * (rng.bool() ? 1 : -1)];
  for (const n of bad) { throwsAny(() => canonical(n), String(n)); throwsAny(() => canonical({ n }), String(n)); }
  for (const t of ['9007199254740992', '-9007199254740992', '1e999', '-1e999', '1e21', '12345678901234567890']) throwsAny(() => parseJson(t), t);
  const n = randomNumber(rng);
  const ok = Number.isFinite(n) && (!Number.isInteger(n) || Number.isSafeInteger(n));
  if (ok) { assert.equal(JSON.parse(canonical(n)), Object.is(n, -0) ? 0 : n); assert.equal(parseJson(canonical([n]))[0], Object.is(n, -0) ? 0 : n); }
  else throwsAny(() => canonical(n));
  // the safe-integer boundary itself
  for (const s of [Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) assert.equal(JSON.parse(canonical(s)), s);
});

property('lone surrogates are deterministic, escaped and round trip (documented behaviour: accepted)', 120, (rng) => {
  const s = randomString(rng, { surrogates: true, max: 8 }) + String.fromCharCode(rng.int(0xd800, 0xdfff));
  const c = canonical({ [s]: s, list: [s] });
  assert.ok(!new RegExp('[\\u0000-\\u001f]').test(c));
  const back = JSON.parse(c);
  assert.equal(back[s], s);
  assert.equal(canonical(back), c);
  assert.equal(canonical(parseJson(c)), c);
  // well formed pairs are never split into escapes of their halves
  assert.equal(canonical('😀'), '"😀"');
});

property('depth limit is exactly 32 for canonical and parseJson, for arrays and objects alike', 40, (rng) => {
  const build = (n, leaf) => { let v = leaf; for (let i = 0; i < n; i++) v = rng.bool() ? [v] : { k: v }; return v; };
  const nest = rng.int(1, 32);
  const okValue = build(nest, rng.pick([null, 1, 'x', true]));
  assert.equal(canonical(parseJson(JSON.stringify(okValue))), canonical(okValue));
  const tooDeep = build(33 + rng.int(0, 5), null);
  throwsAny(() => canonical(tooDeep));
  throwsAny(() => parseJson(JSON.stringify(tooDeep)));
  // exactly 32 containers around a leaf is the last accepted shape; 33 is the first rejected
  assert.doesNotThrow(() => canonical(build(32, null)));
  assert.throws(() => canonical(build(33, null)));
  assert.doesNotThrow(() => parseJson(JSON.stringify(build(32, 1))));
  assert.throws(() => parseJson(JSON.stringify(build(33, 1))));
});

property('size and node limits hold at the boundary', 6, (rng) => {
  // string byte limit: output is JSON text including quotes
  const ch = rng.pick(['a', 'é', '€', '😀']);
  const unit = Buffer.byteLength(ch);
  const fit = Math.floor((MAX_BYTES - 2) / unit);
  const exact = ch.repeat(fit);
  assert.ok(Buffer.byteLength(canonical(exact)) <= MAX_BYTES);
  throwsAny(() => canonical(ch.repeat(fit + 1)));
  throwsAny(() => canonical('a'.repeat(MAX_BYTES)));
  throwsAny(() => parseJson('"' + 'a'.repeat(MAX_BYTES) + '"'));
  // array and node counts
  throwsAny(() => canonical(new Array(100_001).fill(0)));
  throwsAny(() => canonical(Array.from({ length: 10 }, () => new Array(10_000).fill(0))));
  throwsAny(() => parseJson('[' + '0,'.repeat(100_000) + '0]'));
  // many members in one object
  const big = {}; for (let i = 0; i < 100_001; i++) big['k' + i] = 0;
  throwsAny(() => canonical(big));
});

const KNOWN_REJECTIONS = /Duplicate or forbidden|Unsafe JSON number|resource limit|byte limit|too large/;
property('parseJson is a strict subset of JSON.parse: differential fuzz over mutated documents', 400, (rng) => {
  let text = JSON.stringify(randomJson(rng, 0, { surrogates: false }), null, rng.pick([0, 2]));
  const alphabet = ['{', '}', '[', ']', ',', ':', '"', '\\', ' ', '\n', '0', '-', '.', 'e', 'E', '+', 't', 'u', 'n', 'l', '1', '\u0000', '﻿', ' ', '/'];
  for (let m = rng.int(0, 3); m > 0 && text.length; m--) {
    const at = rng.int(0, text.length - 1), op = rng.int(0, 3);
    if (op === 0) text = text.slice(0, at) + text.slice(at + 1);
    else if (op === 1) text = text.slice(0, at) + rng.pick(alphabet) + text.slice(at);
    else if (op === 2) text = text.slice(0, at) + rng.pick(alphabet) + text.slice(at + 1);
    else text = text.slice(0, at) + text.slice(at, at + 1).repeat(2) + text.slice(at + 1);
  }
  let native, nativeError;
  try { native = JSON.parse(text); } catch (e) { nativeError = e; }
  let mine, mineError;
  try { mine = parseJson(text); } catch (e) { mineError = e; }
  if (mine !== undefined || !mineError) {
    assert.ok(!nativeError, 'parseJson accepted text that JSON.parse rejects: ' + JSON.stringify(text));
    assert.equal(canonical(mine), canonical(native));
  } else if (!nativeError) {
    assert.match(mineError.message, KNOWN_REJECTIONS, 'unexpected parseJson rejection of valid JSON: ' + JSON.stringify(text));
  }
});
