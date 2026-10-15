import { readFileSync } from 'node:fs';

// Machine-readable claim-boundary codes. A code states something an artifact does NOT show.
// The registry is evidence/claim-boundaries.json; this module only reads it and never changes any artifact output.
const REGISTRY = JSON.parse(readFileSync(new URL('../../evidence/claim-boundaries.json', import.meta.url), 'utf8'));

const deepFreeze = (v) => { if (v && typeof v === 'object') { for (const k of Object.keys(v)) deepFreeze(v[k]); Object.freeze(v); } return v; };
deepFreeze(REGISTRY);

const BY_CODE = new Map(REGISTRY.codes.map((c) => [c.code, c]));
const BY_STRING = new Map();
for (const c of REGISTRY.codes) for (const s of c.strings) {
  if (!BY_STRING.has(s)) BY_STRING.set(s, []);
  BY_STRING.get(s).push(c.code);
}

export const CLAIM_BOUNDARY_CODES = Object.freeze(REGISTRY.codes.map((c) => c.code).sort());

/** Sorted unique codes for a list of limit strings. Throws on a string the registry does not know, so new limit text cannot ship without a code. */
export function codesForLimitStrings(strings) {
  if (!Array.isArray(strings)) throw new TypeError('Limit strings must be an array');
  const out = new Set();
  for (const s of strings) {
    if (typeof s !== 'string') throw new TypeError('Limit string must be a string');
    const codes = BY_STRING.get(s);
    if (!codes) throw new RangeError(`Unknown claim boundary string: ${s}`);
    for (const c of codes) out.add(c);
  }
  return [...out].sort();
}

/** Registry entry for a code: { code, meaning, artifactKinds, strings }. Throws on an unknown code. */
export function describe(code) {
  const entry = BY_CODE.get(code);
  if (!entry) throw new RangeError(`Unknown claim boundary code: ${String(code)}`);
  return entry;
}
