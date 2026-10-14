import assert from 'node:assert/strict';
import { canonical, digest, validateManifest, validatePolicy, validateEvidence, validateProfile, validateIncident, hashBytes, keyId } from '../src/index.mjs';
import { manifest, profile, policy, payload } from './helpers.mjs';
import { property, keyPool, hex, randomId, clone } from './helpers-fuzz.mjs';

const T0 = '2026-10-13T12:00:00.000Z';
const incident = () => ({ schema: 'kya.incident/v1', id: 'inc:1', subjectDigest: hashBytes('s'), kind: 'report', severity: 'high', refId: null, reportedAt: T0, detailsDigest: hashBytes('d') });
const resolution = () => ({ ...incident(), id: 'res:1', kind: 'resolution', refId: 'inc:1' });
const withParty = () => { const m = manifest(); m.principal.accountableParty = { kind: 'legal-entity', ref: 'entity:acme' }; return m; };
const richPolicy = () => {
  const p = policy();
  p.trustedKeys = keyPool.slice(0, 3).map((k, i) => ({ id: keyId(k.pem), publicKey: k.pem, role: i ? 'independent' : 'self' }));
  p.allowedSources = ['fixture', 'runtime'];
  p.requirePrincipalBinding = true; p.maxAssessmentAgeSeconds = 86400;
  p.revokedKeyIds = [hashBytes('rk')]; p.revokedEvidenceIds = ['ev:revoked']; p.revokedSubjectDigests = [hashBytes('rs')];
  return p;
};
const richManifest = () => { const m = withParty(); m.system.tools.push({ id: 'shell', version: '2', permissions: ['read', 'write'] }); return m; };
const SUBJECTS = [
  ['manifest', validateManifest, () => manifest()], ['manifest-party', validateManifest, richManifest],
  ['policy', validatePolicy, () => policy()], ['policy-rich', validatePolicy, richPolicy],
  ['evidence', validateEvidence, () => payload()], ['profile', validateProfile, () => profile()],
  ['incident-report', validateIncident, incident], ['incident-resolution', validateIncident, resolution],
];

// ---- mutation engine --------------------------------------------------------
const OPTIONAL = new Set(['requirePrincipalBinding', 'maxAssessmentAgeSeconds', 'accountableParty']);
const ENUM_KEYS = new Set(['schema', 'outcome', 'source', 'kind', 'severity', 'role', 'dimension']);
const kindOf = v => v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v;
function walk(v, path = [], out = []) {
  out.push(path);
  if (Array.isArray(v)) v.forEach((x, i) => walk(x, [...path, i], out));
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) walk(v[k], [...path, k], out);
  return out;
}
const at = (root, path) => path.reduce((v, k) => v[k], root);
const strictString = (path, v, parent) => typeof v === 'string' && (/^[a-f0-9]{64}$/.test(v) || ENUM_KEYS.has(path.at(-1)) || (Array.isArray(parent) && path.at(-2) === 'allowedSources'));
const swapCase = (rng, s) => { let t = s; for (let n = 0; n < 8 && t === s; n++) t = [...s].map(c => rng.bool(0.5) ? (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()) : c).join(''); return t === s ? s.toUpperCase() : t; };
const BOUNDARY_LENGTHS = [0, 1, 23, 24, 25, 63, 64, 65, 127, 128, 129, 511, 512, 513, 2000, 2001];
const ODD_STRINGS = ['', ' ', '\u0000', 'a\nb', '\u007f', 'café', '../x', 'a b', '-lead', ':lead', 'A', '0', 'null', '__proto__'];
const BAD_STAMPS = ['2026-10-13T12:00:00Z', '2026-10-13T12:00:00.000+00:00', '2026-10-13t12:00:00.000z', '2026-02-30T12:00:00.000Z', '2026-13-01T12:00:00.000Z', '2026-10-13T24:00:00.000Z', '2026-10-13T12:00:60.000Z', ' 2026-10-13T12:00:00.000Z', '2026-10-13T12:00:00.000Z ', '+002026-10-13T12:00:00.000Z', '2026-10-13 12:00:00.000Z', '2026-10-13T12:00:00.0000Z', '2026-10-13T12:00:00.00Z', '2026-10-13', '1760356800000', ''];

function mutate(rng, doc) {
  const paths = walk(doc), nonRoot = paths.filter(p => p.length);
  const path = rng.pick(nonRoot), parentPath = path.slice(0, -1), key = path.at(-1), parent = at(doc, parentPath), value = parent[key];
  const containers = paths.filter(p => { const v = at(doc, p); return v && typeof v === 'object' && !Array.isArray(v); });
  const op = rng.int(0, 8);
  switch (op) {
    case 0: { // delete a member or element
      const isOptional = !Array.isArray(parent) && OPTIONAL.has(key);
      if (Array.isArray(parent)) parent.splice(key, 1); else delete parent[key];
      return { desc: `delete ${path.join('.')}`, mustThrow: !Array.isArray(parent) && !isOptional };
    }
    case 1: { // add an unknown member to some object
      const p = rng.pick(containers), o = at(doc, p);
      o['zz_extra'] = rng.pick([1, 'x', null, [], {}]);
      return { desc: `add member under ${p.join('.') || '<root>'}`, mustThrow: true };
    }
    case 2: { // rename a member (also onto another existing member name)
      if (Array.isArray(parent)) return { desc: 'noop', mustThrow: false };
      const names = Object.keys(parent).filter(k => k !== key);
      const to = names.length && rng.bool(0.3) ? rng.pick(names) : key + '_r';
      const v = parent[key]; delete parent[key]; parent[to] = v;
      return { desc: `rename ${path.join('.')} -> ${to}`, mustThrow: !names.includes(to) };
    }
    case 3: { // change JSON type
      const options = [0, 1, -1, 1.5, 'x', '', true, false, null, [], {}, [1], { a: 1 }].filter(c => kindOf(c) !== kindOf(value));
      parent[key] = rng.pick(options);
      return { desc: `retype ${path.join('.')} to ${canonical(parent[key])}`, mustThrow: true };
    }
    case 4: { // truncate or extend a string
      if (typeof value !== 'string') return { desc: 'noop', mustThrow: false };
      const strict = strictString(path, value, parent);
      const s = rng.bool() ? value.slice(0, rng.int(0, Math.max(0, value.length - 1))) : value + rng.pick(['a', 'A', '0', ' ', 'zz', '\u0000', 'x'.repeat(rng.int(1, 600))]);
      parent[key] = s;
      return { desc: `resize ${path.join('.')}`, mustThrow: strict && s !== value };
    }
    case 5: { // flip the case of a string
      if (typeof value !== 'string') return { desc: 'noop', mustThrow: false };
      const s = swapCase(rng, value); parent[key] = s;
      return { desc: `case flip ${path.join('.')}`, mustThrow: strictString(path, value, parent) && s !== value && /[A-Za-z]/.test(value) && s !== value };
    }
    case 6: { // boundary length string of identifier characters
      if (typeof value !== 'string') return { desc: 'noop', mustThrow: false };
      parent[key] = 'a'.repeat(rng.pick(BOUNDARY_LENGTHS));
      return { desc: `length boundary ${path.join('.')}`, mustThrow: false };
    }
    case 7: { // odd strings
      if (typeof value !== 'string') return { desc: 'noop', mustThrow: false };
      parent[key] = rng.pick(ODD_STRINGS);
      return { desc: `odd string ${path.join('.')}`, mustThrow: false };
    }
    default: { // timestamps
      if (typeof value !== 'string' || !/At$/.test(String(key))) return { desc: 'noop', mustThrow: false };
      if (rng.bool(0.6)) { parent[key] = rng.pick(BAD_STAMPS); return { desc: `bad stamp ${path.join('.')}`, mustThrow: true }; }
      const base = Date.parse(value), delta = rng.pick([0, 1, -1, 1000, -1000, 86_400_000, -86_400_000]);
      parent[key] = new Date(base + delta).toISOString();
      return { desc: `shift stamp ${path.join('.')} by ${delta}`, mustThrow: false };
    }
  }
}

for (const [name, validate, build] of SUBJECTS) {
  property("single mutations of a valid " + name + " throw or settle to a stable value without touching the input", 150, (rng) => {
    const doc = build();
    assert.doesNotThrow(() => validate(doc), 'baseline must be valid');
    const m = mutate(rng, doc);
    const snapshot = clone(doc);
    let out, error;
    try { out = validate(doc); } catch (e) { error = e; }
    assert.deepEqual(doc, snapshot, `validator mutated its input (${m.desc})`);
    if (m.mustThrow) assert.ok(error, `expected rejection: ${m.desc} -> ${canonical(doc).slice(0, 300)}`);
    if (error) { assert.ok(error instanceof Error); return; }
    assert.notEqual(out, doc, 'validator must return a fresh value');
    assert.deepEqual(out, JSON.parse(canonical(doc)), `result differs from the canonical form of the input (${m.desc})`);
    assert.deepEqual(validate(out), out, `validate is not idempotent (${m.desc})`);
    assert.equal(digest(validate(out)), digest(out));
  });
}

// ---- boundary tables --------------------------------------------------------
const idOf = (rng, n) => { let s = randomId(rng, 128); while (s.length < n) s += randomId(rng, 128); return s.slice(0, n).replace(/[:._/-]$/, 'a'); };
const FIELDS = [
  ['manifest', validateManifest, () => manifest(), [['agent', 'id', 128, 'id'], ['agent', 'name', 512, 'text'], ['agent', 'version', 128, 'text'], ['principal', 'id', 128, 'id'], ['system', 'harness', 128, 'text'], ['system', 'harnessVersion', 128, 'text'], ['system', 'model', 128, 'text'], ['scope', 'purpose', 512, 'text']]],
  ['evidence', validateEvidence, () => payload(), [['id', null, 128, 'id'], ['runId', null, 128, 'id'], ['checkId', null, 128, 'id'], ['scopeId', null, 128, 'id']]],
  ['profile', validateProfile, () => profile(), [['id', null, 128, 'id'], ['version', null, 64, 'text'], ['title', null, 512, 'text']]],
  ['incident', validateIncident, resolution, [['id', null, 128, 'id'], ['refId', null, 128, 'id']]],
  ['policy', validatePolicy, () => policy(), [['id', null, 128, 'id'], ['scopeId', null, 128, 'id']]],
];
property('text and identifier fields accept exactly their documented maximum length', 60, (rng) => {
  const [name, validate, build, fields] = rng.pick(FIELDS);
  const [a, b, max, kind] = rng.pick(fields);
  const set = (doc, v) => { if (b) doc[a][b] = v; else doc[a] = v; };
  const make = n => kind === 'id' ? idOf(rng, n) : 'x'.repeat(n);
  const doc = build(); set(doc, make(max));
  assert.doesNotThrow(() => validate(doc), `${name}.${a}${b ? '.' + b : ''} at ${max}`);
  const over = build(); set(over, make(max + 1)); assert.throws(() => validate(over), Error, `${name}.${a} at ${max + 1}`);
  const empty = build(); set(empty, ''); assert.throws(() => validate(empty));
  const ctl = build(); set(ctl, 'a' + rng.pick(['\u0000', '\u001f', '\u007f', '\n']) + 'b'); assert.throws(() => validate(ctl));
  if (kind === 'id') for (const bad of ['-x', ':x', '.x', '/x', 'a b', 'café', 'a b', 'a\\b', 'a*']) { const d = build(); set(d, bad); assert.throws(() => validate(d), Error, bad); }
});

property('timestamp ordering rules match an exact oracle across the supported date range', 150, (rng) => {
  const ms = () => rng.pick([rng.int(0, 4_102_444_800_000), 1_760_356_800_000 + rng.int(-2, 2), 0, 253_402_300_799_999]);
  const clampMs = n => Math.min(253_402_300_799_999, Math.max(0, n)), t1 = ms(), t2 = rng.bool(0.25) ? clampMs(t1 + rng.int(-1, 1)) : ms();
  const iso = n => new Date(n).toISOString();
  const cases = [
    [validateEvidence, () => payload(), 'observedAt', 'expiresAt'],
    [validateManifest, () => manifest(), 'issuedAt', 'expiresAt'],
  ];
  const [validate, build, from, to] = rng.pick(cases);
  const doc = build(); doc[from] = iso(t1); doc[to] = iso(t2);
  if (t2 > t1) assert.doesNotThrow(() => validate(doc)); else assert.throws(() => validate(doc), Error, `${iso(t1)} ${iso(t2)}`);
  const inc = incident(); inc.reportedAt = iso(t1);
  assert.doesNotThrow(() => validateIncident(inc));
});

property('manifest permission rules match a set-based oracle', 150, (rng) => {
  const U = ['read', 'write', 'publish', 'delete', 'exec'];
  const sub = () => rng.sample(U, rng.int(0, U.length));
  const m = manifest();
  m.scope.permissions = sub(); m.scope.forbidden = sub(); m.scope.approvalRequired = sub();
  const toolCount = rng.int(0, 3);
  m.system.tools = Array.from({ length: toolCount }, (_, i) => ({ id: rng.bool(0.15) ? 'dup' : `tool-${i}`, version: '1', permissions: sub() }));
  let ref = null;
  if (rng.bool()) { ref = rng.pick(['entity:acme', m.agent.id, m.agent.id.toUpperCase(), 'Agent:Test']); m.principal.accountableParty = { kind: rng.pick(['natural-person', 'legal-entity', 'robot']), ref }; }
  const P = new Set(m.scope.permissions);
  const dupTools = new Set(m.system.tools.map(t => t.id)).size !== m.system.tools.length;
  const ok = m.scope.forbidden.every(x => !P.has(x)) && m.scope.approvalRequired.every(x => P.has(x)) && m.system.tools.every(t => t.permissions.every(x => P.has(x))) && !dupTools
    && (!ref || (m.principal.accountableParty.kind !== 'robot' && ref.toLowerCase() !== m.agent.id.toLowerCase()));
  if (ok) assert.deepEqual(validateManifest(m), JSON.parse(canonical(m)));
  else assert.throws(() => validateManifest(m), Error, canonical(m).slice(0, 300));
  // duplicates inside any permission list are always rejected
  if (m.scope.permissions.length) { const d = clone(m); d.scope.permissions.push(d.scope.permissions[0]); assert.throws(() => validateManifest(d)); }
});

property('policy numeric and list bounds match an exact oracle', 100, (rng) => {
  const p = richPolicy();
  const num = rng.pick([0, 1, 0.5, -0.0000001, 1.0000001, -1, 2, 999, 1000, 1001, 1.5, 31_536_000, 31_536_001, 86_400, 100_000, 2 ** 53 - 1]);
  const field = rng.pick(['minCoverage', 'minIndependentCoverage', 'minScore', 'maxEvidenceAgeSeconds', 'maxAssessmentAgeSeconds']);
  p[field] = num;
  const ratio = n => n >= 0 && n <= 1, age = n => Number.isSafeInteger(n) && n > 0 && n <= 31_536_000;
  const ok = field.startsWith('min') ? (field === 'minScore' ? Number.isInteger(num) && num >= 0 && num <= 1000 : ratio(num)) : age(num);
  if (ok) assert.equal(validatePolicy(p)[field], num); else assert.throws(() => validatePolicy(p), Error, `${field}=${num}`);
  const q = richPolicy(); q.allowedSources = rng.sample(['fixture', 'runtime', 'declaration', 'other'], rng.int(0, 4));
  if (q.allowedSources.includes('other')) assert.throws(() => validatePolicy(q)); else assert.doesNotThrow(() => validatePolicy(q));
  const dup = richPolicy(); dup.trustedKeys.push(clone(dup.trustedKeys[rng.int(0, dup.trustedKeys.length - 1)])); assert.throws(() => validatePolicy(dup));
  const wrongId = richPolicy(); wrongId.trustedKeys[0].id = hex(rng); assert.throws(() => validatePolicy(wrongId));
  const role = richPolicy(); role.trustedKeys[0].role = rng.pick(['Self', 'INDEPENDENT', 'admin', '', null]); assert.throws(() => validatePolicy(role));
});
