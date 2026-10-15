import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, symlinkSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assess, digest } from '../src/index.mjs';
import { inputs, clone } from './helpers.mjs';
import {
  exportInTotoStatement, exportOtelAttributes, exportOAuthClaims, exportSpiffeBinding, exportA2aExtension, exportMcpMeta,
  verifyBridgeExport, serialize, BridgeError, LIMITS, OTEL_ATTRIBUTES, OTEL_ATTRIBUTE_NAMES, INTOTO_STATEMENT_TYPE, KYA_PREDICATE_TYPE,
  A2A_EXTENSION_URI, MCP_META_KEY, BRIDGE_KINDS
} from '../src/interop-bridges/index.mjs';

const SPIFFE = 'spiffe://example.test/agent/one';
const CHECK = '2026-10-13T12:10:00.000Z';
const base = () => inputs();
const report = () => assess(base());
const cur = (extra = {}) => { const i = base(); return { manifest: i.manifest, policy: i.policy, now: CHECK, ...extra }; };
const notQualified = () => assess({ ...base(), evidence: [] });
const refused = (fn, code) => assert.throws(fn, e => e instanceof BridgeError && e.code === code, `expected ${code}`);

// One entry per kind: export with the shared options, and what a forged copy looks like.
const exporters = {
  intoto: (r, o) => exportInTotoStatement(r, o),
  otel: (r, o) => exportOtelAttributes(r, o),
  oauth: (r, o) => exportOAuthClaims(r, o),
  spiffe: (r, o) => exportSpiffeBinding(r, SPIFFE, o),
  a2a: (r, o) => exportA2aExtension(r, { assessmentUrl: 'https://example.test/kya/a.json', ...o }),
  mcp: (r, o) => exportMcpMeta(r, o)
};
const decisionPath = {
  intoto: x => { x.predicate.decision = 'qualified'; x.predicate.evidenceMode = 'runtime'; },
  otel: x => { x['kya.evidence.mode'] = 'runtime'; },
  oauth: x => { x.kya.evidence_mode = 'runtime'; },
  spiffe: x => { x.claims.evidence_mode = 'runtime'; },
  a2a: x => { x.params.evidenceMode = 'runtime'; },
  mcp: x => { x._meta[MCP_META_KEY].evidenceMode = 'runtime'; }
};

test('intoto statement is v1 shaped and its subject is the manifest digest', () => {
  const i = base(), s = exportInTotoStatement(assess(i), cur());
  assert.equal(s._type, INTOTO_STATEMENT_TYPE);
  assert.equal(s.predicateType, KYA_PREDICATE_TYPE);
  assert.equal(s.subject.length, 1);
  assert.equal(s.subject[0].digest.sha256, digest(i.manifest));
  assert.equal(s.subject[0].name, `urn:kya:subject:sha256:${digest(i.manifest)}`);
  assert.deepEqual(Object.keys(s).sort(), ['_type', 'predicate', 'predicateType', 'subject']);
});

test('intoto predicate carries decision scores blocker codes input digests and limits', () => {
  const r = report(), p = exportInTotoStatement(r, cur()).predicate;
  assert.equal(p.decision, 'qualified'); assert.equal(p.qualified, true);
  assert.deepEqual(p.scores, { earned: r.score.earned, possible: r.score.possible, upperBound: r.score.upperBound, coverage: r.coverage, independentCoverage: r.independentCoverage });
  assert.deepEqual(p.blockerCodes, r.blockerCodes);
  assert.deepEqual(p.inputDigests, { subjectDigest: r.subjectDigest, profileDigest: r.profileDigest, policyDigest: r.policyDigest, evaluatorDigest: r.evaluatorDigest, evidenceBundleDigest: r.evidenceBundleDigest, acceptedEvidenceDigests: r.acceptedEvidenceDigests, reportDigest: r.reportDigest });
  assert.equal(p.evidenceMode, 'fixture');
  assert.ok(p.limitations.includes('Includes synthetic fixture evidence; not a real product benchmark'));
  assert.deepEqual(p.limits, [...LIMITS]);
  assert.equal(p.currency.checked, true); assert.equal(p.currency.current, true); assert.deepEqual(p.currency.overrides, []);
  assert.deepEqual(p.notAsserted, ['human identity', 'authorization grant', 'truthful execution']);
});

test('otel attribute map uses exactly the documented names with primitive or string array values', () => {
  const a = exportOtelAttributes(report(), cur());
  for (const [k, v] of Object.entries(a)) {
    assert.ok(OTEL_ATTRIBUTE_NAMES.includes(k), `undocumented attribute ${k}`);
    assert.match(k, /^kya(\.[a-z][a-z_]*)+$/);
    assert.ok(['string', 'boolean', 'number'].includes(typeof v) || (Array.isArray(v) && v.every(x => typeof x === 'string')), `bad value type for ${k}`);
  }
  assert.deepEqual(Object.keys(a), Object.keys(a).slice().sort());
  assert.equal(a['kya.decision'], 'qualified'); assert.equal(a['kya.qualified'], true);
  assert.equal(a['kya.authorization.granted'], false); assert.equal(a['kya.assessment.authenticated'], false);
  assert.deepEqual(a['kya.blocker.codes'], []);
  assert.equal(a['kya.currency.current'], true);
  const types = { string: 'string', boolean: 'boolean', int: 'number', double: 'number' };
  for (const row of OTEL_ATTRIBUTES) if (row.name in a && row.type !== 'string[]') assert.equal(typeof a[row.name], types[row.type], row.name);
  for (const row of OTEL_ATTRIBUTES) if (row.type === 'int' && row.name in a) assert.ok(Number.isInteger(a[row.name]));
});

test('otel attributes for a blocked assessment carry blocker codes and omit unchecked currency members', () => {
  const r = notQualified();
  assert.ok(r.blockerCodes.length > 0);
  const a = exportOtelAttributes(r, { allowNonQualified: true, allowNotCurrent: true });
  assert.deepEqual(a['kya.blocker.codes'], r.blockerCodes);
  assert.equal(a['kya.qualified'], false);
  assert.equal(a['kya.currency.checked'], false);
  for (const k of ['kya.currency.current', 'kya.currency.reliable', 'kya.currency.checked_at', 'kya.currency.digest']) assert.ok(!(k in a), k);
  assert.deepEqual(a['kya.gate.overrides'], ['allowNonQualified', 'allowNotCurrent']);
});

test('otel attribute table in the docs lists every attribute name and no other kya name', () => {
  const doc = readFileSync(new URL('../docs/INTEROP-BRIDGES.md', import.meta.url), 'utf8');
  for (const n of OTEL_ATTRIBUTE_NAMES) assert.ok(doc.includes('`' + n + '`'), `docs miss ${n}`);
  const named = new Set([...doc.matchAll(/`(kya\.[a-z_.]+)`/g)].map(m => m[1]));
  for (const n of named) assert.ok(OTEL_ATTRIBUTE_NAMES.includes(n), `docs list unknown ${n}`);
});

test('oauth claims carry the assessment digest and decision under one private claim and set no token members', () => {
  const r = report(), c = exportOAuthClaims(r, cur());
  assert.deepEqual(Object.keys(c).sort(), ['kya', 'kya_limits']);
  for (const reserved of ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'cnf']) assert.ok(!(reserved in c) && !(reserved in c.kya), reserved);
  assert.equal(c.kya.assessment_digest, r.reportDigest); assert.equal(c.kya.subject_digest, r.subjectDigest);
  assert.equal(c.kya.decision, 'qualified'); assert.equal(c.kya.qualified, true); assert.equal(c.kya.authorization_granted, false);
  assert.equal(c.kya.valid_until_epoch, Date.parse(r.validUntil) / 1000);
  assert.deepEqual(c.kya_limits, [...LIMITS]);
});

test('spiffe binding ties one spiffe id to the assessment and says the association is not proven', () => {
  const r = report(), b = exportSpiffeBinding(r, SPIFFE, cur());
  assert.equal(b.spiffeId, SPIFFE); assert.equal(b.association, 'asserted-not-proven');
  assert.equal(b.bindingDigest, digest({ spiffeId: SPIFFE, assessmentDigest: r.reportDigest, subjectDigest: r.subjectDigest }));
  assert.equal(b.claims.assessment_digest, r.reportDigest);
  assert.match(b.note, /not prove|Nothing here proves/);
  const other = exportSpiffeBinding(r, 'spiffe://example.test/agent/two', cur());
  assert.notEqual(other.bindingDigest, b.bindingDigest);
});

test('spiffe binding rejects malformed spiffe ids', () => {
  const r = report();
  for (const bad of ['', 'https://example.test/a', 'spiffe://', 'spiffe://Example.test/a', 'spiffe://example.test/a?x=1', 'spiffe://example.test/a#f', 'spiffe://user@example.test/a', 'spiffe://example.test/a/../b', 'spiffe://example.test/./b', 'spiffe://example.test//b', 'spiffe://example.test/a/', 'spiffe://example.test/a b', 42, null, undefined])
    assert.throws(() => exportSpiffeBinding(r, bad, cur()), /SPIFFE ID/, String(bad));
  assert.equal(exportSpiffeBinding(r, 'spiffe://example.test', cur()).spiffeId, 'spiffe://example.test');
});

test('a2a extension and mcp meta point at the assessment digest and carry the currency check', () => {
  const r = report(), url = 'https://example.test/kya/assessment.json';
  const x = exportA2aExtension(r, cur({ assessmentUrl: url }));
  assert.equal(x.uri, A2A_EXTENSION_URI); assert.equal(x.required, false);
  assert.deepEqual(Object.keys(x).sort(), ['description', 'params', 'required', 'uri']);
  assert.equal(x.params.assessmentDigest, r.reportDigest); assert.equal(x.params.assessmentUrl, url);
  assert.equal(x.params.currencyCheck.schema, 'kya.currency/v1');
  assert.equal(x.params.currencyCheck.asOfExport.current, true);
  assert.match(x.params.currencyCheck.how, /yourself/);
  assert.equal(x.params.authorizationGranted, false);
  const m = exportMcpMeta(r, cur());
  assert.deepEqual(Object.keys(m), ['_meta']);
  assert.equal(m._meta[MCP_META_KEY].assessmentDigest, r.reportDigest);
  assert.ok(!('assessmentUrl' in m._meta[MCP_META_KEY]));
  assert.deepEqual(m._meta[MCP_META_KEY].currencyCheck, x.params.currencyCheck);
});

test('a2a and mcp urls must be https and are never fetched', () => {
  const r = report();
  for (const bad of ['http://example.test/a', 'file:///etc/passwd', 'javascript:alert(1)', 'https://exa mple.test', 'https://x.test/"<', '', 5])
    assert.throws(() => exportA2aExtension(r, cur({ assessmentUrl: bad })), /assessmentUrl/, String(bad));
  assert.throws(() => exportMcpMeta(r, cur({ assessmentUrl: 'ftp://x.test/a' })), /assessmentUrl/);
});

test('every export is reproducible byte for byte regardless of input key order', () => {
  const r = report(), reordered = JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(r).reverse())));
  for (const kind of BRIDGE_KINDS) {
    const a = serialize(exporters[kind](r, cur())), b = serialize(exporters[kind](reordered, cur())), c = serialize(exporters[kind](clone(r), cur()));
    assert.equal(a, b, kind); assert.equal(a, c, kind);
    assert.ok(a.endsWith('}\n'));
  }
});

test('every export states the limits and leaks no principal agent name or signature', () => {
  const r = report();
  for (const kind of BRIDGE_KINDS) {
    const text = serialize(exporters[kind](r, cur()));
    for (const l of LIMITS) assert.ok(text.includes(JSON.stringify(l).slice(1, -1)) || kind === 'otel', `${kind} lacks limit`);
    for (const secret of [r.principalId, r.agentName, r.agentId]) assert.ok(!text.includes(secret), `${kind} leaks ${secret}`);
    assert.ok(!/"signatures?"|"sig"|"proof"|"jws"|BEGIN /.test(text), kind);
    assert.ok(/authorization/i.test(text), kind);
  }
  assert.ok(LIMITS.some(l => /not an authorization grant/i.test(l)));
  assert.ok(LIMITS.some(l => /unauthenticated/.test(l)));
  assert.ok(LIMITS.some(l => /no third-party tool/i.test(l)));
});

test('exports fail closed on a non qualified assessment unless allowNonQualified is passed', () => {
  const r = notQualified();
  assert.notEqual(r.decision, 'qualified');
  for (const kind of BRIDGE_KINDS) {
    refused(() => exporters[kind](r, { ...cur() }), 'NOT_QUALIFIED');
    refused(() => exporters[kind](r, { ...cur(), allowNotCurrent: true }), 'NOT_QUALIFIED');
  }
  const s = exportInTotoStatement(r, { ...cur(), allowNonQualified: true });
  assert.equal(s.predicate.qualified, false); assert.equal(s.predicate.decision, r.decision);
  assert.deepEqual(s.predicate.currency.overrides, ['allowNonQualified']);
});

test('exports fail closed on an expired assessment and an aged assessment', () => {
  const r = report();
  for (const kind of BRIDGE_KINDS) refused(() => exporters[kind](r, cur({ now: '2026-10-13T13:00:00.001Z' })), 'NOT_CURRENT');
  const i = base(); const aged = { ...i.policy, maxAssessmentAgeSeconds: 60 };
  const r2 = assess({ ...i, policy: aged });
  refused(() => exportOtelAttributes(r2, { manifest: i.manifest, policy: aged, now: CHECK }), 'NOT_CURRENT');
});

test('exports fail closed when the manifest or the policy changed or the subject is revoked', () => {
  const r = report(), i = base();
  const changedManifest = { ...clone(i.manifest), agent: { ...i.manifest.agent, version: '2' } };
  refused(() => exportInTotoStatement(r, cur({ manifest: changedManifest })), 'NOT_CURRENT');
  refused(() => exportOAuthClaims(r, cur({ policy: { ...clone(i.policy), minScore: 700 } })), 'NOT_CURRENT');
  refused(() => exportMcpMeta(r, cur({ policy: { ...clone(i.policy), revokedSubjectDigests: [r.subjectDigest] } })), 'NOT_CURRENT');
  refused(() => exportA2aExtension(r, cur({ now: '2026-10-13T11:59:59.999Z' })), 'NOT_CURRENT');
});

test('exports fail closed when no currency inputs are given or only some are given', () => {
  const r = report(), i = base();
  for (const kind of BRIDGE_KINDS) refused(() => exporters[kind](r, {}), 'CURRENCY_NOT_CHECKED');
  refused(() => exportInTotoStatement(r, { manifest: i.manifest }), 'CURRENCY_INPUTS_INCOMPLETE');
  refused(() => exportInTotoStatement(r, { manifest: i.manifest, policy: i.policy }), 'CURRENCY_INPUTS_INCOMPLETE');
  refused(() => exportInTotoStatement(r, { now: CHECK, allowNotCurrent: true }), 'CURRENCY_INPUTS_INCOMPLETE');
});

test('allowNotCurrent records the override and the export never claims qualified without a passing currency check', () => {
  const r = report();
  const unchecked = exportOAuthClaims(r, { allowNotCurrent: true });
  assert.equal(unchecked.kya.qualified, false); assert.equal(unchecked.kya.currency.checked, false);
  assert.deepEqual(unchecked.kya.currency.overrides, ['allowNotCurrent']);
  const expired = exportInTotoStatement(r, cur({ now: '2026-10-14T12:00:00.000Z', allowNotCurrent: true }));
  assert.equal(expired.predicate.qualified, false); assert.equal(expired.predicate.currency.current, false);
  assert.ok(expired.predicate.currency.triggerCodes.length >= 1);
  assert.deepEqual(expired.predicate.currency.overrides, ['allowNotCurrent']);
  const needless = exportInTotoStatement(r, cur({ allowNotCurrent: true, allowNonQualified: true }));
  assert.deepEqual(needless.predicate.currency.overrides, []);
  assert.equal(needless.predicate.qualified, true);
});

test('incidents supplied to the gate can make an export refuse', () => {
  const r = report();
  assert.equal(exportInTotoStatement(r, cur({ incidents: [] })).predicate.currency.current, true);
  assert.throws(() => exportInTotoStatement(r, cur({ incidents: 'x' })), /Incidents/);
});

test('exports reject unknown options and non boolean flags and tampered reports', () => {
  const r = report();
  assert.throws(() => exportInTotoStatement(r, cur({ evidenceMode: 'runtime' })), /Unknown option evidenceMode/);
  assert.throws(() => exportOtelAttributes(r, cur({ assessmentUrl: 'https://example.test/a' })), /Unknown option assessmentUrl/);
  assert.throws(() => exportOAuthClaims(r, cur({ allowNotCurrent: 'yes' })), /boolean/);
  assert.throws(() => exportOAuthClaims(r, null), /Options/);
  const t = clone(r); t.decision = 'blocked'; assert.throws(() => exportInTotoStatement(t, cur({ allowNonQualified: true })), /digest differs/);
  const u = clone(r); u.evidenceMode = 'runtime'; assert.throws(() => exportOtelAttributes(u, cur()), /digest differs/);
  const w = clone(r); delete w.limitations; assert.throws(() => exportMcpMeta(w, cur()));
  assert.throws(() => exportInTotoStatement({}, cur()));
  assert.throws(() => exportInTotoStatement(undefined, cur()));
});

test('cross check accepts every export built from the same report and recomputes currency when inputs are given', () => {
  const r = report();
  for (const kind of BRIDGE_KINDS) {
    const out = exporters[kind](r, cur());
    const plain = verifyBridgeExport(kind, out, { report: r });
    assert.deepEqual(plain.errors, [], kind); assert.equal(plain.valid, true);
    assert.equal(plain.reportChecked, true); assert.equal(plain.currencyRechecked, false); assert.equal(plain.authenticated, false);
    const full = verifyBridgeExport(kind, out, { report: r, ...cur() });
    assert.deepEqual(full.errors, [], kind); assert.equal(full.currencyRechecked, true);
  }
  const nq = notQualified(), out = exportInTotoStatement(nq, { allowNonQualified: true, allowNotCurrent: true });
  assert.equal(verifyBridgeExport('intoto', out, { report: nq }).valid, true);
});

test('cross check names forged members for every kind including an edit that needs no resign', () => {
  const r = report();
  for (const kind of BRIDGE_KINDS) {
    const out = clone(exporters[kind](r, cur()));
    decisionPath[kind](out);
    const v = verifyBridgeExport(kind, out, { report: r });
    assert.equal(v.valid, false, kind);
    assert.deepEqual(v.errors.map(e => e.code), ['REPORT_MISMATCH'], kind);
    assert.match(v.errors[0].message, /evidence|predicate|kya|claims|params|_meta/i, kind);
  }
});

test('cross check detects injected members dropped members and swapped digests', () => {
  const r = report();
  const s = clone(exportInTotoStatement(r, cur()));
  s.extra = 1; assert.match(verifyBridgeExport('intoto', s, { report: r }).errors[0].message, /extra/);
  const t = clone(exportInTotoStatement(r, cur())); t.predicate.notAsserted = []; assert.match(verifyBridgeExport('intoto', t, { report: r }).errors[0].message, /notAsserted/);
  const u = clone(exportInTotoStatement(r, cur())); u.subject[0].digest.sha256 = 'a'.repeat(64); assert.match(verifyBridgeExport('intoto', u, { report: r }).errors[0].message, /subject/);
  const v = clone(exportInTotoStatement(r, cur())); v.predicate.limits.pop(); assert.equal(verifyBridgeExport('intoto', v, { report: r }).valid, false);
  const w = clone(exportOtelAttributes(r, cur())); delete w['kya.authorization.granted']; assert.match(verifyBridgeExport('otel', w, { report: r }).errors[0].message, /authorization/);
  const x = clone(exportOtelAttributes(r, cur())); x['kya.authorization.granted'] = true; assert.equal(verifyBridgeExport('otel', x, { report: r }).valid, false);
  const y = clone(exportSpiffeBinding(r, SPIFFE, cur())); y.spiffeId = 'spiffe://example.test/other'; assert.match(verifyBridgeExport('spiffe', y, { report: r }).errors[0].message, /bindingDigest/);
  const z = clone(exportA2aExtension(r, cur())); z.required = true; assert.match(verifyBridgeExport('a2a', z, { report: r }).errors[0].message, /required/);
  const other = assess({ ...base(), now: '2026-10-13T12:01:00.000Z' });
  assert.equal(verifyBridgeExport('oauth', exportOAuthClaims(other, cur()), { report: r }).valid, false);
});

test('cross check without currency inputs cannot see a forged currency block but a recheck does', () => {
  const r = report();
  const forged = clone(exportInTotoStatement(r, cur({ now: '2026-10-14T12:00:00.000Z', allowNotCurrent: true })));
  forged.predicate.currency = { ...forged.predicate.currency, current: true, reliable: true, triggerCodes: [] };
  forged.predicate.qualified = true;
  assert.equal(verifyBridgeExport('intoto', forged, { report: r }).valid, true);
  const rechecked = verifyBridgeExport('intoto', forged, { report: r, ...cur({ now: '2026-10-14T12:00:00.000Z' }) });
  assert.equal(rechecked.valid, false);
  assert.match(rechecked.errors[0].message, /predicate/);
  const lie = clone(exportInTotoStatement(r, cur({ now: '2026-10-14T12:00:00.000Z', allowNotCurrent: true })));
  lie.predicate.currency.overrides = [];
  assert.equal(verifyBridgeExport('intoto', lie, { report: r, ...cur({ now: '2026-10-14T12:00:00.000Z' }) }).valid, false);
});

test('cross check refuses a report that fails its checksum and missing or partial inputs without throwing', () => {
  const r = report(), out = exportInTotoStatement(r, cur());
  const bad = clone(r); bad.score.earned = 0;
  assert.equal(verifyBridgeExport('intoto', out, { report: bad }).errors[0].code, 'REPORT_INVALID');
  assert.equal(verifyBridgeExport('intoto', out, {}).errors[0].code, 'REPORT_REQUIRED');
  assert.equal(verifyBridgeExport('intoto', out).errors[0].code, 'REPORT_REQUIRED');
  assert.equal(verifyBridgeExport('nope', out, { report: r }).errors[0].code, 'UNKNOWN_KIND');
  assert.equal(verifyBridgeExport('__proto__', out, { report: r }).errors[0].code, 'UNKNOWN_KIND');
  assert.equal(verifyBridgeExport('intoto', out, { report: r, manifest: base().manifest }).errors[0].code, 'CURRENCY_INPUTS_INCOMPLETE');
  assert.equal(verifyBridgeExport('intoto', out, { report: r, manifest: {}, policy: {}, now: CHECK }).errors[0].code, 'CURRENCY_RECHECK_FAILED');
  for (const junk of [null, undefined, 5, 'x', [], {}, { predicate: null }, { predicate: { currency: null } }, { kya: 1 }, { params: {} }, { _meta: {} }])
    for (const kind of BRIDGE_KINDS) assert.equal(verifyBridgeExport(kind, junk, { report: r }).valid, false, `${kind} ${JSON.stringify(junk)}`);
  assert.equal(verifyBridgeExport('spiffe', { spiffeId: 'nope', claims: out }, { report: r }).valid, false);
});

test('the module is offline and unsigned and imports no network or crypto signing api', () => {
  for (const f of ['gate', 'intoto', 'otel', 'oauth', 'discovery', 'verify', 'index']) {
    const text = readFileSync(new URL(`../src/interop-bridges/${f}.mjs`, import.meta.url), 'utf8');
    assert.ok(!/node:(http|https|net|dgram|dns|tls|child_process)|\bfetch\(|XMLHttpRequest|crypto\.(sign|createSign)|Date\.now\(|new Date\(\)/.test(text), f);
  }
});

const dir = mkdtempSync(join(tmpdir(), 'kya-bridge-'));
const put = (name, v) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(v)); return p; };
const cli = (...args) => spawnSync(process.execPath, [join(process.cwd(), 'scripts/kya-bridge.mjs'), ...args], { encoding: 'utf8', shell: false, timeout: 20000 });

test('cli exports each kind reproducibly verifies it against the report and refuses unsafe exports with exit 2', () => {
  const i = base(), r = assess(i), nq = notQualified();
  const a = put('a.json', r), m = put('m.json', i.manifest), p = put('p.json', i.policy), q = put('q.json', nq);
  const cur2 = ['--manifest', m, '--policy', p, '--now', CHECK];
  for (const kind of BRIDGE_KINDS) {
    const extra = kind === 'spiffe' ? ['--spiffe-id', SPIFFE] : [];
    const one = cli('export', kind, '--assessment', a, ...cur2, ...extra), two = cli('export', kind, '--assessment', a, ...cur2, ...extra);
    assert.equal(one.status, 0, one.stderr); assert.equal(one.stdout, two.stdout);
    const direct = { intoto: exportInTotoStatement, otel: exportOtelAttributes, oauth: exportOAuthClaims, a2a: exportA2aExtension, mcp: exportMcpMeta }[kind];
    assert.equal(one.stdout, serialize(kind === 'spiffe' ? exportSpiffeBinding(r, SPIFFE, cur()) : direct(r, cur())), kind);
    const f = join(dir, `${kind}.json`); writeFileSync(f, one.stdout);
    const v = cli('verify', kind, '--export', f, '--assessment', a, ...cur2);
    assert.equal(v.status, 0, v.stdout); assert.equal(JSON.parse(v.stdout).valid, true);
    const forged = JSON.parse(one.stdout); decisionPath[kind](forged); writeFileSync(f, JSON.stringify(forged));
    assert.equal(cli('verify', kind, '--export', f, '--assessment', a).status, 1);
  }
  const no = cli('export', 'intoto', '--assessment', q, ...cur2);
  assert.equal(no.status, 2); assert.equal(no.stdout, ''); assert.equal(JSON.parse(no.stderr).code, 'NOT_QUALIFIED');
  assert.equal(cli('export', 'intoto', '--assessment', q, ...cur2, '--allow-non-qualified').status, 0);
  assert.equal(JSON.parse(cli('export', 'otel', '--assessment', a).stderr).code, 'CURRENCY_NOT_CHECKED');
  assert.equal(JSON.parse(cli('export', 'otel', '--assessment', a, ...cur2.slice(0, 4), '--now', '2026-10-14T12:00:00.000Z').stderr).code, 'NOT_CURRENT');
  assert.equal(cli('export', 'oauth', '--assessment', a, ...cur2, '--spiffe-id', SPIFFE).status, 2);
  assert.equal(cli('export', 'spiffe', '--assessment', a, ...cur2).status, 2);
  assert.equal(cli('export', 'bogus', '--assessment', a).status, 2);
  assert.equal(cli('--help').status, 0);
});

// ---- fix lane: adversarial review findings ----
const reseal = r => { const { reportDigest, ...b } = r; return { ...b, reportDigest: digest(b) }; };
const noCheck = { allowNotCurrent: true };

test('cross check refuses a self contradictory currency block when currency is not rechecked', () => {
  const r = report();
  const unchecked = () => clone(exportInTotoStatement(r, noCheck));
  const checked = () => clone(exportInTotoStatement(r, cur()));
  const mutations = [
    ['unchecked but current true', unchecked, x => { x.predicate.currency.current = true; x.predicate.qualified = true; }],
    ['unchecked with trigger codes', unchecked, x => { x.predicate.currency.triggerCodes = ['SUBJECT_CHANGED']; }],
    ['unchecked with a digest', unchecked, x => { x.predicate.currency.digest = 'a'.repeat(64); }],
    ['unchecked without the override', unchecked, x => { x.predicate.currency.overrides = []; }],
    ['current with trigger codes', checked, x => { x.predicate.currency.triggerCodes = ['SUBJECT_CHANGED']; }],
    ['not current without trigger codes', checked, x => { x.predicate.currency.current = false; x.predicate.qualified = false; }],
    ['junk checked at', checked, x => { x.predicate.currency.checkedAt = 'yesterday'; }],
    ['junk digest', checked, x => { x.predicate.currency.digest = 'zz'; }],
    ['unknown trigger code', checked, x => { x.predicate.currency.current = false; x.predicate.currency.triggerCodes = ['MADE_UP']; x.predicate.qualified = false; }]
  ];
  for (const [name, make, mutate] of mutations) {
    const x = make(); mutate(x);
    const v = verifyBridgeExport('intoto', x, { report: r });
    assert.equal(v.valid, false, name);
    assert.equal(v.errors[0].code, 'MALFORMED', name);
  }
  const o = clone(exportOAuthClaims(r, noCheck)); o.kya.currency.current = true; o.kya.qualified = true;
  assert.equal(verifyBridgeExport('oauth', o, { report: r }).valid, false);
  assert.equal(verifyBridgeExport('intoto', unchecked(), { report: r }).valid, true);
  assert.equal(verifyBridgeExport('intoto', checked(), { report: r }).valid, true);
});

test('export options are read as own properties only', () => {
  const r = report();
  refused(() => exportOtelAttributes(r, Object.create({ allowNotCurrent: true })), 'CURRENCY_NOT_CHECKED');
  Object.prototype.allowNotCurrent = true;
  try { refused(() => exportOtelAttributes(r, {}), 'CURRENCY_NOT_CHECKED'); refused(() => exportOtelAttributes(r), 'CURRENCY_NOT_CHECKED'); }
  finally { delete Object.prototype.allowNotCurrent; }
  Object.prototype.allowNonQualified = true;
  try { refused(() => exportOtelAttributes(notQualified(), cur()), 'NOT_QUALIFIED'); }
  finally { delete Object.prototype.allowNonQualified; }
  const inherited = Object.create({ assessmentUrl: 'https://bad.example/x' });
  Object.assign(inherited, cur());
  assert.equal(exportMcpMeta(r, inherited)._meta[MCP_META_KEY].assessmentUrl, undefined);
});

const cliDir = mkdtempSync(join(tmpdir(), 'kya-bridge-fix-'));
const cput = (name, v) => { const p = join(cliDir, name); writeFileSync(p, JSON.stringify(v)); return p; };
const cliFix = (...args) => spawnSync(process.execPath, [join(process.cwd(), 'scripts/kya-bridge.mjs'), ...args], { encoding: 'utf8', shell: false, timeout: 20000 });

test('cli refuses unknown flags per command', () => {
  const i = base(), r = assess(i);
  const a = cput('a.json', r), m = cput('m.json', i.manifest), p = cput('p.json', i.policy);
  const c = ['--manifest', m, '--policy', p, '--now', CHECK];
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--incident', a).status, 2);
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--export', a).status, 2);
  const e = cliFix('export', 'otel', '--assessment', a, ...c);
  const ef = join(cliDir, 'otel.json'); writeFileSync(ef, e.stdout);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, ...c, '--incidnts', a).status, 2);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, '--allow-not-current').status, 2);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, '--out', join(cliDir, 'zz.json')).status, 2);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, ...c).status, 0);
});

test('cli treats empty valued flags as present and requires recheck inputs together', () => {
  const i = base(), r = assess(i);
  const a = cput('a2.json', r), m = cput('m2.json', i.manifest), p = cput('p2.json', i.policy), inc = cput('inc2.json', []);
  const c = ['--manifest', m, '--policy', p, '--now', CHECK];
  const ef = join(cliDir, 'otel2.json'); writeFileSync(ef, cliFix('export', 'otel', '--assessment', a, ...c).stdout);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, '--manifest', '', '--policy', p, '--now', CHECK).status, 2);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, '--manifest', '').status, 2);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, '--incidents', inc).status, 2);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, '--manifest', m).status, 2);
  assert.equal(cliFix('export', 'otel', '--assessment', a, '--incidents', inc, '--allow-not-current').status, 2);
  assert.equal(cliFix('export', 'otel', '--assessment', a, '--allow-not-current', '--now', '').status, 2);
  assert.equal(cliFix('verify', 'otel', '--export', ef, '--assessment', a, ...c, '--incidents', inc).status, 0);
});

test('library refuses incidents without the other currency inputs', () => {
  const r = report();
  refused(() => exportOtelAttributes(r, { incidents: [], allowNotCurrent: true }), 'CURRENCY_INPUTS_INCOMPLETE');
  const out = exportOtelAttributes(r, cur());
  assert.equal(verifyBridgeExport('otel', out, { report: r, incidents: [] }).errors[0].code, 'CURRENCY_INPUTS_INCOMPLETE');
});

test('timestamps in the report are validated even when currency is not checked', () => {
  const r = report();
  for (const [k, v] of [['validUntil', 'garbage'], ['validUntil', '2026-10-14 12:00:00'], ['validUntil', '2026-10-14T12:00:00'], ['assessedAt', 'garbage']]) {
    const bad = reseal({ ...clone(r), [k]: v });
    assert.throws(() => exportOAuthClaims(bad, noCheck), /Assessment|timestamp/, k + v);
    assert.equal(verifyBridgeExport('oauth', exportOAuthClaims(r, noCheck), { report: bad }).errors[0].code, 'REPORT_INVALID', k + v);
  }
});

test('a non ISO validity is refused identically under different time zones', () => {
  const r = reseal({ ...clone(report()), validUntil: '2026-10-14T12:00:00' });
  const script = 'import { exportOAuthClaims } from ' + JSON.stringify(new URL('../src/interop-bridges/index.mjs', import.meta.url).href) + '; try { exportOAuthClaims(JSON.parse(process.argv[1]), { allowNotCurrent: true }); console.log("EXPORTED"); } catch (e) { console.log("REFUSED"); }';
  for (const tz of ['UTC', 'Asia/Tokyo']) {
    const out = spawnSync(process.execPath, ['--input-type=module', '-e', script, JSON.stringify(r)], { encoding: 'utf8', env: { ...process.env, TZ: tz } });
    assert.equal(out.stdout.trim(), 'REFUSED', tz + ' ' + out.stderr);
  }
});

test('cross check never throws on unusual export values', () => {
  const r = report();
  const good = () => clone(exportOtelAttributes(r, cur()));
  const cyc = good(); cyc.self = cyc;
  const own = JSON.parse('{"__proto__":{"x":1}}');
  const withProto = good(); Object.defineProperty(withProto, '__proto__', { value: 1, enumerable: true, configurable: true, writable: true });
  const cases = [{ ...good(), 'kya.score.earned': NaN }, { ...good(), extra: 10n }, cyc, own, withProto, { ...good(), nested: { a: Infinity } }];
  for (const kind of BRIDGE_KINDS) for (const x of cases) {
    let v; assert.doesNotThrow(() => { v = verifyBridgeExport(kind, x, { report: r }); }, kind);
    assert.equal(v.valid, false, kind);
  }
  for (const x of cases) assert.doesNotThrow(() => verifyBridgeExport('otel', x, { report: r, ...cur() }));
  assert.doesNotThrow(() => verifyBridgeExport('otel', good(), null));
  assert.doesNotThrow(() => verifyBridgeExport('otel', good(), 5));
  assert.equal(verifyBridgeExport('otel', cases[0], { report: r }).errors[0].code, 'MALFORMED');
});

test('spiffe trust domains need dns label like labels', () => {
  for (const bad of ['.', '..', '-', 'a..b', 'a.', '.a', '-a', 'a-', 'a.-b', 'a_.b', 'A.b', 'a' + '.b'.repeat(200)])
    assert.throws(() => exportSpiffeBinding(report(), 'spiffe://' + bad + '/x', cur()), /SPIFFE/, bad);
  for (const ok of ['example.test', 'example', 'a-b.c_d.e1', 'x.y.z']) exportSpiffeBinding(report(), 'spiffe://' + ok + '/x', cur());
});

test('assessment urls with userinfo or fragments are refused and the url can be pinned in the cross check', () => {
  const r = report();
  for (const bad of ['https://user@example.test/a', 'https://user:pw@example.test/a', 'https://@example.test/a', 'https://:@example.test/a', 'https://example.test/a#frag', 'https://example.test/a#', 'https://', 'https:///a'])
    for (const fn of [exportA2aExtension, exportMcpMeta]) assert.throws(() => fn(r, cur({ assessmentUrl: bad })), /https URL/, bad);
  const url = 'https://example.test/kya/a.json';
  const out = exportA2aExtension(r, cur({ assessmentUrl: url }));
  assert.equal(verifyBridgeExport('a2a', out, { report: r, assessmentUrl: url }).valid, true);
  const other = verifyBridgeExport('a2a', out, { report: r, assessmentUrl: 'https://example.test/other.json' });
  assert.equal(other.valid, false); assert.equal(other.errors[0].code, 'REPORT_MISMATCH');
  assert.equal(verifyBridgeExport('a2a', out, { report: r, assessmentUrl: 'http://x' }).valid, false);
  assert.equal(verifyBridgeExport('otel', exportOtelAttributes(r, cur()), { report: r, assessmentUrl: url }).valid, false);
  const forged = clone(out); forged.params.assessmentUrl = 'https://user@example.test/a';
  assert.equal(verifyBridgeExport('a2a', forged, { report: r }).valid, false);
});

test('cli refuses to overwrite inputs or symlinks and uses exclusive create unless force is given', () => {
  const i = base(), r = assess(i);
  const a = cput('a3.json', r), m = cput('m3.json', i.manifest), p = cput('p3.json', i.policy);
  const c = ['--manifest', m, '--policy', p, '--now', CHECK];
  const before = readFileSync(a, 'utf8');
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', a).status, 2);
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', a, '--force').status, 2);
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', join(cliDir, '.', 'a3.json')).status, 2);
  assert.equal(readFileSync(a, 'utf8'), before);
  const link = join(cliDir, 'link.json'); symlinkSync(a, link);
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', link).status, 2);
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', link, '--force').status, 2);
  assert.equal(readFileSync(a, 'utf8'), before);
  const hard = join(cliDir, 'hard.json'); linkSync(a, hard);
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', hard, '--force').status, 2);
  assert.equal(readFileSync(a, 'utf8'), before);
  const out = join(cliDir, 'fresh.json');
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', out).status, 0);
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', out).status, 2);
  writeFileSync(out, 'old');
  assert.equal(cliFix('export', 'otel', '--assessment', a, ...c, '--out', out, '--force').status, 0);
  assert.notEqual(readFileSync(out, 'utf8'), 'old');
});
