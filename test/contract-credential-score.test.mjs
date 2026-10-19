import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { sign } from 'node:crypto';
import { digest, hashBytes } from '../src/shared/canonical.mjs';
import { V2_OPERATIONS } from '../interop/impl-contract/js-operations.mjs';
import { verifyAssessmentCredential } from '../src/vc-bridge/index.mjs';
import { credentialKeys } from '../scripts/lib/vectors-credential.mjs';

// Contract version 2, later operations: verify-credential, verify-score-card, compare-score-cards (ADR-0035).
// Fixtures are the published vectors, so these tests and the vectors file cannot drift apart silently.
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const FILE = JSON.parse(readFileSync(join(ROOT, 'evidence/assessment-vectors.json'), 'utf8'));
const byId = id => { const v = FILE.vectors.find(x => x.id === id); assert.ok(v, 'missing vector ' + id); return v; };
const inputsOf = id => structuredClone(byId(id).inputs);
const vc = inputs => V2_OPERATIONS['verify-credential'](structuredClone(inputs));
const KEYS = credentialKeys(hashBytes);
const b = x => Buffer.from(x).toString('base64url');

test('verify-credential applies its opening steps in the order the specification lists', () => {
  const base = inputsOf('verify-credential.valid-unchecked-issuer');
  const header = { alg: 'EdDSA', typ: 'vc+jwt', cty: 'vc', kid: `${KEYS.issuer.did}#${KEYS.issuer.did.slice(8)}` };
  const payload = JSON.parse(Buffer.from(base.jwt.split('.')[1], 'base64url').toString('utf8'));
  const make = (h, p = payload, sig) => { const i = `${b(JSON.stringify(h))}.${b(typeof p === 'string' ? p : JSON.stringify(p))}`; return `${i}.${b(sig ?? sign(null, Buffer.from(i), KEYS.issuer.priv))}`; };
  const code = jwt => vc({ ...base, jwt }).errors[0];
  assert.equal(code(make({ ...header, alg: 'none', jwk: {} }, 'not json')), 'ALG_NOT_ALLOWED');
  assert.equal(code(make({ ...header, typ: 'JWT', extra: 1 })), 'HEADER_MEMBER_NOT_ALLOWED');
  assert.equal(code(make({ alg: 'EdDSA', typ: 'JWT' })), 'TYP_NOT_ALLOWED');
  assert.equal(code(make({ alg: 'EdDSA', typ: 'vc+jwt' }, 'not json')), 'MALFORMED');
  assert.equal(code(make({ ...header, kid: 'did:key:z6Mk' })), 'KID_MISMATCH');
  assert.equal(code(make(header, { ...payload, exp: 1 }, Buffer.alloc(64))), 'SIGNATURE_INVALID');
  assert.equal(code(make(header, { ...payload, '@context': ['x'] }, Buffer.alloc(64))), 'SIGNATURE_INVALID');
  assert.equal(code(make(header, { ...payload, '@context': ['x'] })), 'PAYLOAD_INVALID');
  assert.equal(vc({ ...base, jwt: make(header, { ...payload, '@context': ['x'] }), now: 'x' }).errors[0], 'TIME_INVALID');
  assert.equal(vc({ ...base, now: '2030-01-01T00:00:00.000Z', expectedIssuers: [KEYS.other.did] }).errors[0], 'EXPIRED');
  assert.equal(vc({ ...base, expectedIssuers: [KEYS.other.did] }).errors[0], 'ISSUER_NOT_EXPECTED');
});

test('verify-credential reports internal consistency only without the report and names the differing member with it', () => {
  const alone = V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.resigned-edit-verifies-without-the-report'));
  assert.equal(alone.valid, true);
  assert.equal(alone.reportChecked, false);
  assert.equal(alone.authenticated, false);
  const withReport = V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.resigned-edit-is-caught-by-the-report'));
  assert.deepEqual([withReport.valid, withReport.errors, withReport.reportMismatch, withReport.reportChecked], [false, ['REPORT_MISMATCH'], ['credentialSubject'], true]);
  const lacking = V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.report-lacks-a-member-the-rebuild-needs'));
  assert.deepEqual(lacking.errors, ['REPORT_INVALID']);
  assert.equal(lacking.reportChecked, false);
  const fixture = V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.fixture-credential-relabelled-runtime-is-caught-by-the-report'));
  assert.deepEqual(fixture.errors, ['REPORT_MISMATCH']);
});

test('verify-credential never infers trust from a signature and trust by policy needs a live anchor', () => {
  const plain = V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.valid-unchecked-issuer'));
  assert.equal(plain.issuerTrust, 'unchecked');
  assert.equal(plain.authenticated, false);
  assert.deepEqual(V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.trust-policy-without-the-issuer')).errors, ['ISSUER_NOT_TRUSTED']);
  assert.deepEqual(V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.trust-policy-anchor-revoked')).errors, ['ISSUER_NOT_TRUSTED']);
  const anchored = V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.valid-anchored-by-policy'));
  assert.deepEqual([anchored.issuerTrust, anchored.issuerRole, anchored.valid], ['anchored', 'independent', true]);
});

test('verify-credential status checks use own members of statusLists only and name each failure', () => {
  const proto = V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.status-url-is-a-prototype-member-name'));
  assert.equal(proto.valid, true);
  assert.equal(proto.status.checked, false);
  // The library itself no longer reads an inherited member or a coerced key as a list.
  const base = inputsOf('verify-credential.status-url-is-a-prototype-member-name');
  const lib = verifyAssessmentCredential(base.jwt, { now: base.now, statusLists: {} });
  assert.equal(lib.status.entries[0].checked, false);
  const order = V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.status-bit-zero-is-the-leftmost-bit'));
  assert.deepEqual(order.status.entries.map(e => e.set), [true, false, false, false, true]);
  for (const [id, code] of [['status-list-expired', 'STATUS_LIST_EXPIRED'], ['status-list-without-valid-until', 'STATUS_LIST_NO_EXPIRY'], ['status-list-has-fewer-than-131072-entries', 'STATUS_LIST_LENGTH_ERROR'], ['status-list-inflates-past-the-bound', 'STATUS_LIST_INVALID'], ['status-entry-index-with-a-leading-zero', 'STATUS_ENTRY_INVALID'], ['status-index-beyond-the-list', 'STATUS_VERIFICATION_ERROR']]) {
    assert.deepEqual(V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.' + id)).errors, [code], id);
  }
  assert.deepEqual(V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.status-index-beyond-the-list')).status.entries[0].error, 'RANGE_ERROR');
  assert.deepEqual(V2_OPERATIONS['verify-credential'](inputsOf('verify-credential.status-list-of-the-largest-allowed-size')).errors, ['REVOKED']);
});

test('verify-credential refuses input outside the contract and never returns a result for it', () => {
  const refusals = FILE.vectors.filter(v => v.operation === 'verify-credential' && v.expected.refused === true && v.inputs);
  assert.ok(refusals.length >= 50, `only ${refusals.length} structural refusals`);
  for (const v of refusals) assert.throws(() => V2_OPERATIONS['verify-credential'](structuredClone(v.inputs)), v.id);
  const base = inputsOf('verify-credential.valid-unchecked-issuer');
  assert.doesNotThrow(() => V2_OPERATIONS['verify-credential'](base));
  assert.throws(() => V2_OPERATIONS['verify-credential']({ ...base, extra: 1 }));
});

test('the credential library refuses ill-formed UTF-8 and reads only an array as the evidence block', () => {
  const v = inputsOf('verify-credential.payload-is-ill-formed-utf8');
  assert.deepEqual(vc(v).errors, ['MALFORMED']);
  const keyed = vc(inputsOf('verify-credential.claims-evidence-is-an-object-keyed-zero'));
  assert.deepEqual(keyed.errors, ['EVIDENCE_REFERENCE_MISMATCH']);
});

test('verify-score-card recomputes every number from the items and judges a value that is not a card without refusing', () => {
  const ok = V2_OPERATIONS['verify-score-card'](inputsOf('verify-score-card.valid-baseline'));
  assert.equal(ok.valid, true);
  assert.equal(ok.cardDigest, inputsOf('verify-score-card.valid-baseline').card.cardDigest);
  const edited = inputsOf('verify-score-card.headline-score-edited-and-card-digest-recomputed');
  assert.deepEqual(V2_OPERATIONS['verify-score-card'](edited).problems, ['results-differ-from-recomputation', 'card-differs-from-recomputation']);
  for (const value of [null, 'card', [], 7, true]) assert.deepEqual(V2_OPERATIONS['verify-score-card']({ card: value }).problems, ['wrong-schema']);
  const resealedManifest = V2_OPERATIONS['verify-score-card'](inputsOf('verify-score-card.valid-after-a-resealed-edit-of-the-subject-version'));
  assert.equal(resealedManifest.valid, true, 'a re-sealed edit of a member no computation reads verifies, by design');
  const scoreOf = card => card.results.headline.score;
  assert.equal(ok.score, scoreOf(inputsOf('verify-score-card.valid-baseline').card));
});

test('verify-score-card fails a card whose evidence is below the floor or whose floor was lowered', () => {
  for (const [id, problems] of [['floor-lowered-below-the-hard-minimum', ['floor-below-hard-minimum', 'card-differs-from-recomputation']], ['only-two-runs', ['evidence-floor-not-met']], ['only-29-items', ['evidence-floor-not-met']], ['only-nine-held-out-items', ['evidence-floor-not-met']], ['holdout-commitment-removed', ['evidence-floor-not-met']], ['floor-raised-above-the-evidence', ['evidence-floor-not-met']]]) {
    const r = V2_OPERATIONS['verify-score-card'](inputsOf('verify-score-card.' + id));
    assert.deepEqual([r.valid, r.problems, r.score, r.cardDigest], [false, problems, null, null], id);
  }
});

test('compare-score-cards compares only valid cards of one suite and evaluator', () => {
  const cmp = id => V2_OPERATIONS['compare-score-cards'](inputsOf('compare-score-cards.' + id));
  assert.deepEqual(cmp('different-suite-and-evaluator').reasons, ['suite-digest-differs', 'evaluator-digest-differs']);
  assert.deepEqual(cmp('invalid-before-lineage'), { schema: 'kya.impl-result/v1', operation: 'compare-score-cards', comparable: false, reasons: ['card-invalid'], delta: null, distinguishable: null });
  const a = cmp('clearly-different-scores'), c = cmp('delta-is-left-minus-right');
  assert.equal(a.delta, -c.delta);
  assert.equal(a.distinguishable, true);
  assert.equal(cmp('the-same-card-twice').delta, 0);
});

test('the vectors file lists nine operations and keeps the earlier 485 vectors and the keys byte for byte', () => {
  assert.deepEqual(FILE.contract, { version: 2, operations: ['assess', 'currency', 'canonicalize', 'digest', 'verify-envelope', 'compare', 'verify-credential', 'verify-score-card', 'compare-score-cards'] });
  const earlier = FILE.vectors.filter(v => !['verify-credential', 'verify-score-card', 'compare-score-cards'].includes(v.operation));
  assert.equal(earlier.length, 485);
  assert.equal(digest(earlier.map(v => digest(v))), '19b326637927fdb5b0c64f65bed7c441fe7933cdc35f4839d0e4790ae0258fcc');
  assert.equal(digest(FILE.keys), '02c677ab13a35f2bed1f00672e67933801dc6d984e1dbd1b738f447cc5cc4ff5');
  for (const op of ['verify-credential', 'verify-score-card', 'compare-score-cards']) assert.ok(FILE.vectors.filter(v => v.operation === op).length >= 15, op);
});

test('at least a third of the later vectors are refusals and every one cites a requirement and names it in its rationale', () => {
  const later = FILE.vectors.filter(v => ['verify-credential', 'verify-score-card', 'compare-score-cards'].includes(v.operation));
  const refusals = later.filter(v => v.expected.refused === true);
  assert.ok(refusals.length * 3 >= later.length, `${refusals.length} of ${later.length}`);
  for (const v of later) assert.ok(v.requirements.some(r => v.rationale.includes(r)), v.id);
  const raw = later.filter(v => typeof v.rawInput === 'string');
  assert.ok(raw.length >= 20);
  for (const v of raw) { assert.equal(v.expected.refused, true, v.id); assert.equal(v.inputs, undefined, v.id); }
});

test('every specified credential code, score card problem code and comparison reason appears in at least one vector', () => {
  const credentialCodes = ['TIME_INVALID', 'MALFORMED', 'ALG_NOT_ALLOWED', 'HEADER_MEMBER_NOT_ALLOWED', 'TYP_NOT_ALLOWED', 'PAYLOAD_INVALID', 'ISSUER_INVALID', 'KID_MISMATCH', 'SIGNATURE_INVALID', 'NOT_YET_VALID', 'EXPIRED', 'ISSUER_NOT_EXPECTED', 'EVIDENCE_MODE_LIMITATION_MISMATCH', 'EVIDENCE_REFERENCE_MISMATCH', 'REPORT_INVALID', 'REPORT_MISMATCH', 'ISSUER_NOT_TRUSTED', 'REVOKED', 'SUSPENDED', 'STATUS_ENTRY_INVALID', 'STATUS_LIST_EXPIRED', 'STATUS_LIST_NO_EXPIRY', 'STATUS_LIST_LENGTH_ERROR', 'STATUS_LIST_INVALID', 'STATUS_VERIFICATION_ERROR', 'STATUS_NOT_CHECKED'];
  for (const c of credentialCodes) assert.ok(FILE.vectors.some(v => v.operation === 'verify-credential' && v.expected.errors?.includes(c)), c);
  const problems = ['wrong-schema', 'unexpected-or-missing-fields', 'card-digest-differs', 'run-digest-differs', 'floor-below-hard-minimum', 'evidence-floor-not-met', 'rebuild-failed', 'results-differ-from-recomputation', 'card-differs-from-recomputation'];
  for (const c of problems) assert.ok(FILE.vectors.some(v => v.operation === 'verify-score-card' && v.expected.problems?.includes(c)), c);
  for (const c of ['card-invalid', 'suite-digest-differs', 'evaluator-digest-differs']) assert.ok(FILE.vectors.some(v => v.operation === 'compare-score-cards' && v.expected.reasons?.includes(c)), c);
});
