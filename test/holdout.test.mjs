import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { commitHoldout, revealCase, verifyReveal, verifyFullReveal, generateSalt, MAX_CASES } from '../src/holdout/index.mjs';

const SALT = 'a1'.repeat(32);
const AT = '2026-10-14T00:00:00Z';
const mk = (n, extra = {}) => Array.from({ length: n }, (_, i) => ({ id: `case-${i}`, prompt: `synthetic holdout prompt ${i}`, ...extra }));
const commit = (cases, opts = {}) => commitHoldout(cases, { salt: SALT, suiteId: 'holdout-demo', createdAt: AT, ...opts });
const clone = v => JSON.parse(JSON.stringify(v));

test('commitment has the documented shape and takes createdAt only from the caller', () => {
  const { commitment, opening } = commit(mk(5));
  assert.deepEqual(Object.keys(commitment).sort(), ['caseCount', 'createdAt', 'merkleRoot', 'saltCommitment', 'schema', 'suiteId']);
  assert.equal(commitment.schema, 'kya.holdout-commitment/v1');
  assert.equal(commitment.caseCount, 5);
  assert.equal(commitment.createdAt, AT);
  assert.match(commitment.merkleRoot, /^[a-f0-9]{64}$/);
  assert.match(commitment.saltCommitment, /^[a-f0-9]{64}$/);
  assert.equal(opening.cases.length, 5);
  assert.throws(() => commitHoldout(mk(2), { salt: SALT, suiteId: 'holdout-demo' }), TypeError);
  for (const bad of ['yesterday', '2026-10-14', 1760400000, null, '2026-13-45T00:00:00Z']) assert.throws(() => commit(mk(2), { createdAt: bad }), TypeError, String(bad));
});

test('commitment is deterministic, salt sensitive and independent of createdAt', () => {
  const a = commit(mk(4)).commitment, b = commit(mk(4)).commitment;
  assert.deepEqual(a, b);
  assert.notEqual(commit(mk(4), { salt: 'b2'.repeat(32) }).commitment.merkleRoot, a.merkleRoot);
  assert.equal(commit(mk(4), { createdAt: '2027-01-01T00:00:00Z' }).commitment.merkleRoot, a.merkleRoot);
  assert.notEqual(commit(mk(4), { suiteId: 'other-suite' }).commitment.merkleRoot, a.merkleRoot);
  assert.match(generateSalt(), /^[0-9a-f]{64}$/);
  assert.notEqual(generateSalt(), generateSalt());
});

test('every case of every set size from one to seventeen reveals and verifies including odd leaf counts', () => {
  for (let n = 1; n <= 17; n++) {
    const { commitment, opening } = commit(mk(n));
    for (let i = 0; i < n; i++) {
      const { case: c, proof } = revealCase(opening, i);
      assert.deepEqual(verifyReveal(commitment, c, proof), { ok: true }, `n=${n} i=${i}`);
    }
    assert.deepEqual(verifyFullReveal(commitment, opening), { ok: true }, `full n=${n}`);
  }
});

test('a single case set and a two case set behave correctly at the edges', () => {
  const one = commit(mk(1));
  const r = revealCase(one.opening, 0);
  assert.deepEqual(r.proof.siblings, []);
  assert.deepEqual(verifyReveal(one.commitment, r.case, r.proof), { ok: true });
  const two = commit(mk(2));
  assert.equal(revealCase(two.opening, 1).proof.siblings.length, 1);
});

test('an empty set is refused and duplicate cases cannot be committed', () => {
  assert.throws(() => commit([]), TypeError);
  assert.throws(() => commit(null), TypeError);
  assert.throws(() => commit(mk(1).concat(mk(1))), /Duplicate/);
  assert.throws(() => commit([{ a: 1, b: 2 }, { b: 2, a: 1 }]), /Duplicate/);
});

test('odd leaf promotion is not duplication so a set and its last-case duplicate have different roots', () => {
  const three = mk(3);
  const { commitment } = commit(three);
  assert.throws(() => commit([...three, three[2]]), /Duplicate/);
  const four = commit([...three, { id: 'case-3', prompt: 'x' }]).commitment;
  assert.notEqual(four.merkleRoot, commitment.merkleRoot);
  const pinned = { ...commitment, caseCount: 4 };
  const { opening } = commit(three);
  const { case: c, proof } = revealCase(opening, 2);
  assert.equal(verifyReveal(pinned, c, proof).ok, false);
});

test('a revealed case verifies without exposing other cases or the master salt', () => {
  const secret = commit(mk(8, { secretMarker: 'MARKER' }));
  const marked = commit(mk(8).map((c, i) => ({ ...c, secretMarker: `UNREVEALED-${i}` })));
  const { case: c, proof } = revealCase(marked.opening, 3);
  const wire = JSON.stringify({ c, proof });
  assert.ok(!wire.includes(marked.opening.salt));
  for (let i = 0; i < 8; i++) if (i !== 3) assert.ok(!wire.includes(`UNREVEALED-${i}`));
  assert.equal(proof.siblings.length, 3);
  assert.deepEqual(verifyReveal(marked.commitment, c, proof), { ok: true });
  assert.ok(secret.commitment.merkleRoot);
});

test('unrevealed cases cannot be confirmed by guessing because leaves are salted per case', () => {
  const { opening } = commit(mk(2));
  const { proof } = revealCase(opening, 0);
  const sibling = proof.siblings[0];
  const guess = createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(JSON.stringify(mk(2)[1]))])).digest('hex');
  assert.notEqual(sibling, guess);
  const other = revealCase(commit(mk(2), { salt: 'c3'.repeat(32) }).opening, 0);
  assert.notEqual(other.proof.caseSalt, proof.caseSalt);
  assert.notEqual(other.proof.siblings[0], sibling);
});

test('a revealed case that is not in the commitment is rejected', () => {
  const a = commit(mk(6)), b = commit(mk(6).map(c => ({ ...c, prompt: c.prompt + ' changed' })));
  const real = revealCase(a.opening, 2);
  assert.deepEqual(verifyReveal(a.commitment, real.case, real.proof), { ok: true });
  assert.equal(verifyReveal(a.commitment, { id: 'case-2', prompt: 'swapped later' }, real.proof).reason, 'not-in-commitment');
  const foreign = revealCase(b.opening, 2);
  assert.equal(verifyReveal(a.commitment, foreign.case, foreign.proof).ok, false);
  assert.equal(verifyReveal(a.commitment, real.case, { ...real.proof, caseSalt: 'e5'.repeat(32) }).ok, false);
  assert.equal(verifyReveal(a.commitment, real.case, { ...real.proof, index: 3 }).ok, false);
});

test('proof tampering truncation extension and reordering are all detected', () => {
  const { commitment, opening } = commit(mk(9));
  const { case: c, proof } = revealCase(opening, 4);
  const flipped = clone(proof); flipped.siblings[0] = (flipped.siblings[0][0] === 'a' ? 'b' : 'a') + flipped.siblings[0].slice(1);
  assert.equal(verifyReveal(commitment, c, flipped).ok, false);
  assert.equal(verifyReveal(commitment, c, { ...proof, siblings: proof.siblings.slice(1) }).reason, 'proof-shape');
  assert.equal(verifyReveal(commitment, c, { ...proof, siblings: [] }).reason, 'proof-shape');
  assert.equal(verifyReveal(commitment, c, { ...proof, siblings: [...proof.siblings, proof.siblings[0]] }).reason, 'proof-shape');
  assert.equal(verifyReveal(commitment, c, { ...proof, siblings: [...proof.siblings].reverse() }).ok, false);
  assert.equal(verifyReveal(commitment, c, { ...proof, index: 99 }).reason, 'index-out-of-range');
  assert.equal(verifyReveal(commitment, c, { ...proof, index: -1 }).reason, 'index-out-of-range');
});

test('second preimage by leaf and node confusion is rejected by domain separation and count binding', () => {
  const { commitment, opening } = commit(mk(4));
  const { case: c, proof } = revealCase(opening, 0);
  // Treat the internal node over leaves 0 and 1 as if it were a leaf: a proof of the remaining upper levels only.
  const upper = { index: 0, caseSalt: proof.caseSalt, siblings: [proof.siblings[1]] };
  assert.equal(verifyReveal(commitment, c, upper).reason, 'proof-shape');
  // Forge a two-case commitment whose root is the sub-tree top of the four-case tree: still different because the root binds count and suite.
  const two = commit(mk(2)).commitment;
  assert.notEqual(two.merkleRoot, commitment.merkleRoot);
  // A node digest offered as a case value cannot reproduce a leaf: leaves and nodes use different tag bytes.
  const nodeLikeCase = { id: proof.siblings[0], prompt: proof.siblings[1] };
  assert.equal(verifyReveal(commitment, nodeLikeCase, proof).ok, false);
  // Changing the claimed case count, suite or schema invalidates the same proof.
  assert.equal(verifyReveal({ ...commitment, caseCount: 3 }, c, proof).ok, false);
  assert.equal(verifyReveal({ ...commitment, suiteId: 'holdout-demo-2' }, c, proof).ok, false);
});

test('full reveal accepts the true opening and rejects reordering omission duplication and substitution', () => {
  const { commitment, opening } = commit(mk(7));
  assert.deepEqual(verifyFullReveal(commitment, opening), { ok: true });
  const swapped = clone(opening); [swapped.cases[1], swapped.cases[5]] = [swapped.cases[5], swapped.cases[1]];
  assert.equal(verifyFullReveal(commitment, swapped).reason, 'root-mismatch');
  const reversed = clone(opening); reversed.cases.reverse();
  assert.equal(verifyFullReveal(commitment, reversed).reason, 'root-mismatch');
  const omitted = clone(opening); omitted.cases.pop();
  assert.equal(verifyFullReveal(commitment, omitted).reason, 'case-count-mismatch');
  const extra = clone(opening); extra.cases.push({ id: 'case-extra' });
  assert.equal(verifyFullReveal(commitment, extra).reason, 'case-count-mismatch');
  const duplicated = clone(opening); duplicated.cases[6] = clone(duplicated.cases[0]);
  assert.equal(verifyFullReveal(commitment, duplicated).reason, 'duplicate-case');
  const substituted = clone(opening); substituted.cases[3] = { id: 'case-3', prompt: 'post hoc replacement' };
  assert.equal(verifyFullReveal(commitment, substituted).reason, 'root-mismatch');
});

test('full reveal rejects a wrong salt and malformed openings without throwing', () => {
  const { commitment, opening } = commit(mk(3));
  assert.equal(verifyFullReveal(commitment, { ...opening, salt: 'd4'.repeat(32) }).reason, 'salt-mismatch');
  for (const bad of [null, undefined, 'x', 3, [], {}, { cases: [], salt: 'x' }, { cases: opening.cases, salt: 5 }, { cases: opening.cases, salt: 'zz' }]) {
    assert.equal(verifyFullReveal(commitment, bad).ok, false, JSON.stringify(bad));
  }
  assert.equal(verifyFullReveal({ ...commitment, caseCount: 0 }, opening).reason, 'invalid-commitment');
  assert.equal(verifyFullReveal(null, opening).reason, 'invalid-commitment');
  assert.equal(verifyFullReveal({ ...commitment, extra: 1 }, opening).reason, 'invalid-commitment');
  assert.equal(verifyFullReveal(commitment, { cases: [() => 1, 2, 3], salt: opening.salt }).ok, false);
});

test('hostile commitments and proofs are rejected without throwing', () => {
  const { commitment, opening } = commit(mk(5));
  const { case: c, proof } = revealCase(opening, 1);
  for (const bad of [null, undefined, 'x', 5, [], {}, { ...commitment, merkleRoot: 'abc' }, { ...commitment, caseCount: 1.5 }, { ...commitment, caseCount: MAX_CASES + 1 }, { ...commitment, schema: 'x' }, { ...commitment, createdAt: undefined }]) {
    assert.equal(verifyReveal(bad, c, proof).ok, false);
  }
  for (const bad of [null, undefined, 'x', 5, [], {}, { ...proof, extra: 1 }, { ...proof, index: '1' }, { ...proof, index: 1.5 }, { ...proof, caseSalt: 'short' }, { ...proof, siblings: 'x' }, { ...proof, siblings: [5] }, { ...proof, siblings: Array(40).fill('a'.repeat(64)) }, { ...proof, siblings: ['G'.repeat(64)] }]) {
    assert.equal(verifyReveal(commitment, c, bad).ok, false, JSON.stringify(bad));
  }
  for (const badCase of [undefined, () => 1, 1n, Symbol('s'), NaN, { get x() { throw new Error('boom'); } }]) {
    assert.equal(verifyReveal(commitment, badCase, proof).ok, false);
  }
  assert.throws(() => revealCase(opening, 5), RangeError);
  assert.throws(() => revealCase(opening, -1), RangeError);
  assert.throws(() => revealCase(opening, 1.5), RangeError);
  assert.throws(() => revealCase(null, 0), TypeError);
});

test('invalid salts suite ids and non JSON cases are refused at commit time', () => {
  for (const salt of [undefined, '', 'short', 'zz'.repeat(16), 'a1'.repeat(65), 'a1'.repeat(15), new Uint8Array(8), 12345, 'A1'.repeat(32)]) assert.throws(() => commit(mk(2), { salt }), TypeError, String(salt));
  assert.doesNotThrow(() => commit(mk(2), { salt: new Uint8Array(32).fill(7) }));
  for (const suiteId of [undefined, '', 'Has Space', 'x', 5, 'a'.repeat(70)]) assert.throws(() => commit(mk(2), { suiteId }), TypeError, String(suiteId));
  for (const bad of [undefined, () => 1, 1n, NaN, Symbol('s')]) assert.throws(() => commit([{ ok: 1 }, bad]));
});

test('huge inputs are bounded by case count and case size', () => {
  assert.throws(() => commit(Array.from({ length: MAX_CASES + 1 }, (_, i) => i)), /Too many/);
  assert.throws(() => commit([{ big: 'x'.repeat(2_000_000) }]));
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => commit([cyclic]));
  let deep = {}; const root = deep; for (let i = 0; i < 50; i++) { deep.n = {}; deep = deep.n; }
  assert.throws(() => commit([root]));
});

test('a larger set of two thousand cases verifies at spread indices and the proof stays logarithmic', () => {
  const { commitment, opening } = commit(mk(2000));
  for (const i of [0, 1, 999, 1024, 1998, 1999]) {
    const { case: c, proof } = revealCase(opening, i);
    assert.ok(proof.siblings.length <= 11);
    assert.deepEqual(verifyReveal(commitment, c, proof), { ok: true }, `index ${i}`);
  }
  assert.deepEqual(verifyFullReveal(commitment, opening), { ok: true });
});

test('cherry picking is detectable because the same count and root bind every case a campaign must disclose', () => {
  const { commitment, opening } = commit(mk(10));
  const cherryPicked = clone(opening); cherryPicked.cases = cherryPicked.cases.slice(0, 6);
  assert.equal(verifyFullReveal(commitment, cherryPicked).reason, 'case-count-mismatch');
  const swappedHard = clone(opening); swappedHard.cases[9] = { id: 'case-9', prompt: 'an easier replacement' };
  assert.equal(verifyFullReveal(commitment, swappedHard).ok, false);
});
