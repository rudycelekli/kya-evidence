import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonical } from '../shared/canonical.mjs';

// Commit-reveal over a hidden case set. See docs/SCENARIO-SUITES.md for exactly what this does and does not establish.
export const HOLDOUT_COMMITMENT_SCHEMA = 'kya.holdout-commitment/v1';
export const MAX_CASES = 65536;
const TAG = Object.freeze({ leaf: 0x00, node: 0x01, root: 0x02 });
const SALT_RE = /^[0-9a-f]{32,128}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const SUITE_ID = /^[a-z0-9][a-z0-9.-]{0,62}[a-z0-9]$/u;

const sha = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const tag = n => Buffer.from([n]);
const label = s => Buffer.from(s, 'utf8');
const equalHex = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

function saltBytes(salt) {
  if (salt instanceof Uint8Array && salt.length >= 16 && salt.length <= 64) return Buffer.from(salt);
  if (typeof salt === 'string' && SALT_RE.test(salt) && salt.length % 2 === 0) return Buffer.from(salt, 'hex');
  throw new TypeError('Salt must be 16 to 64 bytes (Uint8Array or even-length lowercase hex)');
}
/** Fresh 32-byte salt as hex. Salt secrecy and entropy are the committer's responsibility. */
export function generateSalt() { return randomBytes(32).toString('hex'); }
const caseSalt = (salt, index) => createHmac('sha256', salt).update(label('kya.holdout.case-salt/v1')).update(u32(index)).digest();
const caseDigest = value => sha(label('kya.holdout.case/v1'), label(canonical(value)));
const leaf = (cSalt, index, value) => sha(tag(TAG.leaf), label('kya.holdout.leaf/v1'), cSalt, u32(index), caseDigest(value));
const node = (left, right) => sha(tag(TAG.node), left, right);
const saltCommit = salt => sha(label('kya.holdout.salt-commitment/v1'), salt).toString('hex');
const bind = (top, count, suiteId) => sha(tag(TAG.root), label('kya.holdout.root/v1'), u32(count), sha(label(suiteId)), top);

function levels(leaves) {
  const out = [leaves];
  while (out.at(-1).length > 1) {
    const cur = out.at(-1), next = [];
    // An unpaired node is promoted unchanged (never duplicated), so [a,b,c] and [a,b,c,c] have different roots.
    for (let i = 0; i < cur.length; i += 2) next.push(i + 1 < cur.length ? node(cur[i], cur[i + 1]) : cur[i]);
    out.push(next);
  }
  return out;
}
function normaliseCases(cases) {
  if (!Array.isArray(cases)) throw new TypeError('cases must be an array');
  if (cases.length === 0) throw new TypeError('A holdout cannot be empty');
  if (cases.length > MAX_CASES) throw new TypeError('Too many holdout cases');
  const copies = cases.map(c => JSON.parse(canonical(c)));
  const seen = new Set();
  for (const c of copies) { const d = caseDigest(c).toString('hex'); if (seen.has(d)) throw new TypeError('Duplicate holdout case'); seen.add(d); }
  return copies;
}
const validTime = t => typeof t === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/u.test(t) && !Number.isNaN(Date.parse(t));
function checkTime(createdAt) {
  if (!validTime(createdAt)) throw new TypeError('createdAt must be supplied explicitly as a UTC ISO-8601 timestamp');
}
function rootOf(cases, salt, suiteId) {
  const tree = levels(cases.map((c, i) => leaf(caseSalt(salt, i), i, c)));
  return { tree, root: bind(tree.at(-1)[0], cases.length, suiteId).toString('hex') };
}

/**
 * Commit to an ordered set of hidden cases. Returns the public `commitment` and the private `opening`
 * (salt and cases) that only the holder keeps. createdAt is never read from a clock.
 */
export function commitHoldout(cases, { salt, suiteId, createdAt } = {}) {
  if (typeof suiteId !== 'string' || !SUITE_ID.test(suiteId)) throw new TypeError('Invalid suiteId');
  checkTime(createdAt);
  const s = saltBytes(salt), copies = normaliseCases(cases);
  const { root } = rootOf(copies, s, suiteId);
  return {
    commitment: { schema: HOLDOUT_COMMITMENT_SCHEMA, suiteId, caseCount: copies.length, merkleRoot: root, saltCommitment: saltCommit(s), createdAt },
    opening: { salt: s.toString('hex'), cases: copies }
  };
}

function validCommitment(c) {
  return c && typeof c === 'object' && !Array.isArray(c) && Object.getPrototypeOf(c) === Object.prototype
    && Object.keys(c).sort().join() === 'caseCount,createdAt,merkleRoot,saltCommitment,schema,suiteId'
    && c.schema === HOLDOUT_COMMITMENT_SCHEMA && typeof c.suiteId === 'string' && SUITE_ID.test(c.suiteId)
    && Number.isSafeInteger(c.caseCount) && c.caseCount >= 1 && c.caseCount <= MAX_CASES
    && typeof c.merkleRoot === 'string' && HEX64.test(c.merkleRoot) && typeof c.saltCommitment === 'string' && HEX64.test(c.saltCommitment) && validTime(c.createdAt);
}

/** Produce a reveal for one case: the case, its per-case salt and the sibling path. Reveals no other case or the master salt. */
export function revealCase(opening, index) {
  if (!opening || !Array.isArray(opening.cases) || typeof opening.salt !== 'string') throw new TypeError('Invalid opening');
  if (!Number.isInteger(index) || index < 0 || index >= opening.cases.length) throw new RangeError('Case index out of range');
  const s = saltBytes(opening.salt), cases = opening.cases.map(c => JSON.parse(canonical(c)));
  const tree = levels(cases.map((c, i) => leaf(caseSalt(s, i), i, c)));
  const siblings = [];
  let pos = index;
  for (let level = 0; level < tree.length - 1; level++) {
    const sib = pos % 2 === 1 ? pos - 1 : pos + 1;
    if (sib < tree[level].length) siblings.push(tree[level][sib].toString('hex'));
    pos = Math.floor(pos / 2);
  }
  return { case: cases[index], proof: { index, caseSalt: caseSalt(s, index).toString('hex'), siblings } };
}

/** Verify that `value` sat at proof.index of the committed set. Returns {ok:true} or {ok:false, reason}. Never throws on hostile input. */
export function verifyReveal(commitment, value, proof) {
  try {
    if (!validCommitment(commitment)) return { ok: false, reason: 'invalid-commitment' };
    if (!proof || typeof proof !== 'object' || Array.isArray(proof) || Object.keys(proof).sort().join() !== 'caseSalt,index,siblings') return { ok: false, reason: 'malformed-proof' };
    const { index, caseSalt: cs, siblings } = proof;
    if (!Number.isInteger(index) || typeof cs !== 'string' || !HEX64.test(cs) || !Array.isArray(siblings) || siblings.length > 17 || siblings.some(x => typeof x !== 'string' || !HEX64.test(x))) return { ok: false, reason: 'malformed-proof' };
    if (index < 0 || index >= commitment.caseCount) return { ok: false, reason: 'index-out-of-range' };
    let acc = leaf(Buffer.from(cs, 'hex'), index, JSON.parse(canonical(value))), pos = index, size = commitment.caseCount, used = 0;
    while (size > 1) {
      const hasSibling = pos % 2 === 1 || pos + 1 < size;
      if (hasSibling) {
        if (used >= siblings.length) return { ok: false, reason: 'proof-shape' };
        const sib = Buffer.from(siblings[used++], 'hex');
        acc = pos % 2 === 1 ? node(sib, acc) : node(acc, sib);
      }
      pos = Math.floor(pos / 2); size = Math.ceil(size / 2);
    }
    if (used !== siblings.length) return { ok: false, reason: 'proof-shape' };
    return equalHex(bind(acc, commitment.caseCount, commitment.suiteId).toString('hex'), commitment.merkleRoot) ? { ok: true } : { ok: false, reason: 'not-in-commitment' };
  } catch { return { ok: false, reason: 'malformed-input' }; }
}

/** After a campaign: check the complete opening (all cases, in order, with the master salt) against the commitment. */
export function verifyFullReveal(commitment, opening) {
  try {
    if (!validCommitment(commitment)) return { ok: false, reason: 'invalid-commitment' };
    if (!opening || typeof opening !== 'object' || !Array.isArray(opening.cases) || typeof opening.salt !== 'string') return { ok: false, reason: 'malformed-opening' };
    if (opening.cases.length !== commitment.caseCount) return { ok: false, reason: 'case-count-mismatch' };
    let s;
    try { s = saltBytes(opening.salt); } catch { return { ok: false, reason: 'malformed-opening' }; }
    if (!equalHex(saltCommit(s), commitment.saltCommitment)) return { ok: false, reason: 'salt-mismatch' };
    const seen = new Set(), copies = [];
    for (const c of opening.cases) {
      const copy = JSON.parse(canonical(c)), d = caseDigest(copy).toString('hex');
      if (seen.has(d)) return { ok: false, reason: 'duplicate-case' };
      seen.add(d); copies.push(copy);
    }
    return equalHex(rootOf(copies, s, commitment.suiteId).root, commitment.merkleRoot) ? { ok: true } : { ok: false, reason: 'root-mismatch' };
  } catch { return { ok: false, reason: 'malformed-input' }; }
}
