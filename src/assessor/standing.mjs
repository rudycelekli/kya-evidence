import { canonical, captureArrayItems, insist } from '../shared/canonical.mjs';
import { hash, timestamp } from '../identity/domain/services/validation.mjs';
import { RELATIONSHIPS, verifyDisclosure } from './disclosure.mjs';

export const STANDING_REASONS = Object.freeze(['no-disclosure', 'disclosure-expired', 'disclosure-not-yet-valid', 'key-revoked', 'blocking-relationship', 'undisclosed-conflict-declared-by-other-party', 'cooling-off-not-elapsed', 'conflicting-disclosures']);
export const IGNORED_REASONS = Object.freeze(['invalid-record', 'signer-mismatch', 'untrusted-declarer', 'declarer-revoked', 'different-operator', 'withdrawal-target-unknown', 'withdrawal-time-invalid', 'unrelated-key']);
export const DEFAULT_BLOCKING = Object.freeze(['authorship', 'control', 'employment', 'financial']);
const DAY = 86_400_000, MAX_RECORDS = 1024;

function checkPolicy(p) {
  insist(p && typeof p === 'object' && !Array.isArray(p), 'Standing policy must be an object');
  const allowed = ['operatorDigest', 'assessorKeyIds', 'declarerKeyIds', 'revokedKeyIds', 'coolingOffDays', 'blockingRelationships'];
  insist(Object.keys(p).every(k => allowed.includes(k)), 'Unknown standing policy field');
  hash(p.operatorDigest, 'Operator digest');
  const ids = (v, label) => { insist(Array.isArray(v) && v.length <= 256, label + ': invalid list'); v.forEach(x => hash(x, label)); insist(new Set(v).size === v.length, label + ': duplicate'); return v; };
  const assessors = ids(p.assessorKeyIds, 'Assessor keys'), declarers = ids(p.declarerKeyIds ?? [], 'Declarer keys'), revoked = ids(p.revokedKeyIds ?? [], 'Revoked keys');
  const cool = p.coolingOffDays ?? 365; insist(Number.isInteger(cool) && cool >= 0 && cool <= 3650, 'Invalid cooling-off days');
  const blocking = p.blockingRelationships ?? DEFAULT_BLOCKING;
  insist(Array.isArray(blocking) && blocking.every(r => RELATIONSHIPS.includes(r) && r !== 'none') && new Set(blocking).size === blocking.length, 'Invalid blocking relationships');
  return { operatorDigest: p.operatorDigest, assessors, declarers: new Set(declarers), revoked: new Set(revoked), cool, blocking: new Set(blocking) };
}

/**
 * Standing is a currency-style check over supplied disclosure records. It never changes an assessment result by itself.
 * A key in good standing has a current, unwithdrawn, own-signed disclosure for this operator, no blocking relationship,
 * no unfinished cooling-off and no conflict declared by a trusted other party that the assessor did not disclose.
 * Standing is not accreditation and not proof that a disclosure is true.
 */
export function checkAssessorStanding(disclosures, policy, now) {
  const P = checkPolicy(policy);
  const t = timestamp(typeof now === 'string' ? now : (now instanceof Date && !Number.isNaN(now.getTime()) ? now.toISOString() : ''), 'now');
  const items = captureArrayItems(disclosures, MAX_RECORDS, 'Disclosures');
  const ignored = [], valid = [], seen = new Set();
  items.forEach((env, index) => {
    let v; try { v = verifyDisclosure(env); } catch { ignored.push({ index, reason: 'invalid-record' }); return; }
    if (!seen.has(v.envelopeDigest)) { seen.add(v.envelopeDigest); valid.push({ ...v, index }); } // identical redelivery collapses
  });
  const byAssessor = new Map(P.assessors.map(k => [k, { own: [], declarations: [], withdrawals: [] }]));
  for (const r of valid) {
    const d = r.payload, slot = byAssessor.get(d.assessorKeyId);
    if (!slot) { ignored.push({ index: r.index, reason: 'unrelated-key' }); continue; }
    if (d.operatorDigest !== P.operatorDigest) { ignored.push({ index: r.index, reason: 'different-operator' }); continue; }
    const trustedDeclarer = r.keyId !== d.assessorKeyId && P.declarers.has(r.keyId);
    if (d.kind === 'conflict-declaration') {
      if (!trustedDeclarer) { ignored.push({ index: r.index, reason: 'untrusted-declarer' }); continue; }
      if (P.revoked.has(r.keyId)) { ignored.push({ index: r.index, reason: 'declarer-revoked' }); continue; }
      slot.declarations.push(r);
    } else if (d.kind === 'withdrawal') {
      if (r.keyId !== d.assessorKeyId && !trustedDeclarer) { ignored.push({ index: r.index, reason: 'signer-mismatch' }); continue; }
      if (r.keyId !== d.assessorKeyId && P.revoked.has(r.keyId)) { ignored.push({ index: r.index, reason: 'declarer-revoked' }); continue; }
      slot.withdrawals.push(r);
    } else if (r.keyId !== d.assessorKeyId) {
      ignored.push({ index: r.index, reason: 'signer-mismatch' });
    } else slot.own.push(r);
  }
  const standings = P.assessors.map(keyId => {
    const slot = byAssessor.get(keyId), reasons = new Set(), rels = new Set();
    if (P.revoked.has(keyId)) reasons.add('key-revoked');
    // A withdrawal binds to the target envelope digest, must come from the target signer and must not predate the target or lie in the future.
    // An effective withdrawal of an own disclosure is itself a timeline event: it supersedes everything issued before it.
    const tombstones = [], withdrawnDecl = new Set();
    for (const w of slot.withdrawals) {
      const target = [...slot.own, ...slot.declarations].find(r => r.envelopeDigest === w.payload.refDigest && r.payload.id === w.payload.refId);
      if (!target) { ignored.push({ index: w.index, reason: 'withdrawal-target-unknown' }); continue; }
      if (target.keyId !== w.keyId) { ignored.push({ index: w.index, reason: 'signer-mismatch' }); continue; }
      const at = Date.parse(w.payload.issuedAt);
      if (at < Date.parse(target.payload.issuedAt) || at > t) { ignored.push({ index: w.index, reason: 'withdrawal-time-invalid' }); continue; }
      if (target.payload.kind === 'disclosure') tombstones.push(at); else withdrawnDecl.add(target.envelopeDigest);
    }
    const started = slot.own.filter(r => Date.parse(r.payload.issuedAt) <= t);
    const events = [...started.map(r => ({ at: Date.parse(r.payload.issuedAt), r })), ...tombstones.map(at => ({ at, r: null }))];
    if (slot.own.length === 0 && tombstones.length === 0) reasons.add('no-disclosure');
    else if (events.length === 0) reasons.add('disclosure-not-yet-valid');
    else {
      const latest = Math.max(...events.map(e => e.at));
      const tops = events.filter(e => e.at === latest);
      if (tops.some(e => e.r === null)) reasons.add('no-disclosure'); // withdrawal ties fail closed
      else {
        const live = tops.map(e => e.r).filter(r => Date.parse(r.payload.expiresAt) > t);
        if (live.length === 0) reasons.add('disclosure-expired'); // the latest statement governs even after it expires
        else {
          // two different same-time disclosures cannot be ordered: fail closed
          if (new Set(live.map(r => canonical(r.payload))).size > 1) reasons.add('conflicting-disclosures');
          for (const r of live) r.payload.relationships.forEach(x => rels.add(x));
          for (const r of live) if (r.payload.priorEngagementEndedAt !== null && t < Date.parse(r.payload.priorEngagementEndedAt) + P.cool * DAY) reasons.add('cooling-off-not-elapsed');
        }
      }
    }
    const disclosed = new Set(rels);
    for (const dec of slot.declarations) {
      if (withdrawnDecl.has(dec.envelopeDigest)) continue;
      if (!(Date.parse(dec.payload.issuedAt) <= t && Date.parse(dec.payload.expiresAt) > t)) continue;
      for (const x of dec.payload.relationships) { rels.add(x); if (!disclosed.has(x)) reasons.add('undisclosed-conflict-declared-by-other-party'); }
      if (dec.payload.priorEngagementEndedAt !== null && t < Date.parse(dec.payload.priorEngagementEndedAt) + P.cool * DAY) reasons.add('cooling-off-not-elapsed');
    }
    if ([...rels].some(x => P.blocking.has(x))) reasons.add('blocking-relationship');
    const sorted = STANDING_REASONS.filter(r => reasons.has(r));
    return { keyId, standing: sorted.length === 0 ? 'good' : 'not-standing', reasons: sorted, relationships: RELATIONSHIPS.filter(x => rels.has(x)) };
  });
  ignored.sort((a, b) => canonical(a) < canonical(b) ? -1 : 1);
  return { checkedAt: new Date(t).toISOString(), operatorDigest: P.operatorDigest, standings, ignored };
}
