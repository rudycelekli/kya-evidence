import { insist, digest } from '../shared/canonical.mjs';
import { gate, checkOptions, isQualified, blockerCodesOf, LIMITS, NOT_ASSERTED } from './gate.mjs';

// Trust domain: dot-separated labels, each starting and ending with a lowercase letter or digit (dash and underscore inside), at most 63 characters.
const SPIFFE_ID = /^spiffe:\/\/((?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?)*)(\/[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)?$/;
export function checkSpiffeId(id) {
  insist(typeof id === 'string' && id.length <= 2048, 'SPIFFE ID must be a string of at most 2048 characters');
  const m = SPIFFE_ID.exec(id);
  insist(m && m[1].length <= 255, 'SPIFFE ID must be spiffe://trust-domain/path with a DNS-label trust domain and no query, fragment or userinfo');
  for (const seg of (m[2] ?? '').split('/').slice(1)) insist(seg !== '.' && seg !== '..', 'SPIFFE ID path must not contain dot segments');
  return id;
}

export function buildKyaClaim(r, c) {
  return {
    assessment_digest: r.reportDigest, subject_digest: r.subjectDigest, decision: r.decision, qualified: isQualified(r, c),
    evidence_mode: r.evidenceMode, blocker_codes: blockerCodesOf(r), valid_until: r.validUntil,
    valid_until_epoch: Math.floor(Date.parse(r.validUntil) / 1000),
    currency: { checked: c.checked, current: c.current, checked_at: c.checkedAt, trigger_codes: [...c.triggerCodes], digest: c.digest, overrides: [...c.overrides] },
    authorization_granted: false, not_asserted: [...NOT_ASSERTED]
  };
}
export const buildOAuthClaims = (r, c) => ({ kya: buildKyaClaim(r, c), kya_limits: [...LIMITS] });
export const SVID_ASSOCIATION_NOTE = 'Association asserted by whoever built this record. Nothing here proves that the SVID holder runs the manifest named by subject_digest; the relying party must establish that link out of band.';
export function buildSpiffeBinding(r, c, spiffeId) {
  const triple = { spiffeId, assessmentDigest: r.reportDigest, subjectDigest: r.subjectDigest };
  return { schema: 'kya.spiffe-binding/v1', spiffeId, bindingDigest: digest(triple), claims: buildKyaClaim(r, c), association: 'asserted-not-proven', note: SVID_ASSOCIATION_NOTE, limits: [...LIMITS] };
}

/**
 * OAuth 2.0 claims map (the shape of a JWT claims set or an RFC 7662 introspection member) carrying a KYA assessment under one
 * private claim named kya. No token is built or signed, and no iss, sub, aud, iat or exp is set: those belong to the token issuer,
 * which should keep exp at or below kya.valid_until_epoch. Claim names are private-use names, not registered with IANA.
 */
export function exportOAuthClaims(assessment, options = {}) {
  options = checkOptions(options);
  const { report, currency } = gate(assessment, options);
  return buildOAuthClaims(report, currency);
}

/**
 * SPIFFE binding record: associates one SPIFFE ID with an assessment digest and decision. Carry it as workload registration metadata
 * or an SVID-adjacent claim set. It is not embedded in an SVID and creates no trust relationship. bindingDigest is the SHA-256 of
 * the (spiffeId, assessment digest, subject digest) triple so a changed association is detectable.
 */
export function exportSpiffeBinding(assessment, spiffeId, options = {}) {
  options = checkOptions(options);
  checkSpiffeId(spiffeId);
  const { report, currency } = gate(assessment, options);
  return buildSpiffeBinding(report, currency, spiffeId);
}
