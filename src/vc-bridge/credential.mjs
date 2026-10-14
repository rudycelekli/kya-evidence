import { createPublicKey } from 'node:crypto';
import { insist, canonical } from '../shared/canonical.mjs';
import { verifyAssessment } from '../assessment/application/assess.mjs';
import { hash } from '../identity/domain/services/validation.mjs';
import { didKeyFromPublicKey } from './encoding.mjs';
import { fail, signCompact, privateKeyObject, VcBridgeError } from './jws.mjs';
import { openCredential, anchorRole, checkTime, VC_CONTEXT } from './open.mjs';
import { checkStatus } from './status.mjs';

// The inline context only gives KYA terms a vocabulary IRI. The IRI is a URN and is not dereferenceable;
// no JSON-LD processor has been run against these documents.
export const KYA_VOCAB = 'urn:kya:vocab:v1:';
export const CREDENTIAL_TYPE = 'KyaAssessmentCredential';
export const SUBJECT_TYPE = 'KyaAssessment';
export const NOT_ASSERTED = Object.freeze(['human identity', 'authorization grant', 'truthful execution']);
const MODES = ['none', 'mixed', 'runtime', 'fixture', 'declaration'];
const FIXTURE_LIMITATION = 'Includes synthetic fixture evidence; not a real product benchmark';
const OPTIONS = new Set(['issuerKey', 'validFrom', 'validUntil', 'status']);
const WARNING = 'A valid signature proves possession of the issuer key and integrity of these bytes. It does not prove truthful execution, human identity, authorization, or independent review. Issuer trust is relative to the relying party policy.';

const fixtureModes = m => m === 'fixture' || m === 'mixed';
const hasFixtureLimitation = l => Array.isArray(l) && l.includes(FIXTURE_LIMITATION);

function statusEntry(purpose, spec) {
  insist(spec && typeof spec.statusListCredential === 'string' && /^https?:\/\/\S+$/.test(spec.statusListCredential), 'status list credential must be a URL');
  const i = spec.statusListIndex;
  insist(Number.isSafeInteger(i) && i >= 0 || (typeof i === 'string' && /^(0|[1-9]\d{0,15})$/.test(i)), 'status list index must be a non-negative integer');
  return { type: 'BitstringStatusListEntry', statusPurpose: purpose, statusListIndex: String(i), statusListCredential: spec.statusListCredential };
}

/**
 * Export a kya.assessment/v1 report as a W3C VC 2.0 data model document secured as a compact JWS
 * (VC-JOSE-COSE, typ vc+jwt, alg EdDSA). The credential binds the agent by KYA subject digest. It makes no
 * identity claim and no authorization grant. evidenceMode is copied verbatim from the report.
 */
export function exportAssessmentCredential(assessment, options = {}) {
  for (const k of Object.keys(options)) insist(OPTIONS.has(k), `Unknown option ${k}`);
  const r = JSON.parse(JSON.stringify(assessment));
  verifyAssessment(r);
  insist(MODES.includes(r.evidenceMode), 'Unknown evidenceMode on report');
  insist(Array.isArray(r.limitations) && r.limitations.length > 0, 'Report has no limitations to carry');
  insist(fixtureModes(r.evidenceMode) === hasFixtureLimitation(r.limitations), 'Report evidenceMode and its fixture limitation disagree; refusing to export fixture evidence without the fixture limitation');
  const privateKey = privateKeyObject(options.issuerKey);
  const issuer = didKeyFromPublicKey(createPublicKey(privateKey));
  const validFrom = options.validFrom ?? r.assessedAt;
  const from = checkTime(validFrom, 'validFrom');
  insist(from >= Date.parse(r.assessedAt), 'validFrom must not predate the assessment');
  const cap = Date.parse(r.validUntil);
  const validUntil = options.validUntil ?? r.validUntil;
  const until = checkTime(validUntil, 'validUntil');
  insist(until <= cap, 'validUntil must not outlive the assessment validUntil');
  insist(until > from, 'Assessment already expired at validFrom');
  const entries = [];
  for (const purpose of ['revocation', 'suspension']) if (options.status?.[purpose]) entries.push(statusEntry(purpose, options.status[purpose]));
  const credential = buildCredentialBody(r, { issuer, validFrom, validUntil, entries });
  const { token } = signCompact(credential, privateKey);
  const evidenceIds = r.checks.map(c => c.evidenceId).filter(Boolean);
  return { jwt: token, credential, issuer, ledgerEntry: { reportDigest: r.reportDigest, subjectDigest: r.subjectDigest, evidenceIds } };
}

// The single construction of the credential body. Export signs it; report verification rebuilds it and compares.
function buildCredentialBody(r, { issuer, validFrom, validUntil, entries }) {
  return {
    '@context': [VC_CONTEXT, { '@vocab': KYA_VOCAB }],
    id: `urn:kya:assessment:sha256:${r.reportDigest}`,
    type: ['VerifiableCredential', CREDENTIAL_TYPE],
    issuer, validFrom, validUntil,
    credentialSubject: {
      id: `urn:kya:subject:sha256:${r.subjectDigest}`, type: SUBJECT_TYPE,
      subjectDigest: r.subjectDigest, scopeDigest: r.scopeDigest, scopeId: r.scopeId, profileId: r.profileId,
      profileDigest: r.profileDigest, policyDigest: r.policyDigest, evaluatorDigest: r.evaluatorDigest,
      reportDigest: r.reportDigest, assessedAt: r.assessedAt, selectedRunId: r.selectedRunId,
      decision: r.decision, score: r.score, coverage: r.coverage, independentCoverage: r.independentCoverage,
      evidenceMode: r.evidenceMode, blockerCodes: Object.hasOwn(r, 'blockerCodes') ? r.blockerCodes : null,
      limitations: r.limitations, notAsserted: [...NOT_ASSERTED]
    },
    evidence: [{ type: 'KyaInputDigests', subjectDigest: r.subjectDigest, profileDigest: r.profileDigest, policyDigest: r.policyDigest, evaluatorDigest: r.evaluatorDigest, evidenceBundleDigest: r.evidenceBundleDigest, acceptedEvidenceDigests: r.acceptedEvidenceDigests, reportDigest: r.reportDigest }],
    ...(entries.length ? { credentialStatus: entries } : {})
  };
}

function checkClaims(c) {
  const s = c.credentialSubject;
  const errs = [];
  if (!c.type.includes(CREDENTIAL_TYPE) || s.type !== SUBJECT_TYPE) errs.push(['PAYLOAD_INVALID', 'Not a KYA assessment credential']);
  for (const k of ['subjectDigest', 'profileDigest', 'policyDigest', 'evaluatorDigest', 'reportDigest']) { try { hash(s[k], k); } catch { errs.push(['PAYLOAD_INVALID', `Missing or malformed ${k}`]); } }
  if (!MODES.includes(s.evidenceMode)) errs.push(['PAYLOAD_INVALID', 'Unknown evidenceMode']);
  else if (fixtureModes(s.evidenceMode) !== hasFixtureLimitation(s.limitations)) errs.push(['EVIDENCE_MODE_LIMITATION_MISMATCH', 'evidenceMode and the fixture limitation disagree']);
  if (!Array.isArray(s.limitations) || !s.limitations.length) errs.push(['PAYLOAD_INVALID', 'limitations are required']);
  if (s.id !== `urn:kya:subject:sha256:${s.subjectDigest}`) errs.push(['PAYLOAD_INVALID', 'Subject id does not match subjectDigest']);
  const ev = c.evidence?.[0];
  if (!ev || ev.type !== 'KyaInputDigests' || ev.reportDigest !== s.reportDigest || ev.subjectDigest !== s.subjectDigest || ev.profileDigest !== s.profileDigest || ev.policyDigest !== s.policyDigest || ev.evaluatorDigest !== s.evaluatorDigest) errs.push(['EVIDENCE_REFERENCE_MISMATCH', 'Evidence input digests do not match the subject']);
  return errs;
}

// Rebuild the expected credential from the report with the exporter's own construction and compare the whole thing.
// Issuer, validFrom and validUntil come from the credential being checked (bounded against the report below). The status entries
// are issuer-supplied options and are not in the report: they are rebuilt through the same constructor so their shape is exact, but
// their content is not bound to the assessment. Returns names of the top-level members that differ.
const canonicalForm = v => v === undefined ? 'undefined' : canonical(v);
function subjectDiff(c, e) {
  const keys = new Set([...Object.keys(e.credentialSubject), ...Object.keys(c.credentialSubject ?? {})]);
  const names = [...keys].filter(k => canonicalForm(c.credentialSubject?.[k]) !== canonicalForm(e.credentialSubject[k]));
  return `credentialSubject (${names.join(', ')})`;
}
function compareToReport(c, r) {
  const diffs = [];
  let entries = [];
  try { entries = [].concat(c.credentialStatus ?? []).map(e => statusEntry(e?.statusPurpose, e)); } catch { diffs.push('credentialStatus'); }
  const expected = buildCredentialBody(r, { issuer: c.issuer, validFrom: c.validFrom, validUntil: c.validUntil, entries });
  for (const k of new Set([...Object.keys(expected), ...Object.keys(c)])) {
    if (canonicalForm(c[k]) !== canonicalForm(expected[k])) diffs.push(k === 'credentialSubject' ? subjectDiff(c, expected) : k);
  }
  if (!(Date.parse(c.validFrom) >= Date.parse(r.assessedAt))) diffs.push('validFrom (predates the assessment)');
  if (!(Date.parse(c.validUntil) <= Date.parse(r.validUntil))) diffs.push('validUntil (outlives the assessment)');
  return [...new Set(diffs)];
}

/**
 * Verify a vc+jwt assessment credential. Never throws for bad input: returns { valid, errors }.
 * authenticated is always false: a valid signature proves key possession, not truthful execution.
 * Without `report`, only internal consistency is checked: a holder of the issuer key can edit fields and re-sign, and the result
 * is still valid. With the original `report` (kya.assessment/v1) the credential is compared as a whole to a credential rebuilt from it
 * and any difference is REPORT_MISMATCH naming the top-level member. Network access never happens; supply status list credentials as { [url]: jwt }.
 */
export function verifyAssessmentCredential(token, { now = new Date().toISOString(), expectedIssuerKeys = [], policy, statusLists, requireStatusCheck = false, report } = {}) {
  const base = { authenticated: false, warning: WARNING };
  const errors = [];
  let opened;
  try { opened = openCredential(token, { now, expectedIssuerKeys }); }
  catch (e) { return { ...base, valid: false, errors: [{ code: e.code ?? 'MALFORMED', message: e.message }] }; }
  const { credential, issuer } = opened;
  for (const [code, message] of checkClaims(credential)) errors.push({ code, message });
  let reportChecked = false;
  if (report !== undefined) {
    try { verifyAssessment(report); } catch (e) { errors.push({ code: 'REPORT_INVALID', message: e.message }); report = undefined; }
    if (report !== undefined) {
      const diffs = compareToReport(credential, report);
      if (diffs.length) errors.push({ code: 'REPORT_MISMATCH', message: `Credential differs from the supplied report in: ${diffs.join(', ')}` });
      reportChecked = true;
    }
  }
  let issuerTrust = opened.issuerTrust, issuerRole = null;
  if (policy) {
    issuerRole = anchorRole(issuer, policy);
    if (issuerRole === null) errors.push({ code: 'ISSUER_NOT_TRUSTED', message: 'Issuer key is not a non-revoked trust anchor of the supplied policy' });
    else issuerTrust = 'anchored';
  }
  const entries = [].concat(credential.credentialStatus ?? []);
  const status = { checked: false, entries: [] };
  let all = entries.length > 0;
  for (const entry of entries) {
    const list = statusLists?.[entry?.statusListCredential];
    if (!list) { all = false; status.entries.push({ purpose: entry?.statusPurpose, checked: false }); continue; }
    try {
      const r = checkStatus(list, entry, { now, expectedIssuerKeys: [issuer] });
      status.entries.push({ purpose: r.purpose, checked: true, set: r.set });
      if (r.set) errors.push({ code: r.purpose === 'revocation' ? 'REVOKED' : 'SUSPENDED', message: `Status list bit is set for ${r.purpose}` });
    } catch (e) { all = false; status.entries.push({ purpose: entry?.statusPurpose, checked: false, error: e.code }); errors.push({ code: e instanceof VcBridgeError ? (e.code.startsWith('STATUS_') ? e.code : 'STATUS_VERIFICATION_ERROR') : 'STATUS_VERIFICATION_ERROR', message: e.message }); }
  }
  status.checked = all;
  if (requireStatusCheck && !all) errors.push({ code: 'STATUS_NOT_CHECKED', message: 'Status was required but not fully checked' });
  return { ...base, valid: errors.length === 0, errors, issuer, issuerTrust, issuerRole, credential, status, validAt: now, reportChecked };
}
