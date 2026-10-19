// Contract version 2 operations (canonicalize, digest, verify-envelope, compare) of the second implementation.
// Written from docs/SPECIFICATION.md and interop/impl-contract/README.md. Team-built, NOT independent.
import { createPublicKey, verify as edVerify } from 'node:crypto';
import {
  Refusal, canonical, sha256hex, digest, parseStrict, isObj, HEX64, isId, exactKeys,
  validManifest, validProfile, validPolicy, evidencePayloadShape, strictPublicKey
} from './kya2.mjs';
import { incidentPayloadShape } from './currency.mjs';
import { verifyCredentialOp } from './credential.mjs';
import { verifyScoreCardOp, compareScoreCardsOp } from './scorecard.mjs';

const refuse = m => { throw new Refusal(m); };
const RESULT = 'kya.impl-result/v1';

function inputsExactly(inputs, members) {
  if (!exactKeys(inputs, members)) refuse('inputs must hold exactly ' + members.join(', '));
}

// ---------------------------------------------------------------- canonicalize

export function canonicalizeOp(inputs) {
  inputsExactly(inputs, ['text']);
  if (typeof inputs.text !== 'string') refuse('text must be a string');
  const value = parseStrict(inputs.text);
  const text = canonical(value);
  if (Buffer.byteLength(text, 'utf8') > 1048576) refuse('canonical form too long');
  return { schema: RESULT, operation: 'canonicalize', canonical: text, sha256: sha256hex(text) };
}

// ---------------------------------------------------------------- digest

const ARTIFACTS = ['manifest', 'scope', 'profile', 'policy', 'evidence-signing-input', 'incident-signing-input'];
export function digestOp(inputs) {
  inputsExactly(inputs, ['artifact', 'value']);
  const { artifact, value } = inputs;
  if (typeof artifact !== 'string' || !ARTIFACTS.includes(artifact)) refuse('unknown artifact');
  let preimage;
  switch (artifact) {
    case 'manifest': validManifest(value); preimage = canonical(value); break;
    case 'scope': validManifest(value); preimage = canonical(value.scope); break;
    case 'profile': validProfile(value); preimage = canonical(value); break;
    case 'policy': validPolicy(value, null, null, null); preimage = canonical(value); break;
    case 'evidence-signing-input':
      if (evidencePayloadShape(value)) refuse('invalid evidence payload');
      preimage = 'kya.evidence/v1\n' + canonical(value); break;
    case 'incident-signing-input':
      if (incidentPayloadShape(value)) refuse('invalid incident payload');
      preimage = 'kya.incident/v1\n' + canonical(value); break;
  }
  return { schema: RESULT, operation: 'digest', artifact, preimage, digest: sha256hex(preimage) };
}

// ---------------------------------------------------------------- verify-envelope

// Group order of the Ed25519 base point (RFC 8032): the scalar half S of a signature must be below it.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const b64uExact = s => typeof s === 'string' && s.length === 86 && /^[A-Za-z0-9_-]+$/.test(s) && Buffer.from(s, 'base64url').length === 64 && Buffer.from(s, 'base64url').toString('base64url') === s;

function envelopeFailure(kind, env) {
  const domain = kind === 'evidence' ? 'kya.evidence/v1\n' : 'kya.incident/v1\n';
  if (!exactKeys(env, ['payload', 'proof'])) return { code: 'MALFORMED_ENVELOPE' };
  const bad = kind === 'evidence' ? evidencePayloadShape(env.payload) : incidentPayloadShape(env.payload);
  if (bad) return { code: 'INVALID_PAYLOAD' };
  const proof = env.proof;
  if (!exactKeys(proof, ['algorithm', 'keyId', 'publicKey', 'signature'])) return { code: 'MALFORMED_PROOF' };
  if (proof.algorithm !== 'Ed25519') return { code: 'UNSUPPORTED_ALGORITHM' };
  if (typeof proof.keyId !== 'string' || !HEX64.test(proof.keyId)) return { code: 'INVALID_KEY' };
  const strict = strictPublicKey(proof.publicKey);
  if (strict.problem) return { code: 'INVALID_KEY' };
  if (sha256hex(strict.der) !== proof.keyId) return { code: 'KEY_ID_MISMATCH' };
  if (!b64uExact(proof.signature)) return { code: 'INVALID_SIGNATURE_ENCODING' };
  const sig = Buffer.from(proof.signature, 'base64url');
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
  if (s >= L) return { code: 'SIGNATURE_INVALID' };
  const signingInput = domain + canonical(env.payload);
  let ok = false;
  try { ok = edVerify(null, Buffer.from(signingInput, 'utf8'), createPublicKey(proof.publicKey), sig); } catch { ok = false; }
  if (!ok) return { code: 'SIGNATURE_INVALID' };
  return { code: null, keyId: proof.keyId, signingInput };
}

export function verifyEnvelopeOp(inputs) {
  inputsExactly(inputs, ['kind', 'envelope']);
  const { kind, envelope } = inputs;
  if (kind !== 'evidence' && kind !== 'incident') refuse('unknown kind');
  const r = envelopeFailure(kind, envelope);
  if (r.code) return { schema: RESULT, operation: 'verify-envelope', kind, valid: false, failure: r.code, keyId: null, envelopeDigest: null, signingInputSha256: null };
  return { schema: RESULT, operation: 'verify-envelope', kind, valid: true, failure: null, keyId: r.keyId, envelopeDigest: digest(envelope), signingInputSha256: sha256hex(r.signingInput) };
}

// ---------------------------------------------------------------- compare

const DECISIONS = ['qualified', 'insufficient-evidence', 'blocked', 'expired', 'revoked'];
const MODES = ['none', 'runtime', 'fixture', 'mixed'];
const BLOCKER_CODES = ['SUBJECT_REVOKED', 'SUBJECT_EXPIRED', 'SUBJECT_NOT_YET_VALID', 'CRITICAL_CHECK_FAILED', 'CRITICAL_CHECK_UNPROVEN', 'COVERAGE_BELOW_POLICY', 'INDEPENDENT_COVERAGE_BELOW_POLICY', 'SCORE_BELOW_POLICY', 'AMBIGUOUS_RUNS', 'RUN_CONFLICT', 'RUN_INVALIDATED', 'MIXED_RUN_ISSUERS', 'REPEATED_RUN_CHECKS', 'NO_SCORED_OBSERVATIONS', 'NO_OBSERVED_CHECKS', 'PRINCIPAL_UNBOUND', 'MANDATORY_MINIMUM_NOT_MET', 'MANDATORY_MINIMUM_UNPROVEN'];
const SUBJECT_CODES = ['SUBJECT_REVOKED', 'SUBJECT_EXPIRED', 'SUBJECT_NOT_YET_VALID'];

export function checkReport(r) {
  if (!isObj(r) || r.schema !== 'kya.assessment/v1') refuse('report is not a kya.assessment/v1');
  if (typeof r.reportDigest !== 'string' || !HEX64.test(r.reportDigest)) refuse('report checksum member');
  const { reportDigest, ...rest } = r;
  if (digest(rest) !== reportDigest) refuse('report checksum does not match');
  for (const k of ['scopeDigest', 'profileDigest', 'evaluatorDigest', 'policyDigest']) if (typeof r[k] !== 'string' || !HEX64.test(r[k])) refuse('report ' + k);
  if (!isId(r.scopeId)) refuse('report scopeId');
  if (!MODES.includes(r.evidenceMode)) refuse('report evidenceMode');
  if (!DECISIONS.includes(r.decision)) refuse('report decision');
  if (!isObj(r.score) || !Number.isInteger(r.score.earned)) refuse('report score.earned');
  if (!Array.isArray(r.checks)) refuse('report checks');
  for (const c of r.checks) {
    if (!isObj(c) || !isId(c.id) || !Number.isInteger(c.weight) || typeof c.status !== 'string') refuse('report check entry');
  }
  checkBlockerCodes(r);
}

// the blockerCodes rules alone (also used by verify-credential, which applies no other shape check)
export function checkBlockerCodes(r) {
  if (r.blockerCodes !== undefined) {
    const c = r.blockerCodes;
    if (!Array.isArray(r.blockers) || !Array.isArray(c) || c.length !== r.blockers.length || c.some(x => !BLOCKER_CODES.includes(x))) refuse('report blockerCodes');
    if (r.decision === 'qualified' && c.length) refuse('qualified report carries blocker codes');
    if (!c.some(x => SUBJECT_CODES.includes(x))) {
      if (!Array.isArray(r.checks)) refuse('report checks');
      const failed = r.checks.filter(x => x.critical === true && x.status === 'fail').length;
      if (c.filter(x => x === 'CRITICAL_CHECK_FAILED').length !== failed) refuse('blocker codes contradict the critical failures');
    }
  }
}

export function compareOp(inputs) {
  inputsExactly(inputs, ['left', 'right']);
  const { left, right } = inputs;
  checkReport(left);
  checkReport(right);
  const base = { schema: RESULT, operation: 'compare' };
  const reason = (() => {
    if (left.scopeId !== right.scopeId) return 'SCOPE_ID_DIFFERS';
    if (left.scopeDigest !== right.scopeDigest) return 'SCOPE_DIGEST_DIFFERS';
    if (left.profileDigest !== right.profileDigest) return 'PROFILE_DIFFERS';
    if (left.evaluatorDigest !== right.evaluatorDigest) return 'EVALUATOR_DIFFERS';
    if (left.policyDigest !== right.policyDigest) return 'POLICY_DIFFERS';
    if (left.evidenceMode !== right.evidenceMode) return 'EVIDENCE_MODE_DIFFERS';
    if (left.checks.length !== right.checks.length || left.checks.some((c, i) => c.id !== right.checks[i].id || c.weight !== right.checks[i].weight)) return 'CHECK_POPULATION_DIFFERS';
    if ([...left.checks, ...right.checks].some(c => c.status !== 'pass' && c.status !== 'fail')) return 'CHECKS_INCOMPLETE';
    return null;
  })();
  if (reason) return { ...base, comparable: false, reason, left: left.reportDigest, right: right.reportDigest, scoreDelta: null, decisionChanged: null, measurement: null };
  return {
    ...base, comparable: true, reason: null, left: left.reportDigest, right: right.reportDigest,
    scoreDelta: right.score.earned - left.score.earned, decisionChanged: left.decision !== right.decision,
    measurement: 'same-policy evidence comparison; not a causal improvement claim'
  };
}

export const OPERATIONS = {
  canonicalize: canonicalizeOp, digest: digestOp, 'verify-envelope': verifyEnvelopeOp, compare: compareOp,
  'verify-credential': verifyCredentialOp, 'verify-score-card': verifyScoreCardOp, 'compare-score-cards': compareScoreCardsOp
};
