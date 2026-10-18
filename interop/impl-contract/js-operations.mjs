// KYA implementation contract version 2: the four pure operations beyond assess and currency, implemented with the JavaScript
// reference. Used by js-reference.mjs and by the vector generator. A refusal is a thrown Error; the adapter turns it into a non-zero exit.
// Not an independent implementation: it calls the reference library and exists to fix the result shapes (interop/impl-contract/README.md).
import { verify as edVerify } from 'node:crypto';
import { canonical, digest, hashBytes, parseJson } from '../../src/shared/canonical.mjs';
import { validateManifest, validateProfile, validatePolicy, validateEvidence, keyId, describeComparison, verifyEvidence, verifyIncident, validateIncident } from '../../src/index.mjs';
import { validatePublicPem, publicKeyObject } from '../../src/identity/domain/services/validation.mjs';

const RESULT = 'kya.impl-result/v1';
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
function exactInputs(inputs, names) {
  if (!isObject(inputs) || Object.keys(inputs).length !== names.length || !names.every(n => Object.hasOwn(inputs, n))) throw Error('operation inputs must have exactly: ' + names.join(', '));
}

function canonicalizeOp(inputs) {
  exactInputs(inputs, ['text']);
  if (typeof inputs.text !== 'string') throw Error('text must be a string');
  if (!inputs.text.isWellFormed()) throw Error('text holds an unpaired surrogate');
  const text = canonical(parseJson(inputs.text));
  return { schema: RESULT, operation: 'canonicalize', canonical: text, sha256: hashBytes(text) };
}

const SIGNING_PREFIX = { evidence: 'kya.evidence/v1\n', incident: 'kya.incident/v1\n' };
function digestOp(inputs) {
  exactInputs(inputs, ['artifact', 'value']);
  const { artifact, value } = inputs;
  let preimage;
  switch (artifact) {
    case 'manifest': validateManifest(value); preimage = canonical(value); break;
    case 'scope': validateManifest(value); preimage = canonical(value.scope); break;
    case 'profile': validateProfile(value); preimage = canonical(value); break;
    case 'policy': validatePolicy(value); preimage = canonical(value); break;
    case 'evidence-signing-input': validateEvidence(value); preimage = SIGNING_PREFIX.evidence + canonical(value); break;
    case 'incident-signing-input': validateIncident(value); preimage = SIGNING_PREFIX.incident + canonical(value); break;
    default: throw Error('unknown artifact');
  }
  return { schema: RESULT, operation: 'digest', artifact, preimage, digest: hashBytes(preimage) };
}

const HEX64 = /^[0-9a-f]{64}$/;
const KINDS = { evidence: { validate: validateEvidence, verify: verifyEvidence }, incident: { validate: validateIncident, verify: verifyIncident } };
const exactMembers = (v, names) => isObject(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
// Judge an envelope step by step in the order of docs/SPECIFICATION.md "Envelope verification"; returns a failure code or null.
function envelopeFailure(kind, env) {
  if (!exactMembers(env, ['payload', 'proof'])) return 'MALFORMED_ENVELOPE';
  try { KINDS[kind].validate(env.payload); } catch { return 'INVALID_PAYLOAD'; }
  const p = env.proof;
  if (!exactMembers(p, ['algorithm', 'keyId', 'publicKey', 'signature'])) return 'MALFORMED_PROOF';
  if (p.algorithm !== 'Ed25519') return 'UNSUPPORTED_ALGORITHM';
  if (typeof p.keyId !== 'string' || !HEX64.test(p.keyId)) return 'INVALID_KEY';
  try { validatePublicPem(p.publicKey); } catch { return 'INVALID_KEY'; }
  if (keyId(p.publicKey) !== p.keyId) return 'KEY_ID_MISMATCH';
  if (typeof p.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(p.signature)) return 'INVALID_SIGNATURE_ENCODING';
  const bytes = Buffer.from(p.signature, 'base64url');
  if (bytes.length !== 64 || bytes.toString('base64url') !== p.signature) return 'INVALID_SIGNATURE_ENCODING';
  if (!edVerify(null, Buffer.from(SIGNING_PREFIX[kind] + canonical(env.payload)), publicKeyObject(p.publicKey), bytes)) return 'SIGNATURE_INVALID';
  return null;
}
function verifyEnvelopeOp(inputs) {
  exactInputs(inputs, ['kind', 'envelope']);
  const { kind, envelope } = inputs;
  if (typeof kind !== 'string' || !Object.hasOwn(KINDS, kind)) throw Error('kind must be evidence or incident');
  const failure = envelopeFailure(kind, envelope);
  // The library verifier is the reference; the staged judgement above only names the failing step and must agree with it on validity.
  let libraryAccepts = true;
  try { KINDS[kind].verify(envelope); } catch { libraryAccepts = false; }
  if (libraryAccepts !== (failure === null)) throw Error('reference disagreement between the staged envelope check and the library verifier');
  if (failure) return { schema: RESULT, operation: 'verify-envelope', kind, valid: false, failure, keyId: null, envelopeDigest: null, signingInputSha256: null };
  return { schema: RESULT, operation: 'verify-envelope', kind, valid: true, failure: null, keyId: envelope.proof.keyId, envelopeDigest: digest(envelope), signingInputSha256: hashBytes(SIGNING_PREFIX[kind] + canonical(envelope.payload)) };
}

function compareOp(inputs) {
  exactInputs(inputs, ['left', 'right']);
  if (!isObject(inputs.left) || !isObject(inputs.right)) throw Error('left and right must be assessment objects');
  const { left, right, reason } = describeComparison(inputs.left, inputs.right);
  if (reason) return { schema: RESULT, operation: 'compare', comparable: false, reason, left: left.reportDigest, right: right.reportDigest, scoreDelta: null, decisionChanged: null, measurement: null };
  return { schema: RESULT, operation: 'compare', comparable: true, reason: null, left: left.reportDigest, right: right.reportDigest, scoreDelta: right.score.earned - left.score.earned, decisionChanged: left.decision !== right.decision, measurement: 'same-policy evidence comparison; not a causal improvement claim' };
}

export const V2_OPERATIONS = Object.freeze({ canonicalize: canonicalizeOp, digest: digestOp, 'verify-envelope': verifyEnvelopeOp, compare: compareOp });
