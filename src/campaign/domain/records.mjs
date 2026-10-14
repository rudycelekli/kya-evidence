import { createPrivateKey, createPublicKey, sign, verify, KeyObject } from 'node:crypto';
import { canonical, exactKeys, insist } from '../../shared/canonical.mjs';
import { identifier, hash, text, timestamp, keyId, publicKeyObject, validatePublicPem, SOURCES } from '../../identity/domain/services/validation.mjs';

export const PLAN_DOMAIN = 'kya.campaign-plan/v1\n';
export const LEDGER_DOMAIN = 'kya.campaign-ledger/v1\n';
export const MAX_PLANNED = 128;
export const MAX_ATTEMPTS = 256;
export const ENTRY_KINDS = Object.freeze(['planned', 'started', 'completed', 'abandoned', 'errored', 'amended']);
export const ERROR_CODES = Object.freeze(['TIMEOUT', 'ABORTED', 'OUTPUT_LIMIT', 'NONZERO_EXIT', 'SPAWN_FAILED', 'INPUT_LIMIT', 'ADAPTER_ERROR', 'BUNDLE_WRITE_FAILED']);
export const ABANDON_CODES = Object.freeze(['operator-abandon', 'campaign-closed', 'budget-exhausted', 'unsafe-to-run']);
const ENTRY_BASE = ['schema', 'campaignId', 'planDigest', 'seq', 'prevDigest', 'kind', 'attemptId', 'at'];
const ENTRY_EXTRA = { planned: [], started: [], completed: ['runId', 'evidenceBundleDigest'], errored: ['errorCode', 'evidenceBundleDigest'], abandoned: ['reasonCode'], amended: ['retryOf', 'subjectDigest', 'scenarioSetDigest', 'seed'] };

function seedOk(seed, label) { insist(seed === null || (Number.isSafeInteger(seed) && seed >= 0), `${label}: invalid seed`); }
function adapterDeclaration(a) {
  exactKeys(a, ['source', 'id', 'mode'], 'Plan adapter');
  insist(SOURCES.includes(a.source), 'Plan adapter: unknown source'); identifier(a.id, 'Plan adapter ID');
  if (a.mode !== null) identifier(a.mode, 'Plan adapter mode');
}
export function validatePlan(v) {
  v = JSON.parse(canonical(v));
  exactKeys(v, ['schema', 'campaignId', 'useCase', 'profileDigest', 'scenarioSetDigest', 'subjects', 'attempts', 'evaluatorDigest', 'policyDigest', 'adapter', 'createdAt'], 'Campaign plan');
  insist(v.schema === 'kya.campaign-plan/v1', 'Unsupported campaign plan schema');
  identifier(v.campaignId, 'Campaign ID'); text(v.useCase, 'Use case');
  for (const k of ['profileDigest', 'scenarioSetDigest', 'evaluatorDigest', 'policyDigest']) hash(v[k], k);
  adapterDeclaration(v.adapter); timestamp(v.createdAt, 'Plan creation time');
  insist(Array.isArray(v.attempts) && v.attempts.length >= 1 && v.attempts.length <= MAX_PLANNED, 'Plan attempts: expected 1 to 128 entries');
  const ids = new Set();
  for (const a of v.attempts) {
    exactKeys(a, ['attemptId', 'subjectDigest', 'scenarioSetDigest', 'seed'], 'Planned attempt');
    identifier(a.attemptId, 'Attempt ID'); hash(a.subjectDigest, 'Attempt subject'); hash(a.scenarioSetDigest, 'Attempt scenario set'); seedOk(a.seed, 'Attempt');
    insist(!ids.has(a.attemptId), 'Duplicate attempt ID'); ids.add(a.attemptId);
  }
  const subjects = [...new Set(v.attempts.map(a => a.subjectDigest))].sort();
  insist(Array.isArray(v.subjects) && v.subjects.length === subjects.length && v.subjects.every((s, i) => s === subjects[i]), 'Plan subjects must be the sorted unique attempt subjects');
  return v;
}

export function validateEntry(v) {
  v = JSON.parse(canonical(v));
  insist(v && typeof v === 'object' && ENTRY_KINDS.includes(v.kind), 'Unknown ledger entry kind');
  exactKeys(v, [...ENTRY_BASE, ...ENTRY_EXTRA[v.kind]], 'Ledger entry');
  insist(v.schema === 'kya.campaign-ledger-entry/v1', 'Unsupported ledger entry schema');
  identifier(v.campaignId, 'Campaign ID'); hash(v.planDigest, 'Plan digest'); hash(v.prevDigest, 'Previous digest');
  insist(Number.isSafeInteger(v.seq) && v.seq >= 0 && v.seq < 4096, 'Invalid sequence number');
  identifier(v.attemptId, 'Attempt ID'); timestamp(v.at, 'Entry time');
  if (v.kind === 'completed') { identifier(v.runId, 'Run ID'); hash(v.evidenceBundleDigest, 'Evidence bundle digest'); }
  if (v.kind === 'errored') {
    insist(ERROR_CODES.includes(v.errorCode), 'Invalid error code');
    if (v.evidenceBundleDigest !== null) hash(v.evidenceBundleDigest, 'Evidence bundle digest');
  }
  if (v.kind === 'abandoned') insist(ABANDON_CODES.includes(v.reasonCode), 'Invalid abandon reason code');
  if (v.kind === 'amended') { identifier(v.retryOf, 'Retried attempt'); hash(v.subjectDigest, 'Attempt subject'); hash(v.scenarioSetDigest, 'Attempt scenario set'); seedOk(v.seed, 'Amendment'); }
  return v;
}
/** Caller-supplied fields of an entry before the harness adds sequence, chain and plan binding. */
export function entryFields(kind) {
  insist(ENTRY_KINDS.includes(kind), 'Unknown ledger entry kind');
  return ['kind', 'attemptId', 'at', ...ENTRY_EXTRA[kind]];
}

export function privateKeyObject(privateKey) {
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  insist(key.type === 'private' && key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 private key');
  return key;
}
export function publicPem(key) { return createPublicKey(key).export({ format: 'pem', type: 'spki' }).toString(); }

export function signPlan(payload, key) {
  payload = validatePlan(payload);
  const publicKey = publicPem(key);
  return { payload, proof: { algorithm: 'Ed25519', keyId: keyId(publicKey), publicKey, signature: sign(null, Buffer.from(PLAN_DOMAIN + canonical(payload)), key).toString('base64url') } };
}
function checkSignature(signature, bytesToVerify, publicKey, label) {
  insist(typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), `${label}: invalid signature encoding`);
  const bytes = Buffer.from(signature, 'base64url');
  insist(bytes.length === 64 && bytes.toString('base64url') === signature, `${label}: noncanonical signature encoding`);
  insist(verify(null, bytesToVerify, publicKeyObject(publicKey), bytes), `${label}: signature verification failed`);
}
export function verifyPlan(envelope) {
  envelope = JSON.parse(canonical(envelope));
  exactKeys(envelope, ['payload', 'proof'], 'Plan envelope');
  const payload = validatePlan(envelope.payload), p = envelope.proof;
  exactKeys(p, ['algorithm', 'keyId', 'publicKey', 'signature'], 'Plan proof');
  insist(p.algorithm === 'Ed25519', 'Unsupported proof algorithm'); hash(p.keyId, 'Proof key'); validatePublicPem(p.publicKey);
  insist(keyId(p.publicKey) === p.keyId, 'Proof key fingerprint differs');
  checkSignature(p.signature, Buffer.from(PLAN_DOMAIN + canonical(payload)), p.publicKey, 'Plan');
  return { payload, keyId: p.keyId, publicKey: p.publicKey };
}

export function signEntry(payload, key) {
  payload = validateEntry(payload);
  return { payload, proof: { algorithm: 'Ed25519', keyId: keyId(publicPem(key)), signature: sign(null, Buffer.from(LEDGER_DOMAIN + canonical(payload)), key).toString('base64url') } };
}
/** Entries are verified against the plan-declared issuer key, so their proofs carry only its fingerprint. */
export function verifyEntry(envelope, issuer) {
  envelope = JSON.parse(canonical(envelope));
  exactKeys(envelope, ['payload', 'proof'], 'Entry envelope');
  const payload = validateEntry(envelope.payload), p = envelope.proof;
  exactKeys(p, ['algorithm', 'keyId', 'signature'], 'Entry proof');
  insist(p.algorithm === 'Ed25519', 'Unsupported proof algorithm'); hash(p.keyId, 'Proof key');
  insist(p.keyId === issuer.keyId, 'Entry is not signed by the campaign capture issuer');
  checkSignature(p.signature, Buffer.from(LEDGER_DOMAIN + canonical(payload)), issuer.publicKey, 'Entry');
  return payload;
}
