import { createPrivateKey, createPublicKey, sign, verify, KeyObject } from 'node:crypto';
import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { text, hash, timestamp, keyId, publicKeyObject, validatePublicPem } from '../identity/domain/services/validation.mjs';

// kya.conformance-report/v1: an implementation states, per requirement ID, what it ran and what happened.
// Declarations never count as pass. not-run stays in the denominator. Nothing here reads a clock.
export const REPORT_SCHEMA = 'kya.conformance-report/v1';
export const REPORT_DOMAIN = 'kya.conformance-report/v1\n';
export const RESULTS = Object.freeze(['pass', 'fail', 'not-applicable', 'not-run']);
export const EVIDENCE_CLASSES = Object.freeze(['executed-test', 'portable-vector', 'declaration']);
const ID = /^KYA-[A-Z]{3}-\d{3}$/;
const MAX = 4096;

function reqId(v, label) { insist(typeof v === 'string' && ID.test(v), `${label}: invalid requirement ID`); }
function idList(v, label) {
  insist(Array.isArray(v) && v.length <= MAX, `${label}: invalid list`); v.forEach(x => reqId(x, label));
  insist(new Set(v).size === v.length, `${label}: duplicate values`);
  insist(v.every((x, i) => i === 0 || v[i - 1] < x), `${label}: must be sorted`);
}
function registryIds(registry) {
  insist(registry && Array.isArray(registry.requirements) && registry.requirements.length > 0, 'Registry malformed');
  const ids = registry.requirements.map(r => r.id); ids.forEach(x => reqId(x, 'Registry'));
  insist(new Set(ids).size === ids.length, 'Registry has duplicate IDs');
  return new Set(ids);
}

function validateImplementation(v) {
  exactKeys(v, ['name', 'version', 'language', 'sourceDigest', 'declaredSubset'], 'Implementation');
  text(v.name, 'Implementation name', 128); text(v.version, 'Implementation version', 128); text(v.language, 'Implementation language', 64);
  if (v.sourceDigest !== null) hash(v.sourceDigest, 'Implementation source digest');
  if (v.declaredSubset !== null) idList(v.declaredSubset, 'Declared subset');
}

function validateEntry(e, sub) {
  exactKeys(e, ['id', 'result', 'evidence', 'executed'], 'Result');
  reqId(e.id, 'Result');
  insist(RESULTS.includes(e.result), `Result ${e.id}: unknown result`);
  insist(Array.isArray(e.executed) && e.executed.length <= 256, `Result ${e.id}: invalid executed list`);
  e.executed.forEach(x => text(x, `Result ${e.id} executed`, 512)); insist(new Set(e.executed).size === e.executed.length, `Result ${e.id}: duplicate executed IDs`);
  const inSubset = sub === null || sub.has(e.id);
  if (e.result === 'not-run' || e.result === 'not-applicable') {
    insist(e.evidence === null && e.executed.length === 0, `Result ${e.id}: ${e.result} carries no evidence or executed IDs`);
    if (e.result === 'not-applicable') insist(!inSubset, `Result ${e.id}: not-applicable requires a declared subset that excludes it`);
    else insist(inSubset, `Result ${e.id}: outside the declared subset it must be not-applicable`);
    return;
  }
  insist(EVIDENCE_CLASSES.includes(e.evidence), `Result ${e.id}: evidence class required`);
  if (e.result === 'pass') insist(e.evidence !== 'declaration', `Result ${e.id}: a declaration cannot support pass`);
  if (e.evidence !== 'declaration') insist(e.executed.length > 0, `Result ${e.id}: executed test or vector IDs required`);
}

export function summarize(results) {
  const n = r => results.filter(x => x.result === r).length;
  const total = results.length, notApplicable = n('not-applicable'), pass = n('pass'), applicable = total - notApplicable;
  return { total, pass, fail: n('fail'), notApplicable, notRun: n('not-run'), applicable, passPermille: applicable === 0 ? null : Math.floor(pass * 1000 / applicable), declarationEntries: results.filter(x => x.evidence === 'declaration').length };
}

export function validateReport(v, { registry } = {}) {
  v = JSON.parse(canonical(v));
  exactKeys(v, ['schema', 'implementation', 'registryDigest', 'runAt', 'results', 'summary'], 'Report');
  insist(v.schema === REPORT_SCHEMA, 'Unsupported report schema');
  validateImplementation(v.implementation); hash(v.registryDigest, 'Registry digest'); timestamp(v.runAt, 'Run time');
  insist(Array.isArray(v.results) && v.results.length > 0 && v.results.length <= MAX, 'Report results invalid');
  const sub = v.implementation.declaredSubset === null ? null : new Set(v.implementation.declaredSubset);
  v.results.forEach(e => validateEntry(e, sub));
  const ids = v.results.map(e => e.id);
  insist(new Set(ids).size === ids.length, 'Duplicate requirement ID in report');
  insist(ids.every((x, i) => i === 0 || ids[i - 1] < x), 'Results must be in ascending ID order');
  insist(canonical(v.summary) === canonical(summarize(v.results)), 'Summary does not match results');
  if (registry) {
    insist(v.registryDigest === digest(registry), 'Registry digest mismatch');
    const known = registryIds(registry);
    for (const id of ids) insist(known.has(id), `Unknown requirement ID ${id}`);
    for (const id of known) insist(new Set(ids).has(id), `Missing requirement ID ${id}`);
    for (const id of v.implementation.declaredSubset ?? []) insist(known.has(id), `Unknown requirement ID in declared subset ${id}`);
  }
  return v;
}

// results: map {id: {result,evidence,executed}} or an array of {id,...}; the array form lets a duplicate be detected.
export function buildReport({ registry, implementation, results, runAt, registryDigest }) {
  const known = registryIds(registry), actual = digest(registry);
  if (registryDigest !== undefined) insist(registryDigest === actual, 'Registry digest mismatch');
  insist(typeof runAt === 'string', 'runAt must be supplied explicitly');
  for (const id of implementation?.declaredSubset ?? []) insist(known.has(id), `Unknown requirement ID in declared subset ${id}`);
  const list = Array.isArray(results) ? results : Object.entries(results ?? {}).map(([id, r]) => ({ id, ...r }));
  const seen = new Set();
  for (const e of list) {
    insist(e && typeof e.id === 'string', 'Result without ID');
    insist(!seen.has(e.id), `Duplicate requirement ID ${e.id}`); seen.add(e.id);
    insist(known.has(e.id), `Unknown requirement ID ${e.id}`);
  }
  for (const id of known) insist(seen.has(id), `Missing requirement ID ${id}`);
  const entries = list.map(e => ({ id: e.id, result: e.result, evidence: e.evidence ?? null, executed: [...(e.executed ?? [])] })).sort((a, b) => a.id < b.id ? -1 : 1);
  const impl = { name: implementation?.name, version: implementation?.version, language: implementation?.language, sourceDigest: implementation?.sourceDigest ?? null, declaredSubset: implementation?.declaredSubset ? [...implementation.declaredSubset].sort() : null };
  const report = { schema: REPORT_SCHEMA, implementation: impl, registryDigest: actual, runAt, results: entries, summary: summarize(entries) };
  return validateReport(report, { registry });
}

export function signReport(report, privateKey) {
  const payload = validateReport(report);
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  insist(key.type === 'private' && key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 private key');
  const publicKey = createPublicKey(key).export({ format: 'pem', type: 'spki' }).toString();
  const signature = sign(null, Buffer.from(REPORT_DOMAIN + canonical(payload)), key).toString('base64url');
  return { payload, proof: { algorithm: 'Ed25519', keyId: keyId(publicKey), publicKey, signature } };
}

// Integrity and key possession only: never truthfulness of execution, independence or identity.
export function verifyReport(envelope, options = {}) {
  envelope = JSON.parse(canonical(envelope)); exactKeys(envelope, ['payload', 'proof'], 'Report envelope');
  const payload = validateReport(envelope.payload, options), p = envelope.proof;
  exactKeys(p, ['algorithm', 'keyId', 'publicKey', 'signature'], 'Report proof');
  insist(p.algorithm === 'Ed25519', 'Unsupported proof algorithm'); hash(p.keyId, 'Proof key'); validatePublicPem(p.publicKey);
  insist(keyId(p.publicKey) === p.keyId, 'Proof key fingerprint differs');
  insist(typeof p.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(p.signature), 'Invalid signature encoding');
  const bytes = Buffer.from(p.signature, 'base64url'); insist(bytes.length === 64 && bytes.toString('base64url') === p.signature, 'Noncanonical signature encoding');
  insist(verify(null, Buffer.from(REPORT_DOMAIN + canonical(payload)), publicKeyObject(p.publicKey), bytes), 'Report signature verification failed');
  return { payload, keyId: p.keyId, envelopeDigest: digest(envelope), authenticated: false, truthfulnessVerified: false };
}

// ---- TAP mapping (node --test --test-reporter=tap) ----
export function parseTap(output) {
  const out = [];
  for (const line of String(output).split('\n')) {
    const m = /^(not ok|ok) \d+ - (.*)$/.exec(line); if (!m) continue;
    let title = m[2], status = m[1] === 'ok' ? 'pass' : 'fail';
    const d = /^(.*?) # (SKIP|TODO)\b.*$/.exec(title);
    if (d) { title = d[1]; status = 'skip'; }
    out.push({ title: title.replace(/\\([\\#])/g, '$1'), status });
  }
  return out;
}

// A requirement passes only if every traced test passed and none was skipped. A failure anywhere is fail.
// Anything else (skipped, absent, ambiguous, file crashed without a verdict) is unknown: not-run.
export function mapTapToRequirements(registry, runs) {
  const out = {};
  for (const r of registry.requirements) {
    const executed = []; let failed = false, unknown = false;
    for (const t of r.tests) {
      const found = (runs[t.file]?.tests ?? []).filter(x => x.title === t.title);
      if (found.length !== 1) { unknown = true; continue; }
      if (found[0].status === 'fail') { failed = true; executed.push(`${t.file} :: ${t.title}`); }
      else if (found[0].status === 'skip') unknown = true;
      else executed.push(`${t.file} :: ${t.title}`);
    }
    if (failed) out[r.id] = { result: 'fail', evidence: 'executed-test', executed };
    else if (unknown) out[r.id] = { result: 'not-run', evidence: null, executed: [] };
    else out[r.id] = { result: 'pass', evidence: 'executed-test', executed };
  }
  return out;
}
