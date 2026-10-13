import { createPublicKey, KeyObject } from 'node:crypto';
import { canonical, exactKeys, hashBytes, insist } from '../../../shared/canonical.mjs';

export const DIMENSIONS = Object.freeze(['identity', 'authority', 'security', 'reliability', 'accountability', 'operations']);
export const SOURCES = Object.freeze(['runtime', 'fixture', 'declaration']);
export const HASH_PATTERN = /^[a-f0-9]{64}$/;

export function text(v, label, max = 512) {
  insist(typeof v === 'string' && v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v), `${label}: invalid text`);
}
export function identifier(v, label) {
  text(v, label, 128); insist(/^[A-Za-z0-9][A-Za-z0-9:._/-]*$/.test(v), `${label}: invalid identifier`);
}
export function hash(v, label) { insist(typeof v === 'string' && HASH_PATTERN.test(v), `${label}: invalid SHA-256`); }
export function timestamp(v, label = 'timestamp') {
  text(v, label, 24);
  insist(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v) && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString() === v, `${label}: invalid ISO UTC timestamp`);
  return Date.parse(v);
}
export function list(v, label, max = 256, validate = identifier) {
  insist(Array.isArray(v) && v.length <= max, `${label}: invalid list`);
  v.forEach(x => validate(x, label));
  insist(new Set(v).size === v.length, `${label}: duplicate values`);
}
export function publicKeyObject(key) {
  const obj = key instanceof KeyObject && key.type === 'public' ? key : createPublicKey(key);
  insist(obj.asymmetricKeyType === 'ed25519', 'Expected Ed25519 key');
  return obj;
}
export function validatePublicPem(v) {
  insist(typeof v === 'string' && v.length <= 2000 && /^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\r?\n?$/.test(v), 'Expected public SPKI PEM only');
  publicKeyObject(v);
}
export function keyId(key) {
  return hashBytes(publicKeyObject(key).export({ format: 'der', type: 'spki' }));
}

export function validateManifest(v) {
  canonical(v);
  exactKeys(v, ['schema','agent','principal','system','scope','issuedAt','expiresAt'], 'Manifest');
  insist(v.schema === 'kya.manifest/v1', 'Unsupported manifest schema');
  exactKeys(v.agent, ['id','name','version'], 'Agent'); identifier(v.agent.id, 'Agent ID'); text(v.agent.name,'Agent name'); text(v.agent.version,'Agent version',128);
  exactKeys(v.principal, ['id'], 'Principal'); identifier(v.principal.id,'Principal ID');
  exactKeys(v.system, ['harness','harnessVersion','model','artifactDigest','configDigest','tools'], 'System');
  text(v.system.harness,'Harness',128); text(v.system.harnessVersion,'Harness version',128); text(v.system.model,'Model',128);
  hash(v.system.artifactDigest,'Artifact digest'); hash(v.system.configDigest,'Config digest');
  exactKeys(v.scope, ['id','purpose','permissions','forbidden','approvalRequired'], 'Scope');
  identifier(v.scope.id,'Scope ID'); text(v.scope.purpose,'Purpose');
  for (const k of ['permissions','forbidden','approvalRequired']) list(v.scope[k],k);
  insist(v.scope.forbidden.every(x => !v.scope.permissions.includes(x)), 'Forbidden permission is also allowed');
  insist(v.scope.approvalRequired.every(x => v.scope.permissions.includes(x)), 'Approval permission is outside scope');
  insist(Array.isArray(v.system.tools) && v.system.tools.length <= 128, 'Invalid tools');
  const ids = new Set();
  for (const tool of v.system.tools) {
    exactKeys(tool,['id','version','permissions'],'Tool'); identifier(tool.id,'Tool ID'); text(tool.version,'Tool version',128); list(tool.permissions,'Tool permissions');
    insist(!ids.has(tool.id),'Duplicate tool ID'); ids.add(tool.id);
    insist(tool.permissions.every(x => v.scope.permissions.includes(x)), 'Tool permission is outside scope');
  }
  insist(timestamp(v.expiresAt,'Manifest expiry') > timestamp(v.issuedAt,'Manifest issuance'), 'Manifest expiry must follow issuance');
  return v;
}

export function validateProfile(v) {
  canonical(v); exactKeys(v,['schema','id','version','title','checks'],'Profile');
  insist(v.schema === 'kya.profile/v1','Unsupported profile schema'); identifier(v.id,'Profile ID'); text(v.version,'Profile version',64); text(v.title,'Profile title');
  insist(Array.isArray(v.checks) && v.checks.length > 0 && v.checks.length <= 256,'Invalid profile checks');
  const ids = new Set();
  for (const c of v.checks) {
    exactKeys(c,['id','dimension','title','weight','critical'],'Check'); identifier(c.id,'Check ID'); text(c.title,'Check title');
    insist(DIMENSIONS.includes(c.dimension),'Unknown dimension'); insist(Number.isSafeInteger(c.weight) && c.weight > 0 && c.weight <= 100_000,'Invalid weight');
    insist(typeof c.critical === 'boolean','Critical must be boolean'); insist(!ids.has(c.id),'Duplicate profile check'); ids.add(c.id);
  }
  return v;
}

export function validatePolicy(v) {
  canonical(v);
  exactKeys(v,['schema','id','profileDigest','scopeId','minCoverage','minScore','minIndependentCoverage','allowedSources','maxEvidenceAgeSeconds','trustedKeys','revokedKeyIds','revokedEvidenceIds','revokedSubjectDigests'],'Policy');
  insist(v.schema === 'kya.policy/v1','Unsupported policy schema'); identifier(v.id,'Policy ID'); hash(v.profileDigest,'Policy profile'); identifier(v.scopeId,'Policy scope');
  for (const k of ['minCoverage','minIndependentCoverage']) insist(typeof v[k] === 'number' && Number.isFinite(v[k]) && v[k] >= 0 && v[k] <= 1,`Invalid ${k}`);
  insist(Number.isInteger(v.minScore) && v.minScore >= 0 && v.minScore <= 1000,'Invalid minScore');
  insist(Number.isSafeInteger(v.maxEvidenceAgeSeconds) && v.maxEvidenceAgeSeconds > 0 && v.maxEvidenceAgeSeconds <= 31_536_000,'Invalid evidence age');
  list(v.allowedSources,'Allowed sources',3,(x)=>insist(SOURCES.includes(x),'Unknown evidence source'));
  list(v.revokedKeyIds,'Revoked keys',4096,hash); list(v.revokedSubjectDigests,'Revoked subjects',4096,hash); list(v.revokedEvidenceIds,'Revoked evidence',4096);
  insist(Array.isArray(v.trustedKeys) && v.trustedKeys.length <= 256,'Invalid trust anchors');
  const ids = new Set();
  for (const k of v.trustedKeys) {
    exactKeys(k,['id','publicKey','role'],'Trust anchor'); hash(k.id,'Key ID'); validatePublicPem(k.publicKey);
    insist(keyId(k.publicKey) === k.id,'Trust anchor fingerprint differs'); insist(['self','independent'].includes(k.role),'Unknown issuer role'); insist(!ids.has(k.id),'Duplicate trust anchor'); ids.add(k.id);
  }
  return v;
}

export function validateEvidence(v) {
  canonical(v); exactKeys(v,['schema','id','subjectDigest','scopeId','profileDigest','evaluatorDigest','runId','checkId','outcome','observedAt','expiresAt','artifactDigest','source'],'Evidence');
  insist(v.schema === 'kya.evidence/v1','Unsupported evidence schema');
  for (const k of ['id','scopeId','runId','checkId']) identifier(v[k],k);
  for (const k of ['subjectDigest','profileDigest','evaluatorDigest','artifactDigest']) hash(v[k],k);
  insist(['pass','fail','abstain','error'].includes(v.outcome),'Invalid outcome'); insist(SOURCES.includes(v.source),'Unknown evidence source');
  insist(timestamp(v.expiresAt,'Evidence expiry') > timestamp(v.observedAt,'Observation'), 'Evidence expiry must follow observation');
  return v;
}
