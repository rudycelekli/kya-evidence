import { createPrivateKey, createPublicKey, sign, verify, KeyObject } from 'node:crypto';
import { canonical, digest, exactKeys, insist } from '../../../shared/canonical.mjs';
import { identifier, hash, timestamp, keyId, publicKeyObject, validatePublicPem } from '../../../identity/domain/services/validation.mjs';

export const INCIDENT_KINDS = Object.freeze(['report','resolution','appeal']);
export const INCIDENT_SEVERITIES = Object.freeze(['low','medium','high','critical']);

// Incident records carry no narrative: private details stay outside, referenced by digest only.
export function validateIncident(v) {
  v=JSON.parse(canonical(v));
  exactKeys(v,['schema','id','subjectDigest','kind','severity','refId','reportedAt','detailsDigest'],'Incident');
  insist(v.schema === 'kya.incident/v1','Unsupported incident schema'); identifier(v.id,'Incident ID'); hash(v.subjectDigest,'Incident subject'); hash(v.detailsDigest,'Incident details digest');
  insist(INCIDENT_KINDS.includes(v.kind),'Unknown incident kind'); insist(INCIDENT_SEVERITIES.includes(v.severity),'Unknown incident severity');
  if (v.kind === 'report') insist(v.refId === null,'A report cannot reference another incident'); else { identifier(v.refId,'Referenced incident'); insist(v.refId !== v.id,'An incident cannot reference itself'); }
  timestamp(v.reportedAt,'Incident time');
  return v;
}

export function signIncident(payload, privateKey) {
  payload=validateIncident(payload);
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  insist(key.type === 'private' && key.asymmetricKeyType === 'ed25519','Expected Ed25519 private key');
  const publicKey = createPublicKey(key).export({ format:'pem', type:'spki' }).toString();
  const signature = sign(null, Buffer.from('kya.incident/v1\n' + canonical(payload)), key).toString('base64url');
  return { payload, proof:{algorithm:'Ed25519',keyId:keyId(publicKey),publicKey,signature} };
}

export function verifyIncident(envelope) {
  envelope=JSON.parse(canonical(envelope)); exactKeys(envelope,['payload','proof'],'Incident envelope'); const payload=validateIncident(envelope.payload);
  const p=envelope.proof; exactKeys(p,['algorithm','keyId','publicKey','signature'],'Incident proof');
  insist(p.algorithm === 'Ed25519','Unsupported proof algorithm'); hash(p.keyId,'Proof key'); validatePublicPem(p.publicKey);
  insist(keyId(p.publicKey) === p.keyId,'Proof key fingerprint differs');
  insist(typeof p.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(p.signature),'Invalid signature encoding');
  const bytes = Buffer.from(p.signature,'base64url'); insist(bytes.length === 64 && bytes.toString('base64url') === p.signature,'Noncanonical signature encoding');
  insist(verify(null,Buffer.from('kya.incident/v1\n' + canonical(payload)),publicKeyObject(p.publicKey),bytes),'Incident signature verification failed');
  return {payload,keyId:p.keyId,envelopeDigest:digest(envelope)};
}
