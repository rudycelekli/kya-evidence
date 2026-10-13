import { createPrivateKey, createPublicKey, sign, verify, KeyObject } from 'node:crypto';
import { canonical, digest, exactKeys, hashBytes, insist } from '../../../shared/canonical.mjs';
import { validateEvidence, keyId, publicKeyObject, validatePublicPem, hash } from '../../../identity/domain/services/validation.mjs';

export function signEvidence(payload, privateKey) {
  validateEvidence(payload);
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  insist(key.type === 'private' && key.asymmetricKeyType === 'ed25519','Expected Ed25519 private key');
  const publicKey = createPublicKey(key).export({ format:'pem', type:'spki' }).toString();
  // Domain separation prevents interpreting signatures as another protocol's signed object.
  const signature = sign(null, Buffer.from('kya.evidence/v1\n' + canonical(payload)), key).toString('base64url');
  return { payload: JSON.parse(canonical(payload)), proof:{algorithm:'Ed25519',keyId:keyId(publicKey),publicKey,signature} };
}

export function verifyEvidence(envelope) {
  canonical(envelope); exactKeys(envelope,['payload','proof'],'Envelope'); validateEvidence(envelope.payload);
  exactKeys(envelope.proof,['algorithm','keyId','publicKey','signature'],'Proof');
  const p = envelope.proof; insist(p.algorithm === 'Ed25519','Unsupported proof algorithm'); hash(p.keyId,'Proof key'); validatePublicPem(p.publicKey);
  insist(keyId(p.publicKey) === p.keyId,'Proof key fingerprint differs');
  insist(typeof p.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(p.signature),'Invalid signature encoding');
  const bytes = Buffer.from(p.signature,'base64url');
  insist(bytes.length === 64 && bytes.toString('base64url') === p.signature,'Noncanonical signature encoding');
  insist(verify(null,Buffer.from('kya.evidence/v1\n' + canonical(envelope.payload)),publicKeyObject(p.publicKey),bytes),'Evidence signature verification failed');
  return {payload:envelope.payload,keyId:p.keyId,envelopeDigest:digest(envelope)};
}

export function verifyArtifact(payload, bytes) {
  validateEvidence(payload);
  // Artifact contents are private by default; verification is explicit and never fetches a URL.
  const expected = payload.artifactDigest;
  return hashBytes(bytes) === expected;
}
