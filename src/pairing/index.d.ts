import type { KeyObject } from 'node:crypto';
import type { Manifest } from '../index.js';

export interface PairingGrant {
  schema: 'kya.pairing-grant/v1';
  principalId: string;
  agentKeyId: string;
  manifestDigest: string;
  audience: string;
  permission: string;
  issuedAt: string;
  expiresAt: string;
}

export interface PairedAction {
  schema: 'kya.paired-action/v1';
  grantDigest: string;
  challenge: string;
  requestDigest: string;
}

export interface PairingEnvelope<T> {
  payload: T;
  publicKey: string;
  signature: string;
}

export interface PairedActionProof {
  grant: PairingEnvelope<PairingGrant>;
  action: PairingEnvelope<PairedAction>;
}

export interface PairingContext {
  manifest: Manifest;
  principalId: string;
  principalKeyId: string;
  audience: string;
  permission: string;
  challenge: string;
  requestDigest: string;
  now: string;
  revokedKeyIds: string[];
  revokedGrantDigests: string[];
}

export interface VerifiedPairing {
  principalId: string;
  principalKeyId: string;
  agentId: string;
  agentKeyId: string;
  manifestDigest: string;
  grantDigest: string;
  actionDigest: string;
}

export function signPairingGrant(payload: PairingGrant, privateKey: KeyObject | string): PairingEnvelope<PairingGrant>;
export function signPairedAction(payload: PairedAction, privateKey: KeyObject | string): PairingEnvelope<PairedAction>;
export function verifyPairedAction(proof: PairedActionProof, context: PairingContext): VerifiedPairing;
