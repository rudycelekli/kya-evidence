import type { KeyObject } from 'node:crypto';
import type { RegistryLookupProof, RegistryMatch, RegistryQuery } from './registry-proof.mjs';

export interface RegistryCheckpoint {
  schema: 'kya.registry-checkpoint/v1';
  registry: string;
  epoch: number;
  previous: string | null;
  root: string;
  count: number;
  issuedAt: string;
  expiresAt: string;
}

export interface SignedRegistryCheckpoint {
  checkpoint: RegistryCheckpoint;
  signature: string;
}

export interface RegistryEndorsement {
  witnessId: string;
  checkpointDigest: string;
  signature: string;
}

export interface RegistryOriginTrust {
  registry: string;
  originPublicKey: string;
}

export interface RegistryLookupTrust extends RegistryOriginTrust {
  witnessPublicKeys: string[];
  minimumEpoch?: number;
  checkpointPin?: { epoch: number; checkpointDigest: string };
}

export function registryCheckpointBytes(checkpoint: RegistryCheckpoint): Buffer;
export function registryWitnessBytes(checkpoint: RegistryCheckpoint): Buffer;
export function signRegistryStatement(bytes: Uint8Array, privateKey: KeyObject | Buffer | string): string;
export function verifyRegistryCheckpoint(input: SignedRegistryCheckpoint, trust: RegistryOriginTrust, now: string):
  { checkpoint: RegistryCheckpoint; checkpointDigest: string };
export function verifyRegistrySignature(bytes: Uint8Array, signature: string, publicKey: string): void;
export function verifyRegistryEndorsements(signed: SignedRegistryCheckpoint, endorsements: RegistryEndorsement[],
  trust: RegistryLookupTrust, now: string): { checkpoint: RegistryCheckpoint; checkpointDigest: string };
export function verifyWitnessedLookup(query: RegistryQuery, proof: RegistryLookupProof, signed: SignedRegistryCheckpoint,
  endorsements: RegistryEndorsement[], trust: RegistryLookupTrust, now: string):
  { checkpointDigest: string; epoch: number; value: RegistryMatch | null };
