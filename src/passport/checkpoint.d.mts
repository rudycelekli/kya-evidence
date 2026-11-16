import type { PassportRecord, PassportState } from './index.mjs';

export interface PassportCheckpoint {
  schema: 'kya.passport-checkpoint/v1';
  registry: string;
  passportId: string;
  head: string;
  sequence: number;
  issuedAt: string;
  expiresAt: string;
}

export interface PassportCheckpointBundle {
  checkpoint: PassportCheckpoint;
  signature: string;
  history: PassportRecord[];
}

export interface PassportCheckpointTrust {
  registry: string;
  publicKey: string;
}

export type VerifiedPassportCheckpoint = PassportCheckpointBundle & { passport: PassportState };

export function passportCheckpointBytes(checkpoint: PassportCheckpoint): Buffer;
export function verifyPassportCheckpoint(input: PassportCheckpointBundle, trust: PassportCheckpointTrust, now: string): VerifiedPassportCheckpoint;
