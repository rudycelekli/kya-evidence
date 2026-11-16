import type { KeyObject } from 'node:crypto';
import type { PassportRecord } from './index.mjs';
import type { RegistryEndorsement, RegistryOriginTrust, SignedRegistryCheckpoint } from './registry-checkpoint.mjs';

export interface PassportWitness {
  witnessId: string;
  endorse(signed: SignedRegistryCheckpoint, histories: PassportRecord[][]): RegistryEndorsement;
  close(): void;
}

export function openPassportWitness(filename: string, options: RegistryOriginTrust & {
  witnessPrivateKey: KeyObject | Buffer | string;
  clock?: () => string;
}): PassportWitness;
