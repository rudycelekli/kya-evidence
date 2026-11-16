import type { RegistryLookupTrust, RegistryOriginTrust } from './registry-checkpoint.mjs';

export interface WitnessCheckpointPin {
  epoch: number;
  checkpointDigest: string;
}
export interface WitnessOperator {
  id: string;
  publicKey: string;
}
export interface WitnessRoster {
  schema: 'kya.witness-roster/v1';
  registry: string;
  originKeyId: string;
  generation: number;
  previous: string | null;
  operators: [WitnessOperator, WitnessOperator];
  handoff: WitnessCheckpointPin | null;
}
export interface SignedWitnessRoster {
  roster: WitnessRoster;
  signature: string;
  enrollments: { operatorId: string; signature: string }[];
}
export interface VerifiedWitnessRoster extends WitnessRoster {
  rosterDigest: string;
  retiredKeys: string[];
}

export function witnessRosterBytes(roster: WitnessRoster): Buffer;
export function witnessEnrollmentBytes(roster: WitnessRoster, operatorId: string): Buffer;
export function verifyWitnessRoster(input: SignedWitnessRoster, trust: RegistryOriginTrust & { authorityPublicKey: string },
  prior?: VerifiedWitnessRoster | null): VerifiedWitnessRoster;
export function witnessLookupTrust(roster: VerifiedWitnessRoster, originPublicKey: string, checkpointPin?: WitnessCheckpointPin): RegistryLookupTrust;
