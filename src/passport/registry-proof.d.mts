import type { PassportRecord } from './index.mjs';

export interface RegistryQuery {
  kind: 'passport' | 'fingerprint';
  digest: string;
}
export interface PassportHead {
  head: string;
  sequence: number;
}
export type RegistryMatch = PassportHead | string[];
export interface RegistryMember {
  index: number;
  leaf: { key: string; value: RegistryMatch };
  siblings: string[];
}
export type RegistryLookupProof =
  | { member: RegistryMember }
  | { left: RegistryMember | null; right: RegistryMember | null };
export interface RegistryIndex {
  root: string;
  count: number;
  passports: Map<string, PassportHead & { id: string; history: PassportRecord[] }>;
  prove(query: RegistryQuery): RegistryLookupProof;
}
export function buildPassportRegistryIndex(histories: PassportRecord[][], registry: string): RegistryIndex;
export function verifyPassportRegistryLookup(query: RegistryQuery, proof: RegistryLookupProof, root: string, count: number): RegistryMatch | null;
