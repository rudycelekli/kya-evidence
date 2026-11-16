import type { PassportRecord, PassportState } from './index.mjs';

export type RegisteredPassport = PassportState & { history: PassportRecord[] };

export interface PassportRegistry {
  append(record: PassportRecord): RegisteredPassport;
  read(id: string): RegisteredPassport | null;
  snapshotHistories(): PassportRecord[][];
  lookup(fingerprint: string): string[];
  close(): void;
}

export function openPassportRegistry(filename: string, registry: string): PassportRegistry;
