import type { PassportState } from './index.mjs';
import type { PassportCheckpointBundle, PassportCheckpointTrust, VerifiedPassportCheckpoint } from './checkpoint.mjs';

export interface PassportMirror {
  importCheckpoint(input: PassportCheckpointBundle): PassportState;
  read(id: string): VerifiedPassportCheckpoint | null;
  close(): void;
}

export function openPassportMirror(filename: string, options: PassportCheckpointTrust & { clock?: () => string }): PassportMirror;
