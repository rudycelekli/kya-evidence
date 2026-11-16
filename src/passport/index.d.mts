import type { KeyObject } from 'node:crypto';

export interface PassportIdentity {
  registry: string;
  agentId: string;
  principalId: string;
  controllerPublicKey: string;
}

export interface PassportEvent extends PassportIdentity {
  schema: 'kya.passport-event/v1';
  operation: 'register' | 'rotate' | 'revise' | 'revoke';
  passportId: string;
  previous: string | null;
  agentPublicKey: string | null;
  manifestDigest: string;
}

export interface PassportRecord {
  event: PassportEvent;
  controllerSignature: string;
  agentSignature: string | null;
}

export interface PassportState {
  passportId: string;
  agentId: string;
  principalId: string;
  head: string;
  status: 'active' | 'revoked';
  current: { fingerprint: string; manifestDigest: string } | null;
  fingerprints: string[];
}

export const maxPassportEvents: number;
export function passportId(identity: PassportIdentity): string;
export function passportPublicKey(privateKey: KeyObject | Buffer | string): string;
export function signPassportEvent(event: PassportEvent, privateKey: KeyObject | Buffer | string): string;
export function verifyPassport(history: PassportRecord[], expectedRegistry: string): PassportState;
