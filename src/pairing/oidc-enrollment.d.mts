import type { EnrollmentAssertion } from './mcp-gateway.mjs';

export interface EnrollmentIntent {
  issuer: string;
  audience: string;
  challenge: string;
  publicKey: string;
  previousKeyId: string | null;
}

export interface EnrollmentSession {
  idToken: string;
  challenge: string;
  publicKey: string;
  signature: string;
}

export function oidcEnrollmentNonce(intent: EnrollmentIntent): string;
export function oidcEnrollmentMessage(intent: EnrollmentIntent): Uint8Array;
export function createOidcEnrollmentAuthenticator(options: {
  issuer: string;
  audience: string;
  verifyIdToken(token: string): unknown | Promise<unknown>;
  resolvePrincipal(issuer: string, subject: string): string | Promise<string>;
  consumeNonce(challenge: string): boolean | Promise<boolean>;
  clock?(): string;
}): (input: EnrollmentSession, previousKeyId?: string | null) => Promise<EnrollmentAssertion>;
