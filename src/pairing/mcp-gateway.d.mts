import type { Manifest } from '../index.js';
import type { PairedActionProof, VerifiedPairing } from './index.js';

export interface McpCall {
  server: string;
  tool: string;
  arguments: Record<string, unknown>;
}

export interface McpRoute {
  manifest: Manifest;
  audience: string;
  permission: string;
  revision: string;
  revokedKeyIds: string[];
  revokedGrantDigests: string[];
}

export interface EnrollmentAssertion {
  issuer: string;
  subject: string;
  principalId: string;
  publicKey: string;
}

export interface McpAudit extends VerifiedPairing {
  challenge: string;
  requestDigest: string;
  routeRevision: string;
  server: string;
  tool: string;
  acceptedAt: string;
  downstreamResponseObserved?: true;
}

export interface GatewayDependencies<Session, Result> {
  authenticateIdentity(session: Session, previousKeyId: string | null): EnrollmentAssertion | Promise<EnrollmentAssertion>;
  resolveRoute(server: string, tool: string): McpRoute;
  forward(server: string, revision: string, request: {
    method: 'tools/call';
    params: { name: string; arguments: Record<string, unknown> };
  }): Result | Promise<Result>;
  clock?(): string;
}

export interface PairingGateway<Session, Result> {
  issueEnrollmentChallenge(): string;
  consumeEnrollmentChallenge(challenge: string): boolean;
  enrollIdentity(session: Session): Promise<{ principalId: string; keyId: string }>;
  rotateIdentity(session: Session, previousKeyId: string): Promise<{ principalId: string; keyId: string }>;
  issueChallenge(call: McpCall): string;
  invoke(call: McpCall, proof: PairedActionProof): Promise<{ audit: McpAudit; result: Result }>;
  readAudit(challenge: string): McpAudit | null;
  close(): void;
}

export function mcpToolCallDigest(call: McpCall): string;
export function openPairingGateway<Session, Result>(
  filename: string, dependencies: GatewayDependencies<Session, Result>,
): PairingGateway<Session, Result>;
