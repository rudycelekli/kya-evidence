import type { PassportRecord } from '../passport/index.mjs';
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
  passportId?: string;
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
  operationId?: string;
  downstreamResponseObserved?: true;
  passportId?: string;
  passportHead?: string;
}

export interface McpDelivery {
  operationId: string;
  state: 'accepted' | 'dispatching' | 'unknown' | 'response-observed' | 'confirmed-applied' | 'confirmed-not-applied';
  receiptDigest: string | null;
  challenge: string;
  server: string;
  tool: string;
  routeRevision: string;
  requestDigest: string;
}

export type McpDeliveryObservation =
  | { operationId: string; outcome: 'unknown'; receiptDigest: null }
  | { operationId: string; outcome: 'confirmed-applied' | 'confirmed-not-applied'; receiptDigest: string };

export interface GatewayDependencies<Session, Result> {
  authenticateIdentity(session: Session, previousKeyId: string | null): EnrollmentAssertion | Promise<EnrollmentAssertion>;
  resolveRoute(server: string, tool: string): McpRoute;
  forward(server: string, revision: string, request: {
    method: 'tools/call';
    params: { name: string; arguments: Record<string, unknown> };
  }, delivery: { operationId: string }): Result | Promise<Result>;
  observeDelivery?(delivery: McpDelivery): McpDeliveryObservation | Promise<McpDeliveryObservation>;
  passports?: {
    registry: string;
    readHistory(passportId: string): PassportRecord[] | null;
  };
  clock?(): string;
}

export interface PairingGateway<Session, Result> {
  issueEnrollmentChallenge(): string;
  consumeEnrollmentChallenge(challenge: string): boolean;
  enrollIdentity(session: Session): Promise<{ principalId: string; keyId: string }>;
  rotateIdentity(session: Session, previousKeyId: string): Promise<{ principalId: string; keyId: string }>;
  issueChallenge(call: McpCall): string;
  invoke(call: McpCall, proof: PairedActionProof): Promise<{ audit: McpAudit; result: Result }>;
  readDelivery(operationId: string): McpDelivery | null;
  listUnresolvedDeliveries(options?: { after?: string; limit?: number }): McpDelivery[];
  reconcileDelivery(operationId: string): Promise<McpDelivery>;
  readAudit(challenge: string): McpAudit | null;
  close(): void;
}

export function mcpToolCallDigest(call: McpCall): string;
export function openPairingGateway<Session, Result>(
  filename: string, dependencies: GatewayDependencies<Session, Result>,
): PairingGateway<Session, Result>;
