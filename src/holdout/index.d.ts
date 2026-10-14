export interface HoldoutCommitment { schema: 'kya.holdout-commitment/v1'; suiteId: string; caseCount: number; merkleRoot: string; saltCommitment: string; createdAt: string }
export interface HoldoutOpening { salt: string; cases: unknown[] }
export interface RevealProof { index: number; caseSalt: string; siblings: string[] }
export type VerifyResult = { ok: true } | { ok: false; reason: string };
export const HOLDOUT_COMMITMENT_SCHEMA: 'kya.holdout-commitment/v1';
export const MAX_CASES: number;
export function generateSalt(): string;
export function commitHoldout(cases: unknown[], options: { salt: string | Uint8Array; suiteId: string; createdAt: string }): { commitment: HoldoutCommitment; opening: HoldoutOpening };
export function revealCase(opening: HoldoutOpening, index: number): { case: unknown; proof: RevealProof };
export function verifyReveal(commitment: HoldoutCommitment, value: unknown, proof: RevealProof): VerifyResult;
export function verifyFullReveal(commitment: HoldoutCommitment, opening: HoldoutOpening): VerifyResult;
