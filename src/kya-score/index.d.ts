// Typings for the experimental kya.score-card/v1 profile (ADR-0033, Proposed). The card is unsigned, self-run and unvalidated.
export type ScoreOutcome = 'pass' | 'fail' | 'abstain' | 'error';
export type NonClaimCode =
  | 'NOT_PREDICTIVE_VALIDITY' | 'NOT_CALIBRATED_TO_INCIDENTS' | 'NO_INTER_ASSESSOR_AGREEMENT' | 'NOT_SAFETY_CERTIFICATION'
  | 'NOT_ENDORSED_OR_ADOPTED' | 'NOT_A_PRODUCT_RANKING' | 'INTERVAL_COVERS_ITEM_SAMPLING_ONLY' | 'SUBJECT_IDENTITY_AS_DECLARED'
  | 'OFFLINE_EXECUTION_NOT_VERIFIED' | 'ITEM_SET_MAY_BE_MEMORIZED';
export type FloorRefusalCode = 'ITEMS_BELOW_FLOOR' | 'REPEATS_BELOW_FLOOR' | 'HELDOUT_BELOW_FLOOR' | 'HOLDOUT_COMMITMENT_MISSING';

export interface ScoreCardIdentity { id: string; version: string; digest: string }
export interface ScoreCardManifest {
  subject: ScoreCardIdentity;
  suite: ScoreCardIdentity;
  evaluatorDigest: string;
  judge: { id: string; digest: string } | null;
  holdoutCommitment: string | null;
  environment: { runtime: string; offlineDeclared: boolean };
  bootstrap: { seed: string; resamples: number };
}
export interface ScoreItemResult { id: string; outcome: ScoreOutcome; heldOut: boolean; durationMs: number; costUsd: number | null; canaryExposed?: boolean }
export interface ScoreRun { runId: string; items: ScoreItemResult[] }
export interface ScoreFloor { minItems: number; minRepeats: number; minHeldOutItems: number }
export interface ScoreAggregate { items: number; repeats: number; score: number; ci95: { low: number; high: number }; resamples: number }
export interface ScoreCardResults {
  headline: ScoreAggregate;
  heldOut: ScoreAggregate;
  public: ScoreAggregate | null;
  publicMinusHeldOut: number | null;
  outcomes: { pass: number; fail: number; abstain: number; error: number; denominator: number };
  repeatVariance: { perRunScores: number[]; mean: number; sd: number; min: number; max: number; unstableItemShare: number };
  cost: { totalUsd: number | null; knownItems: number; items: number };
  runtime: { totalDurationMs: number; meanPerRunDurationMs: number; maxItemDurationMs: number };
  integrity: { canaryExposures: number };
}
export interface ScoreCard {
  schema: 'kya.score-card/v1';
  label: 'KYA-SCR-EXPERIMENTAL';
  manifest: ScoreCardManifest;
  floor: ScoreFloor;
  runs: (ScoreRun & { items: (ScoreItemResult & { canaryExposed: boolean })[] })[];
  runDigest: string;
  results: ScoreCardResults;
  nonClaims: NonClaimCode[];
  cardDigest: string;
}
export interface BuildScoreCardInput { manifest: ScoreCardManifest; runs: ScoreRun[]; options?: { floor?: Partial<ScoreFloor> } }
export interface ScoreCardVerification { valid: boolean; problems: string[]; score?: number; cardDigest?: string }
export interface ScoreCardComparison { comparable: boolean; reasons: string[]; delta: number | null; distinguishable: boolean | null }

export const SCORE_CARD_SCHEMA: 'kya.score-card/v1';
export const SCORE_LABEL: 'KYA-SCR-EXPERIMENTAL';
export const EVIDENCE_FLOOR: Readonly<ScoreFloor>;
export const NON_CLAIM_CODES: readonly NonClaimCode[];
export class ScoreCardRefusal extends Error { readonly code: 'EVIDENCE_FLOOR_NOT_MET'; readonly refusals: FloorRefusalCode[] }
export function buildScoreCard(input: BuildScoreCardInput): ScoreCard;
export function verifyScoreCard(card: unknown): ScoreCardVerification;
export function compareScoreCards(a: unknown, b: unknown): ScoreCardComparison;
export function seededRandom(seed: string): (bound: number) => number;
export function bootstrapSumQuantiles(data: readonly number[], options: { seed: string; resamples: number }): { n: number; resamples: number; estimateSum: number; lowSum: number; highSum: number };
export function bootstrapInterval(data: readonly number[], options: { seed: string; resamples: number }): { n: number; resamples: number; estimate: number; low: number; high: number };
export function wilsonInterval(k: number, n: number): { n: number; k: number; estimate: number; low: number; high: number };
