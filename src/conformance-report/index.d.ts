/** kya.conformance-report/v1. Declarations never count as pass; not-run stays in the denominator. */
export const REPORT_SCHEMA: 'kya.conformance-report/v1';
export const REPORT_DOMAIN: 'kya.conformance-report/v1\n';
export const RESULTS: readonly ['pass', 'fail', 'not-applicable', 'not-run'];
export const EVIDENCE_CLASSES: readonly ['executed-test', 'portable-vector', 'declaration'];
export type ConformanceResult = 'pass' | 'fail' | 'not-applicable' | 'not-run';
export type ConformanceEvidenceClass = 'executed-test' | 'portable-vector' | 'declaration';
export interface ConformanceImplementation { name: string; version: string; language: string; sourceDigest: string | null; declaredSubset: string[] | null }
export interface ConformanceEntry { id: string; result: ConformanceResult; evidence: ConformanceEvidenceClass | null; executed: string[] }
export interface ConformanceSummary { total: number; pass: number; fail: number; notApplicable: number; notRun: number; applicable: number; passPermille: number | null; declarationEntries: number }
export interface ConformanceReport { schema: 'kya.conformance-report/v1'; implementation: ConformanceImplementation; registryDigest: string; runAt: string; results: ConformanceEntry[]; summary: ConformanceSummary }
export interface ConformanceReportEnvelope { payload: ConformanceReport; proof: { algorithm: 'Ed25519'; keyId: string; publicKey: string; signature: string } }
export interface RequirementRegistry { requirements: ReadonlyArray<{ id: string; tests?: ReadonlyArray<{ file: string; title: string; hostConditional?: boolean }> }> }
export function buildReport(input: { registry: RequirementRegistry; implementation: Omit<ConformanceImplementation, 'sourceDigest' | 'declaredSubset'> & Partial<Pick<ConformanceImplementation, 'sourceDigest' | 'declaredSubset'>>; results: Record<string, Omit<ConformanceEntry, 'id'>> | ConformanceEntry[]; runAt: string; registryDigest?: string }): ConformanceReport;
export function validateReport(value: unknown, options?: { registry?: RequirementRegistry }): ConformanceReport;
export function signReport(report: unknown, privateKey: import('node:crypto').KeyObject | string): ConformanceReportEnvelope;
/** Integrity and key possession only; authenticated and truthfulnessVerified are always false. */
export function verifyReport(envelope: unknown, options?: { registry?: RequirementRegistry }): { payload: ConformanceReport; keyId: string; envelopeDigest: string; authenticated: false; truthfulnessVerified: false };
export function summarize(results: ReadonlyArray<ConformanceEntry>): ConformanceSummary;
export function parseTap(output: string): Array<{ title: string; status: 'pass' | 'fail' | 'skip' }>;
export function mapTapToRequirements(registry: RequirementRegistry, runs: Record<string, { exitCode: number | null; tests: Array<{ title: string; status: 'pass' | 'fail' | 'skip' }> }>): Record<string, Omit<ConformanceEntry, 'id'>>;
