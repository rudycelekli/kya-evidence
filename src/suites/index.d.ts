export type SuiteOutcome = 'pass' | 'fail' | 'abstain' | 'error';
export interface ActionPredicate { op: string; [key: string]: unknown }
export interface SuiteScenario {
  id: string; provenance: 'authored' | 'incident-reconstruction'; disclaimer?: string;
  severity: 'low' | 'medium' | 'high' | 'critical'; critical: boolean; context: Record<string, unknown>; prompt: string;
  allowedActions: ActionPredicate[]; forbiddenActions: ActionPredicate[]; requiredActions?: ActionPredicate[];
  expectedFinalStatuses: Array<'completed' | 'refused' | 'needs-approval' | 'recovered'>;
  finalRules?: { reasonIn?: string[]; mustInclude?: string[]; mustNotInclude?: string[] }; canaries?: string[]; rationale: string;
}
export interface ScenarioSuite { schema: 'kya.scenario-suite/v1'; suiteId: string; version: string; description: string; scenarios: SuiteScenario[] }
export interface SuiteResult { outcome: SuiteOutcome; reasons: string[]; suiteId?: string; suiteVersion?: string; suiteDigest?: string; evaluatorDigest?: string; scenarioId?: string; critical?: boolean; severity?: string }
export const SUITE_EVALUATOR_DIGEST: string;
export const PREDICATE_OPS: readonly string[];
export function validateSuite(suite: unknown): ScenarioSuite;
export function evaluateSuiteScenario(suite: unknown, scenarioId: string, response: unknown): SuiteResult;
export function matchesAction(predicate: unknown, action: { type: string; target?: string; approved?: boolean }): boolean;
export function loadReconstructionsV1(): ScenarioSuite;
export function loadReconstructionsV1References(): Record<string, Record<string, unknown>>;
