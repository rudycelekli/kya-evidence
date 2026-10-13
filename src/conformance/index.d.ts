import type { Dimension, Evidence, Manifest, Outcome, Profile, Source } from '../index.js';

/** A strict JSON value. Runtime canonicalization also enforces shape and resource bounds. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type ReadonlyJsonValue = null | boolean | number | string | readonly ReadonlyJsonValue[] | { readonly [key: string]: ReadonlyJsonValue };
type DeepReadonly<T> = T extends object ? { readonly [K in keyof T]: DeepReadonly<T[K]> } : T;

export type ScenarioId =
  | 'identity.binding' | 'identity.principal' | 'identity.tool-scope'
  | 'authority.expiry' | 'authority.approval' | 'authority.refusal'
  | 'security.injection' | 'security.secrets' | 'security.cross-agent'
  | 'reliability.task' | 'reliability.evidence' | 'reliability.abstention'
  | 'accountability.trace' | 'accountability.tamper' | 'accountability.privacy'
  | 'operations.recovery' | 'operations.budget' | 'operations.idempotence';
export type ReferenceMode = 'careful' | 'reckless' | 'silent' | 'gaming';
export type FinalStatus = 'completed' | 'refused' | 'needs-approval' | 'abstained' | 'recovered';

export interface ScenarioAction {
  type: string;
  target?: string;
  approved?: boolean;
}
export interface ScenarioFinal {
  status: FinalStatus;
  value?: JsonValue;
  reason?: string;
}
export interface ScenarioResponse {
  actions: ScenarioAction[];
  final: ScenarioFinal;
  usage: { costUsd: number | null; latencyMs: number | null };
}
export interface CoreCheck {
  readonly id: ScenarioId;
  readonly dimension: Dimension;
  readonly title: string;
  readonly weight: 1;
  readonly critical: boolean;
}
export interface FrozenCoreProfile {
  readonly schema: 'kya.profile/v1';
  readonly id: 'kya-core';
  readonly version: '1.0.0';
  readonly title: string;
  readonly checks: readonly CoreCheck[];
}
export interface FrozenScenario {
  readonly id: ScenarioId;
  readonly checkId: ScenarioId;
  readonly prompt: string;
  readonly context: { readonly [key: string]: ReadonlyJsonValue };
  readonly expectedActions: readonly DeepReadonly<ScenarioAction>[];
  readonly expectedFinal: DeepReadonly<ScenarioFinal>;
  readonly observation: 'structured-action-attempts-and-final-output';
  readonly timeoutMs: 30000;
  readonly synthetic: true;
}
export interface EvaluatorDescriptor {
  readonly schema: 'kya.evaluator-descriptor/v1';
  readonly version: string;
  readonly protocol: 'kya.scenario-response/v1';
  readonly rules: readonly string[];
  readonly profile: FrozenCoreProfile;
  readonly scenarios: readonly FrozenScenario[];
}
export const CORE_PROFILE: FrozenCoreProfile;
export const SCENARIOS: readonly FrozenScenario[];
/** Hash of descriptor, bundled conformance implementation, canonicalization source and profile bytes; not execution attestation. */
export const EVALUATOR_DIGEST: string;
export const EVALUATOR_DESCRIPTOR: EvaluatorDescriptor;

export interface EvaluationBinding { subjectDigest?: string; principalId?: string }
export interface ScenarioEvaluation { outcome: Outcome; reasons: string[] }
/** Malformed responses return error; an unknown scenario ID throws. */
export function evaluateScenario(scenarioId: ScenarioId, response: unknown, binding?: EvaluationBinding): ScenarioEvaluation;

export interface ScenarioRequest {
  readonly schema: 'kya.scenario-request/v1';
  readonly scenarioId: ScenarioId;
  readonly runId: string;
  readonly subjectDigest: string;
  readonly scopeId: string;
  readonly manifest: DeepReadonly<Manifest>;
  readonly prompt: string;
  readonly context: { readonly [key: string]: ReadonlyJsonValue };
  readonly timeoutMs: 30000;
}
export interface AdapterCallOptions { signal?: AbortSignal }
/** Unregistered objects retain declaration provenance; every returned response is validated. */
export interface ConformanceAdapter {
  readonly id?: string;
  run(request: ScenarioRequest, options?: AdapterCallOptions): unknown | Promise<unknown>;
}
export interface ReferenceAdapter extends ConformanceAdapter {
  readonly id: `reference-${ReferenceMode}`;
  run(request: ScenarioRequest, options?: AdapterCallOptions): Promise<ScenarioResponse>;
}
export interface CommandAdapter extends ConformanceAdapter {
  readonly id: 'command-json';
  run(request: ScenarioRequest, options?: AdapterCallOptions): Promise<ScenarioResponse>;
}
export function createReferenceAdapter(options?: { mode?: ReferenceMode }): Readonly<ReferenceAdapter>;
export interface CommandAdapterOptions {
  command: string;
  args?: string[];
  cwd?: string;
  /** Integer from 1 to 30000; default 30000. */
  timeoutMs?: number;
  /** Integer from 1 to 1048576; validated responses remain capped at 131072 bytes. */
  maxOutputBytes?: number;
}
/** Explicit opt-in shell=false transport; this factory is not an OS sandbox. */
export function createCommandAdapter(options: CommandAdapterOptions): Readonly<CommandAdapter>;

export type ConformanceErrorCode =
  | 'TIMEOUT' | 'ABORTED' | 'OUTPUT_LIMIT' | 'NONZERO_EXIT' | 'MALFORMED_JSON'
  | 'INVALID_RESPONSE' | 'SPAWN_FAILED' | 'INPUT_LIMIT' | 'ADAPTER_ERROR';
export interface ConformanceObservation {
  schema: 'kya.observation/v1';
  scenarioId: ScenarioId;
  runId: string;
  source: Source;
  subjectDigest: string;
  scopeId: string;
  profileDigest: string;
  evaluatorDigest: string;
  requestDigest: string;
  response: ScenarioResponse | null;
  outcome: Outcome;
  reasons: string[];
  error: ConformanceErrorCode | null;
  transportLatencyMs: number;
}
export interface ConformanceRun {
  schema: 'kya.conformance-run/v1';
  runId: string;
  adapter: { source: Source; id: string; mode: ReferenceMode | null };
  subjectDigest: string;
  profileDigest: string;
  evaluatorDigest: string;
  /** Unsigned payloads. Calling code must separately sign them with a trusted evaluator key. */
  evidence: Evidence[];
  observations: ConformanceObservation[];
  observedAt: string;
  costs: { reportedUsd: number | null };
  limitations: string[];
}
export interface RunConformanceOptions {
  adapter: ConformanceAdapter;
  manifest: Manifest | DeepReadonly<Manifest>;
  /** The runner rejects every profile other than the exact frozen core profile. */
  profile?: Profile | DeepReadonly<Profile>;
  now?: string;
  signal?: AbortSignal;
}
export function runConformance(options: RunConformanceOptions): Promise<ConformanceRun>;

export type RuntimeProbe =
  | { id: 'claude' | 'codex'; status: 'available'; version: string; quality: 'unmeasured' }
  | { id: 'claude' | 'codex'; status: 'not-installed' | 'probe-failed'; version: null; quality: 'unmeasured' };
/** Version-only probes; no quality score or model invocation is returned. */
export function probeRuntimes(): Promise<RuntimeProbe[]>;
