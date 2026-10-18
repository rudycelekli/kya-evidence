export type Dimension='identity'|'authority'|'security'|'reliability'|'accountability'|'operations';
export type Outcome='pass'|'fail'|'abstain'|'error';
export type Source='runtime'|'fixture'|'declaration';
type ReadonlyInput<T> = T extends object ? { readonly [K in keyof T]: ReadonlyInput<T[K]> } : T;
export interface Manifest {schema:'kya.manifest/v1';agent:{id:string;name:string;version:string};principal:{id:string;accountableParty?:{kind:'natural-person'|'legal-entity';ref:string}};system:{harness:string;harnessVersion:string;model:string;artifactDigest:string;configDigest:string;tools:{id:string;version:string;permissions:string[]}[]};scope:{id:string;purpose:string;permissions:string[];forbidden:string[];approvalRequired:string[]};issuedAt:string;expiresAt:string}
export interface Check {id:string;dimension:Dimension;title:string;weight:number;critical:boolean}
export interface Profile {schema:'kya.profile/v1';id:string;version:string;title:string;checks:Check[]}
export interface Policy {schema:'kya.policy/v1';id:string;profileDigest:string;scopeId:string;minCoverage:number;minScore:number;minIndependentCoverage:number;requirePrincipalBinding?:boolean;mandatoryMinimums?:{checkId:string;minimum:'pass'|'independent-pass'}[];maxAssessmentAgeSeconds?:number;allowedSources:Source[];maxEvidenceAgeSeconds:number;trustedKeys:{id:string;publicKey:string;role:'self'|'independent'|'capture-issuer'}[];revokedKeyIds:string[];revokedEvidenceIds:string[];revokedSubjectDigests:string[]}
export interface Evidence {schema:'kya.evidence/v1';id:string;subjectDigest:string;scopeId:string;profileDigest:string;evaluatorDigest:string;runId:string;checkId:string;outcome:Outcome;observedAt:string;expiresAt:string;artifactDigest:string;source:Source}
export interface Envelope {payload:Evidence;proof:{algorithm:'Ed25519';keyId:string;publicKey:string;signature:string}}
export interface Assessment {schema:'kya.assessment/v1';subjectDigest:string;scopeDigest:string;agentId:string;agentName:string;principalId:string;scopeId:string;profileDigest:string;profileId:string;evaluatorDigest:string;policyDigest:string;evidenceBundleDigest:string;assessedAt:string;validUntil:string;selectedRunId:string|null;ambiguousRuns:boolean;decision:'qualified'|'blocked'|'insufficient-evidence'|'expired'|'revoked';evidenceMode:'runtime'|'fixture'|'mixed'|'none';score:{earned:number;possible:1000;upperBound:number};coverage:number;independentCoverage:number;dimensions:{id:Dimension;earned:number;possible:number;upperBound:number;coverage:number;weight:number}[];checks:(Check&{status:Outcome|'unknown';evidenceId:string|null;keyId:string|null;independence:'self'|'independent'|null})[];blockers:string[];blockerCodes?:BlockerCode[];rejectedEvidence:{index:number;id:string|null;reason:string}[];acceptedEvidenceDigests:string[];limitations:string[];reportDigest:string}
export function canonical(value:unknown):string;
export function digest(value:unknown):string;
export function hashBytes(bytes:string|Uint8Array):string;
export function parseJson(text:string):unknown;
export function keyId(publicKey:unknown):string;
export function validateManifest(value:unknown):Manifest;
export function validateProfile(value:unknown):Profile;
export function validatePolicy(value:unknown):Policy;
export function validateEvidence(value:unknown):Evidence;
export function signEvidence(payload:Evidence,privateKey:unknown):Envelope;
export function verifyEvidence(envelope:unknown):{payload:Evidence;keyId:string;envelopeDigest:string};
export function verifyArtifact(payload:Evidence,bytes:string|Uint8Array):boolean;
export function assess(input:{manifest:ReadonlyInput<Manifest>;profile:ReadonlyInput<Profile>;evidence:ReadonlyInput<Envelope[]>;policy:ReadonlyInput<Policy>;evaluatorDigest:string;now?:string}):Assessment;
export function verifyAssessment(report:ReadonlyInput<Assessment>):{integrity:true;reportDigest:string;authenticated:false;warning:string};
export type BlockerCode='SUBJECT_REVOKED'|'SUBJECT_EXPIRED'|'SUBJECT_NOT_YET_VALID'|'CRITICAL_CHECK_FAILED'|'CRITICAL_CHECK_UNPROVEN'|'COVERAGE_BELOW_POLICY'|'INDEPENDENT_COVERAGE_BELOW_POLICY'|'SCORE_BELOW_POLICY'|'AMBIGUOUS_RUNS'|'RUN_CONFLICT'|'RUN_INVALIDATED'|'MIXED_RUN_ISSUERS'|'REPEATED_RUN_CHECKS'|'NO_SCORED_OBSERVATIONS'|'NO_OBSERVED_CHECKS'|'PRINCIPAL_UNBOUND'|'MANDATORY_MINIMUM_NOT_MET'|'MANDATORY_MINIMUM_UNPROVEN';
export type CurrencyCode='CLOCK_REGRESSION'|'SUBJECT_CHANGED'|'POLICY_CHANGED'|'SUBJECT_REVOKED'|'ASSESSMENT_EXPIRED'|'ASSESSMENT_AGED'|'INCIDENT_OPEN';
export const BLOCKER_CODES:readonly BlockerCode[];
export const CURRENCY_CODES:Readonly<Record<CurrencyTrigger['id'],CurrencyCode>>;
export interface CurrencyTrigger {code:CurrencyCode;id:'clock-regression'|'subject-changed'|'policy-changed'|'subject-revoked'|'assessment-expired'|'assessment-aged'|'incident-open';detail:string}
export interface CurrencyReport {schema:'kya.currency/v1';assessmentDigest:string;checkedAt:string;current:boolean;reliable:boolean;action:'none'|'reassess';triggers:CurrencyTrigger[];authenticated:false;limits:string[];incidents:{considered:number;open:string[];resolved:string[];appealed:string[];observed:string[];ignored:{id:string|null;reason:string}[]}}
export interface Incident {schema:'kya.incident/v1';id:string;subjectDigest:string;kind:'report'|'resolution'|'appeal';severity:'low'|'medium'|'high'|'critical';refId:string|null;reportedAt:string;detailsDigest:string}
export interface IncidentEnvelope {payload:Incident;proof:{algorithm:'Ed25519';keyId:string;publicKey:string;signature:string}}
export function signIncident(payload:ReadonlyInput<Incident>,privateKey:import('node:crypto').KeyObject|string):IncidentEnvelope;
export function verifyIncident(envelope:ReadonlyInput<IncidentEnvelope>):{payload:Incident;keyId:string;envelopeDigest:string};
export function validateIncident(value:ReadonlyInput<Incident>):Incident;
export function checkCurrency(assessment:ReadonlyInput<Assessment>,context:{manifest:ReadonlyInput<Manifest>;policy:ReadonlyInput<Policy>;now:string;incidents?:ReadonlyInput<IncidentEnvelope>[]}):CurrencyReport;
export function compareAssessments(left:ReadonlyInput<Assessment>,right:ReadonlyInput<Assessment>):{schema:'kya.comparison/v1';left:string;right:string;scoreDelta:number;decisionChanged:boolean;measurement:string};
export function describeComparison(left:ReadonlyInput<Assessment>,right:ReadonlyInput<Assessment>):{left:Assessment;right:Assessment;reason:'SCOPE_ID_DIFFERS'|'SCOPE_DIGEST_DIFFERS'|'PROFILE_DIFFERS'|'EVALUATOR_DIFFERS'|'POLICY_DIFFERS'|'EVIDENCE_MODE_DIFFERS'|'CHECK_POPULATION_DIFFERS'|'CHECKS_INCOMPLETE'|null};
export function importDeclarations(format:'open-kya-alpha'|'a2a-1',value:unknown):Record<string,unknown>;
export const DIMENSIONS:readonly Dimension[];
export const SOURCES:readonly Source[];
export interface SourceArtifact {id:string;digest:string;kind:'original'|'derived'|'hypothesis';rights:'private'|'redistributable'}
export interface FrozenInputs {manifest:Manifest;profile:Profile;policy:Policy;evidence:Envelope[];evaluatorDigest:string;now:string}
export interface Universe {schema:'kya.universe/v1';assessorSourceDigest:string;parentDigest:string|null;hypothesis:string|null;question:string;sourceArtifacts:SourceArtifact[];invalidates:string[];inputs:FrozenInputs;assessment:Assessment;limitations:string[];universeDigest:string}
export function createUniverse(value:ReadonlyInput<{inputs:FrozenInputs;question:string;sourceArtifacts?:SourceArtifact[];parentDigest?:string|null;hypothesis?:string|null;invalidates?:string[]}>):Universe;
export function verifyUniverse(universe:ReadonlyInput<Universe>):{integrity:true;replayMatched:true;universeDigest:string;assessorSourceDigest:string;authenticated:false};
export function forkUniverse(parent:ReadonlyInput<Universe>,patch:ReadonlyInput<Partial<FrozenInputs>&{hypothesis:string;question?:string;sourceArtifacts?:SourceArtifact[];invalidates?:string[]}>):Universe;
export function verifyUniverseGraph(universes:ReadonlyInput<Universe[]>):{nodes:number;roots:string[];declaredInvalidations:string[];affectedDescendants:string[];integrity:true;replayMatched:true;authenticated:false;limitation:string};
export function compareUniverses(left:ReadonlyInput<Universe>,right:ReadonlyInput<Universe>):Record<string,unknown>;
export const ASSESSOR_SOURCE_DIGEST:string;

export interface BenchmarkExpectation {decision:Assessment['decision'];coverage:number;checkPopulation:string[];checkStatuses:{id:string;status:Outcome|'unknown'}[];requiredRejectionReasons:string[]}
export interface BenchmarkActual {decision:Assessment['decision'];coverage:number;checkPopulation:string[];checkStatuses:{id:string;status:Outcome|'unknown'}[];rejectionReasons:string[]}
export interface BenchmarkSummary {total:number;possible:number;passed:number;failed:number;errors:number;allPassed:boolean}
export interface BenchmarkCase {id:string;suiteId:'behavioral-core'|'assessment-integrity';source:'fixture';outcome:'pass'|'fail'|'error';expected:BenchmarkExpectation;actual:BenchmarkActual|null;inputs:FrozenInputs|null;inputDigest:string|null;assessment:Assessment|null;artifactDigest:string|null;durationMs:number;costUsd:null;error:'BENCHMARK_EXECUTION_ERROR'|null}
export interface BenchmarkRun {schema:'kya.benchmark-run/v1';catalogDigest:string;evaluatorDigest:string;assessorSourceDigest:string;now:string;fixtureOnly:true;commercialRuntimesMeasured:false;newProviderCalls:0;evidenceInputDigest:string;cases:BenchmarkCase[];summary:BenchmarkSummary;limitations:string[];runDigest:string}
export const BENCHMARK_CATALOG:ReadonlyInput<{schema:'kya.benchmark-catalog/v1';version:1;profileDigest:string;evaluatorDigest:string;suites:{id:string;title:string;checkPopulation:string[];caseIds:string[]}[];cases:{id:string;suiteId:string;mode?:string;expected:BenchmarkExpectation}[];limitations:string[]}>;
export const CATALOG_DIGEST:string;
export function runOfflineBenchmarks(options:{now:string}):Promise<ReadonlyInput<BenchmarkRun>>;
export function verifyBenchmarkRun(value:unknown):{integrity:true;replayMatched:boolean;passed:boolean;runDigest:string;catalogDigest:string;assessorSourceDigest:string;authenticated:false};
export type VerificationReach='signed-assertion'|'structured-response-replayed'|'bound-error-record';
export interface DossierFinding {checkId:string;title:string;dimension:Dimension;critical:boolean;evidenceId:string|null;source:'runtime'|'fixture'|'none';verificationReach:VerificationReach}
export interface BlindSpot {id:string;title:string;category:string;checkIds:string[];detail:string;nextEvidence:string}
export interface ReportedCost {reportedSubtotalUsd:number|null;reportedTotalUsd:number|null;known:number;planned:number;coverage:number;aggregation:'bounded-report'|'unrepresentable-total'}
export interface ReportedLatency {reportedSubtotalMs:number|null;reportedTotalMs:number|null;known:number;planned:number;coverage:number;aggregation:'bounded-report'|'unrepresentable-total'}
export interface Dossier {schema:'kya.dossier/v1';assessorSourceDigest:string;inputsDigest:string;observationsDigest:string;benchmarkRunDigests:string[];assessment:Assessment;assurance:{authorizationGranted:false;actualEffectsVerified:false;captureComplete:false;issuerIndependence:'relying-policy-assignment'};coverage:{plannedChecks:number;reportedPasses:number;verifiedStructuredPasses:number;verifiedOriginals:number};reportedPasses:DossierFinding[];strengths:DossierFinding[];failureModes:(DossierFinding&{reasonCodes:string[];rootCause:'not-established'})[];blindSpots:BlindSpot[];observations:{provided:number;verifiedOriginals:number;structuredReplays:number;rejected:{index:number;digest:string;code:string}[]};measurements:{cost:ReportedCost;latency:ReportedLatency;label:'receipt-bound evaluator reports; not verified billing'};benchmarks:{catalogDigest:string;runDigest:string;summary:BenchmarkSummary;fixtureOnly:true;commercialRuntimesMeasured:false;executionAuthenticated:false}[];limitations:string[];dossierDigest:string}
// Preserve recursive JSON as its explicit readonly domain, rather than mapping
// ReadonlyInput repeatedly through JsonValue's recursive object/array union.
type DossierObservation = Readonly<Omit<import('./conformance/index.js').ConformanceObservation,'response'|'reasons'>> & {
  readonly reasons: readonly string[];
  readonly response: null | {
    readonly actions: readonly Readonly<import('./conformance/index.js').ScenarioAction>[];
    readonly final: {readonly status:import('./conformance/index.js').FinalStatus;readonly value?:import('./conformance/index.js').ReadonlyJsonValue;readonly reason?:string};
    readonly usage: {readonly costUsd:number|null;readonly latencyMs:number|null};
  };
};
export interface DossierOptions {inputs:ReadonlyInput<FrozenInputs>;observations?:readonly DossierObservation[];benchmarkRuns?:readonly ReadonlyInput<BenchmarkRun>[]}
export function createDossier(options:DossierOptions):Dossier;
export function validateDossier(value:unknown):Dossier;
export function verifyDossier(dossier:unknown,options:DossierOptions):{integrity:true;replayMatched:true;dossierDigest:string;assessorSourceDigest:string;authenticated:false;actualEffectsVerified:false;captureComplete:false};
export function renderDossierMarkdown(dossier:unknown):string;
export function renderDossierHtml(dossier:unknown):string;
export type { ScoreCard, ScoreCardManifest, ScoreCardResults, ScoreCardVerification, ScoreCardComparison, ScoreItemResult, ScoreRun, ScoreFloor, ScoreAggregate, NonClaimCode, FloorRefusalCode, BuildScoreCardInput } from './kya-score/index.js';
