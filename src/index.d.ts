export type Dimension='identity'|'authority'|'security'|'reliability'|'accountability'|'operations';
export type Outcome='pass'|'fail'|'abstain'|'error';
export type Source='runtime'|'fixture'|'declaration';
export interface Manifest {schema:'kya.manifest/v1';agent:{id:string;name:string;version:string};principal:{id:string};system:{harness:string;harnessVersion:string;model:string;artifactDigest:string;configDigest:string;tools:{id:string;version:string;permissions:string[]}[]};scope:{id:string;purpose:string;permissions:string[];forbidden:string[];approvalRequired:string[]};issuedAt:string;expiresAt:string}
export interface Check {id:string;dimension:Dimension;title:string;weight:number;critical:boolean}
export interface Profile {schema:'kya.profile/v1';id:string;version:string;title:string;checks:Check[]}
export interface Policy {schema:'kya.policy/v1';id:string;profileDigest:string;scopeId:string;minCoverage:number;minScore:number;minIndependentCoverage:number;allowedSources:Source[];maxEvidenceAgeSeconds:number;trustedKeys:{id:string;publicKey:string;role:'self'|'independent'}[];revokedKeyIds:string[];revokedEvidenceIds:string[];revokedSubjectDigests:string[]}
export interface Evidence {schema:'kya.evidence/v1';id:string;subjectDigest:string;scopeId:string;profileDigest:string;evaluatorDigest:string;runId:string;checkId:string;outcome:Outcome;observedAt:string;expiresAt:string;artifactDigest:string;source:Source}
export interface Envelope {payload:Evidence;proof:{algorithm:'Ed25519';keyId:string;publicKey:string;signature:string}}
export interface Assessment {schema:'kya.assessment/v1';subjectDigest:string;agentId:string;agentName:string;principalId:string;scopeId:string;profileDigest:string;profileId:string;evaluatorDigest:string;policyDigest:string;evidenceBundleDigest:string;assessedAt:string;validUntil:string;selectedRunId:string|null;ambiguousRuns:boolean;decision:'qualified'|'blocked'|'insufficient-evidence'|'expired'|'revoked';evidenceMode:'runtime'|'fixture'|'mixed'|'none';score:{earned:number;possible:1000;upperBound:number};coverage:number;independentCoverage:number;dimensions:{id:Dimension;earned:number;possible:number;upperBound:number;coverage:number;weight:number}[];checks:(Check&{status:Outcome|'unknown';evidenceId:string|null;keyId:string|null;independence:'self'|'independent'|null})[];blockers:string[];rejectedEvidence:{index:number;id:string|null;reason:string}[];acceptedEvidenceDigests:string[];limitations:string[];reportDigest:string}
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
export function assess(input:{manifest:Manifest;profile:Profile;evidence:Envelope[];policy:Policy;evaluatorDigest:string;now?:string}):Assessment;
export function verifyAssessment(report:Assessment):{integrity:true;reportDigest:string;authenticated:false;warning:string};
export function compareAssessments(left:Assessment,right:Assessment):{schema:'kya.comparison/v1';left:string;right:string;scoreDelta:number;decisionChanged:boolean;measurement:string};
export function importDeclarations(format:'open-kya-alpha'|'a2a-1',value:unknown):Record<string,unknown>;
export const DIMENSIONS:readonly Dimension[];
export const SOURCES:readonly Source[];
export interface SourceArtifact {id:string;digest:string;kind:'original'|'derived'|'hypothesis';rights:'private'|'redistributable'}
export interface FrozenInputs {manifest:Manifest;profile:Profile;policy:Policy;evidence:Envelope[];evaluatorDigest:string;now:string}
export interface Universe {schema:'kya.universe/v1';assessorSourceDigest:string;parentDigest:string|null;hypothesis:string|null;question:string;sourceArtifacts:SourceArtifact[];invalidates:string[];inputs:FrozenInputs;assessment:Assessment;limitations:string[];universeDigest:string}
export function createUniverse(value:{inputs:FrozenInputs;question:string;sourceArtifacts?:SourceArtifact[];parentDigest?:string|null;hypothesis?:string|null;invalidates?:string[]}):Universe;
export function verifyUniverse(universe:Universe):{integrity:true;replayMatched:true;universeDigest:string;assessorSourceDigest:string;authenticated:false};
export function forkUniverse(parent:Universe,patch:Partial<FrozenInputs>&{hypothesis:string;question?:string;sourceArtifacts?:SourceArtifact[];invalidates?:string[]}):Universe;
export function verifyUniverseGraph(universes:Universe[]):{nodes:number;roots:string[];integrity:true;replayMatched:true;authenticated:false};
export function compareUniverses(left:Universe,right:Universe):Record<string,unknown>;
export const ASSESSOR_SOURCE_DIGEST:string;
