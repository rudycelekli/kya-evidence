import {canonical,digest,exactKeys,insist} from '../../shared/canonical.mjs';
import {validateProfile} from '../../identity/index.mjs';
import {assess,verifyAssessment} from '../../assessment/index.mjs';
import {ASSESSOR_SOURCE_DIGEST} from '../../research/index.mjs';
import {CORE_PROFILE,EVALUATOR_DIGEST,SCENARIOS,evaluateScenario} from '../../conformance/index.mjs';
import {verifyBenchmarkRun} from '../../benchmarks/index.mjs';
import {STRUCTURAL_BLIND_SPOTS,REASON_CODES,REJECTION_CODES,REACHES} from '../domain/catalog.mjs';
const capture=v=>JSON.parse(canonical(v)),equal=(a,b)=>canonical(a)===canonical(b);
const hash=v=>insist(typeof v==='string'&&/^[a-f0-9]{64}$/.test(v),'Invalid dossier digest');
const natural=(v,max=4096)=>insist(Number.isSafeInteger(v)&&v>=0&&v<=max,'Invalid dossier count');
const finite=v=>typeof v==='number'&&Number.isFinite(v)&&v>=0&&(!Number.isInteger(v)||Number.isSafeInteger(v));
function options(value){const v=capture(value);insist(v&&typeof v==='object'&&!Array.isArray(v)&&Object.hasOwn(v,'inputs')&&Object.keys(v).every(k=>['inputs','observations','benchmarkRuns'].includes(k)),'Unknown or missing dossier option');exactKeys(v.inputs,['manifest','profile','policy','evidence','evaluatorDigest','now'],'Dossier frozen inputs');if(!Object.hasOwn(v,'observations'))v.observations=[];if(!Object.hasOwn(v,'benchmarkRuns'))v.benchmarkRuns=[];insist(Array.isArray(v.observations)&&v.observations.length<=4096,'Observation population limit');insist(Array.isArray(v.benchmarkRuns)&&v.benchmarkRuns.length<=8,'Benchmark population limit');return v;}
function observationKey(o){return o&&typeof o==='object'&&!Array.isArray(o)&&typeof o.runId==='string'&&typeof o.scenarioId==='string'?canonical([o.runId,o.scenarioId]):null;}
function original(o,e,assessment){
  exactKeys(o,['schema','scenarioId','runId','source','subjectDigest','scopeId','profileDigest','evaluatorDigest','requestDigest','response','outcome','reasons','error','transportLatencyMs'],'Observation');
  insist(o.schema==='kya.observation/v1'&&finite(o.transportLatencyMs)&&Array.isArray(o.reasons)&&o.reasons.length<=64&&o.reasons.every(r=>typeof r==='string'&&r.length<=256),'Invalid observation');hash(o.requestDigest);
  for(const [ok,pk]of [['scenarioId','checkId'],['runId','runId'],['source','source'],['subjectDigest','subjectDigest'],['scopeId','scopeId'],['profileDigest','profileDigest'],['evaluatorDigest','evaluatorDigest'],['outcome','outcome']])insist(o[ok]===e.payload[pk],'observation-binding-mismatch');
  insist(o.subjectDigest===assessment.subjectDigest&&o.scopeId===assessment.scopeId,'observation-binding-mismatch');
  insist(o.error===null||(['TIMEOUT','ABORTED','OUTPUT_LIMIT','NONZERO_EXIT','MALFORMED_JSON','INVALID_RESPONSE','SPAWN_FAILED','INPUT_LIMIT','ADAPTER_ERROR'].includes(o.error)&&o.outcome==='error'&&o.response===null),'Invalid observation error');
  insist(digest(o)===e.payload.artifactDigest,'artifact-digest-mismatch');
}
function telemetry(records,planned,kind){
  const values=records.map(o=>kind==='cost'?o.response?.usage?.costUsd:o.transportLatencyMs).filter(finite),sum=values.reduce((s,v)=>s+v,0),representable=finite(sum);
  const known=values.length,coverage=planned?Math.round(known/planned*1e6)/1e6:0,total=representable&&known===planned?sum:null;
  return kind==='cost'?{reportedSubtotalUsd:known&&representable?sum:null,reportedTotalUsd:total,known,planned,coverage,aggregation:representable?'bounded-report':'unrepresentable-total'}:{reportedSubtotalMs:known&&representable?sum:null,reportedTotalMs:total,known,planned,coverage,aggregation:representable?'bounded-report':'unrepresentable-total'};
}
function blindSpots(assessment,reportedPasses,coverage,observations){
  const gaps=STRUCTURAL_BLIND_SPOTS.map(([id,title,category,detail,nextEvidence])=>({id,title,category,checkIds:[],detail,nextEvidence}));
  for(const c of assessment.checks)if(!['pass','fail'].includes(c.status))gaps.push({id:'unmeasured:'+c.id,title:'Unproven check: '+c.title,category:'check-coverage',checkIds:[c.id],detail:c.status==='error'?'Evaluation error; this is not proof of agent failure.':c.status==='abstain'?'Abstention leaves this check unproven.':'No scored selected observation establishes this check.',nextEvidence:'Collect a fresh complete authorized run and preserve its exact observation original.'});
  const missing=reportedPasses.filter(c=>c.verificationReach!=='structured-response-replayed').map(c=>c.checkId);
  if(missing.length)gaps.push({id:'unsupported-pass-claims',title:'Passed assertions lack structured-response support',category:'verification-reach',checkIds:missing,detail:'Signed passing assertions are retained separately from replay-supported strengths. Missing, quarantined or unsupported originals cannot establish structured-response strength.',nextEvidence:'Retain matching originals and replay them with the exact supported evaluator.'});
  if(coverage.verifiedOriginals<assessment.checks.length)gaps.push({id:'original-coverage',title:'Observation-original coverage is incomplete',category:'verification-reach',checkIds:[],detail:'A policy-qualified receipt bundle can still lack diagnostic originals. Original coverage describes supplied selected checks, not incident-history completeness.',nextEvidence:'Preserve every planned original, including failed and denied attempts, with readback hashes.'});
  if(observations.rejected.some(r=>r.code==='evaluation-contradiction'))gaps.push({id:'contradictory-originals',title:'Original response contradicts its signed outcome',category:'verification-reach',checkIds:[],detail:'A matching signed artifact contains a response that does not replay to its asserted outcome. It cannot support a strength.',nextEvidence:'Investigate the evaluator/issuer and collect corrected evidence without replacing the original receipt.'});
  if(['fixture','mixed'].includes(assessment.evidenceMode))gaps.push({id:'fixture-generalization',title:'Synthetic results do not score a commercial agent',category:'evaluation',checkIds:[],detail:'Fixture performance tests this controlled example. It does not establish real product behavior.',nextEvidence:'Use an authorized instrumented runtime and a separately reviewed benchmark campaign.'});
  return gaps;
}
export function createDossier(value){
  const {inputs,observations,benchmarkRuns}=options(value),assessment=assess(inputs),chosen=new Set(assessment.acceptedEvidenceDigests),envelopes=new Map();
  for(const e of inputs.evidence)if(chosen.has(digest(e)))envelopes.set(e.payload.id,e);
  const population=new Map();for(const o of observations){const k=observationKey(o);if(k!==null)population.set(k,(population.get(k)??0)+1);}
  const evidenceByKey=new Map([...envelopes.values()].map(e=>[canonical([e.payload.runId,e.payload.checkId]),e]));
  const records=new Map(),rejected=[];let structuredReplays=0;
  const supported=inputs.evaluatorDigest===EVALUATOR_DIGEST&&digest(inputs.profile)===digest(CORE_PROFILE);
  for(const [index,o]of observations.entries()){
    let code='invalid-observation';
    try{
      const k=observationKey(o);if(k===null)throw Error(code);
      if(population.get(k)>1){code='duplicate-observation';throw Error(code);}
      const e=evidenceByKey.get(k);if(!e){code='not-selected-signed-receipt';throw Error(code);}
      original(o,e,assessment);
      let reach='signed-assertion',reasonCodes=[];
      if(supported&&SCENARIOS.some(s=>s.id===o.scenarioId)){
        const scenario=SCENARIOS.find(s=>s.id===o.scenarioId);
        const expectedRequest={schema:'kya.scenario-request/v1',scenarioId:scenario.id,runId:o.runId,subjectDigest:assessment.subjectDigest,scopeId:assessment.scopeId,manifest:inputs.manifest,prompt:scenario.prompt,context:scenario.context,timeoutMs:scenario.timeoutMs};
        if(digest(expectedRequest)!==o.requestDigest){code='observation-binding-mismatch';throw Error(code);}
        if(o.response!==null){const replay=evaluateScenario(o.scenarioId,o.response,{subjectDigest:assessment.subjectDigest,principalId:inputs.manifest.principal.id});if(replay.outcome!==o.outcome){code='evaluation-contradiction';throw Error(code);}reach='structured-response-replayed';structuredReplays++;reasonCodes=replay.reasons.filter(r=>REASON_CODES.includes(r));}
        else if(o.outcome==='error'&&o.error!==null)reach='bound-error-record';
        else {code='evaluation-contradiction';throw Error(code);}
      }
      records.set(e.payload.id,{o,reach,reasonCodes});
    }catch(error){if(REJECTION_CODES.includes(error.message))code=error.message;rejected.push({index,digest:digest(o),code});}
  }
  const item=c=>{const e=envelopes.get(c.evidenceId),r=records.get(c.evidenceId);return{checkId:c.id,title:c.title,dimension:c.dimension,critical:c.critical,evidenceId:c.evidenceId,source:e?.payload.source??'none',verificationReach:r?.reach??'signed-assertion'};};
  const reportedPasses=assessment.checks.filter(c=>c.status==='pass').map(item),strengths=reportedPasses.filter(c=>c.verificationReach==='structured-response-replayed');
  const failureModes=assessment.checks.filter(c=>c.status==='fail').map(c=>({...item(c),reasonCodes:records.get(c.evidenceId)?.reasonCodes??[],rootCause:'not-established'}));
  const observationSummary={provided:observations.length,verifiedOriginals:records.size,structuredReplays,rejected};
  const coverage={plannedChecks:assessment.checks.length,reportedPasses:reportedPasses.length,verifiedStructuredPasses:strengths.length,verifiedOriginals:records.size};
  const benchmarks=benchmarkRuns.map(run=>{verifyBenchmarkRun(run);return{catalogDigest:run.catalogDigest,runDigest:run.runDigest,summary:run.summary,fixtureOnly:true,commercialRuntimesMeasured:false,executionAuthenticated:false};});
  insist(new Set(benchmarks.map(b=>b.runDigest)).size===benchmarks.length,'Duplicate benchmark snapshot');
  const body={schema:'kya.dossier/v1',assessorSourceDigest:ASSESSOR_SOURCE_DIGEST,inputsDigest:digest(inputs),observationsDigest:digest(observations),benchmarkRunDigests:benchmarks.map(b=>b.runDigest),assessment,
    assurance:{authorizationGranted:false,actualEffectsVerified:false,captureComplete:false,issuerIndependence:'relying-policy-assignment'},coverage,reportedPasses,strengths,failureModes,blindSpots:blindSpots(assessment,reportedPasses,coverage,observationSummary),observations:observationSummary,
    measurements:{cost:telemetry([...records.values()].map(r=>r.o),assessment.checks.length,'cost'),latency:telemetry([...records.values()].map(r=>r.o),assessment.checks.length,'latency'),label:'receipt-bound evaluator reports; not verified billing'},benchmarks,
    limitations:['Supplied-bundle policy result; not an authorization grant or a human credit score.','Signature integrity, policy-assigned issuer roles, capture completeness and execution truth are separate.','Structured-response replay does not verify tool side effects or omitted incidents.','Failures identify a predicate; causal root cause is not established.','Score upperBound is not a statistical confidence interval.','Standalone dossier checksums are unauthenticated; recompute from frozen authorized inputs.','Raw responses and private error prose are omitted; original bytes belong in authorized private storage.']};
  return{...body,dossierDigest:digest(body)};
}
function assessmentShape(a){
  exactKeys(a,['schema','subjectDigest','scopeDigest','agentId','agentName','principalId','scopeId','profileDigest','profileId','evaluatorDigest','policyDigest','evidenceBundleDigest','assessedAt','validUntil','selectedRunId','ambiguousRuns','decision','evidenceMode','score','coverage','independentCoverage','dimensions','checks','blockers','rejectedEvidence','acceptedEvidenceDigests','limitations','reportDigest'],'Dossier assessment');
  for(const k of ['subjectDigest','scopeDigest','profileDigest','evaluatorDigest','policyDigest','evidenceBundleDigest'])hash(a[k]);
  insist(['qualified','blocked','insufficient-evidence','expired','revoked'].includes(a.decision)&&['runtime','fixture','mixed','none'].includes(a.evidenceMode),'Unsupported policy decision or source');
  insist(Array.isArray(a.checks)&&a.checks.length>0&&a.checks.length<=256,'Invalid dossier checks');
  const checks=a.checks.map(c=>{exactKeys(c,['id','dimension','title','weight','critical','status','evidenceId','keyId','independence'],'Assessment check');insist(['pass','fail','abstain','error','unknown'].includes(c.status)&&[null,'self','independent'].includes(c.independence),'Invalid check outcome');return{id:c.id,dimension:c.dimension,title:c.title,weight:c.weight,critical:c.critical};});
  validateProfile({schema:'kya.profile/v1',id:a.profileId,version:'shape-only',title:'Dossier supplied check population',checks});
  const total=a.checks.reduce((s,c)=>s+c.weight,0),passed=a.checks.filter(c=>c.status==='pass').reduce((s,c)=>s+c.weight,0),known=a.checks.filter(c=>['pass','fail'].includes(c.status)).reduce((s,c)=>s+c.weight,0),independent=a.checks.filter(c=>['pass','fail'].includes(c.status)&&c.independence==='independent').reduce((s,c)=>s+c.weight,0);
  const ratio=(n,t)=>t?Math.round(n/t*1e6)/1e6:0,points=(n,t)=>t?Math.floor(n/t*1000):0;
  insist(equal(a.score,{earned:points(passed,total),possible:1000,upperBound:points(passed+total-known,total)})&&a.coverage===ratio(known,total)&&a.independentCoverage===ratio(independent,total),'Assessment denominator or score differs');
  const dimensions=['identity','authority','security','reliability','accountability','operations'].map(id=>{const cs=a.checks.filter(c=>c.dimension===id),t=cs.reduce((s,c)=>s+c.weight,0),p=cs.filter(c=>c.status==='pass').reduce((s,c)=>s+c.weight,0),k=cs.filter(c=>['pass','fail'].includes(c.status)).reduce((s,c)=>s+c.weight,0);return{id,earned:points(p,t),possible:t?1000:0,upperBound:points(p+t-k,t),coverage:ratio(k,t),weight:t};});
  insist(equal(a.dimensions,dimensions),'Assessment dimensions differ');
}
export function validateDossier(value){
  const d=capture(value);exactKeys(d,['schema','assessorSourceDigest','inputsDigest','observationsDigest','benchmarkRunDigests','assessment','assurance','coverage','reportedPasses','strengths','failureModes','blindSpots','observations','measurements','benchmarks','limitations','dossierDigest'],'Dossier');
  insist(d.schema==='kya.dossier/v1','Unsupported dossier schema');for(const k of ['assessorSourceDigest','inputsDigest','observationsDigest','dossierDigest'])hash(d[k]);const{dossierDigest,...body}=d;insist(digest(body)===dossierDigest,'Dossier digest differs');verifyAssessment(d.assessment);assessmentShape(d.assessment);
  insist(Array.isArray(d.assessment.checks)&&d.assessment.checks.length>0&&d.assessment.checks.length<=256,'Invalid dossier checks');
  insist(equal(d.assurance,{authorizationGranted:false,actualEffectsVerified:false,captureComplete:false,issuerIndependence:'relying-policy-assignment'}),'Unsupported assurance claim');
  exactKeys(d.coverage,['plannedChecks','reportedPasses','verifiedStructuredPasses','verifiedOriginals'],'Dossier coverage');for(const v of Object.values(d.coverage))natural(v,256);insist(d.coverage.plannedChecks===d.assessment.checks.length,'Changed dossier population');
  for(const name of ['reportedPasses','strengths','failureModes'])insist(Array.isArray(d[name])&&d[name].length<=256,'Invalid dossier findings');
  const assertItem=(item,c,failure=false)=>{exactKeys(item,['checkId','title','dimension','critical','evidenceId','source','verificationReach',...(failure?['reasonCodes','rootCause']:[])],'Dossier finding');insist(c&&item.checkId===c.id&&item.title===c.title&&item.dimension===c.dimension&&item.critical===c.critical&&item.evidenceId===c.evidenceId&&['runtime','fixture','none'].includes(item.source)&&REACHES.includes(item.verificationReach),'Finding differs from assessment');if(failure)insist(item.rootCause==='not-established'&&Array.isArray(item.reasonCodes)&&item.reasonCodes.every(r=>REASON_CODES.includes(r)),'Unsupported failure diagnosis');};
  const passes=d.assessment.checks.filter(c=>c.status==='pass'),failures=d.assessment.checks.filter(c=>c.status==='fail');insist(passes.length===d.reportedPasses.length&&failures.length===d.failureModes.length,'Omitted dossier finding');d.reportedPasses.forEach((r,i)=>assertItem(r,passes[i]));d.failureModes.forEach((r,i)=>assertItem(r,failures[i],true));
  insist(equal(d.strengths,d.reportedPasses.filter(c=>c.verificationReach==='structured-response-replayed'))&&d.coverage.reportedPasses===passes.length&&d.coverage.verifiedStructuredPasses===d.strengths.length,'Unsupported dossier strength');
  exactKeys(d.observations,['provided','verifiedOriginals','structuredReplays','rejected'],'Dossier observations');natural(d.observations.provided);natural(d.observations.verifiedOriginals,256);natural(d.observations.structuredReplays,256);insist(Array.isArray(d.observations.rejected)&&d.observations.rejected.length+d.observations.verifiedOriginals===d.observations.provided&&d.observations.verifiedOriginals===d.coverage.verifiedOriginals&&d.observations.structuredReplays<=d.observations.verifiedOriginals,'Inconsistent observation coverage');
  d.observations.rejected.forEach(r=>{exactKeys(r,['index','digest','code'],'Rejected original');natural(r.index);insist(r.index<d.observations.provided,'Rejected original index differs');hash(r.digest);insist(REJECTION_CODES.includes(r.code),'Unsupported rejection code');});insist(new Set(d.observations.rejected.map(r=>r.index)).size===d.observations.rejected.length,'Duplicate original rejection');
  insist(equal(d.blindSpots,blindSpots(d.assessment,d.reportedPasses,d.coverage,d.observations)),'Omitted or fabricated blind spot');
  exactKeys(d.measurements,['cost','latency','label'],'Measurements');insist(d.measurements.label==='receipt-bound evaluator reports; not verified billing','Unsupported measurement claim');
  for(const[k,n]of [['cost','Usd'],['latency','Ms']]){const m=d.measurements[k];exactKeys(m,['reportedSubtotal'+n,'reportedTotal'+n,'known','planned','coverage','aggregation'],'Measurement');natural(m.known,256);insist(m.planned===d.coverage.plannedChecks&&m.known<=m.planned&&m.coverage===Math.round(m.known/m.planned*1e6)/1e6,'Measurement population differs');insist(['bounded-report','unrepresentable-total'].includes(m.aggregation),'Invalid aggregation');for(const name of ['reportedSubtotal'+n,'reportedTotal'+n])insist(m[name]===null||finite(m[name]),'Invalid measurement');insist(m['reportedTotal'+n]===(m.known===m.planned&&m.aggregation==='bounded-report'?m['reportedSubtotal'+n]:null),'Incomplete measurement total');if(m.known===0||m.aggregation==='unrepresentable-total')insist(m['reportedSubtotal'+n]===null,'Unmeasured subtotal');}
  insist(Array.isArray(d.benchmarks)&&d.benchmarks.length<=8&&Array.isArray(d.benchmarkRunDigests)&&equal(d.benchmarkRunDigests,d.benchmarks.map(b=>b.runDigest))&&new Set(d.benchmarkRunDigests).size===d.benchmarks.length,'Benchmark references differ');d.benchmarks.forEach(b=>{exactKeys(b,['catalogDigest','runDigest','summary','fixtureOnly','commercialRuntimesMeasured','executionAuthenticated'],'Benchmark reference');hash(b.catalogDigest);hash(b.runDigest);insist(b.fixtureOnly===true&&b.commercialRuntimesMeasured===false&&b.executionAuthenticated===false,'Unsupported benchmark claim');});
  insist(d.coverage.verifiedStructuredPasses<=d.observations.structuredReplays&&d.coverage.verifiedOriginals<=d.coverage.plannedChecks,'Verification reach exceeds original population');
  insist(Array.isArray(d.limitations)&&d.limitations.length>0&&d.limitations.every(s=>typeof s==='string'&&s.length<=2048),'Invalid limitations');return d;
}
export function verifyDossier(dossier,value){const supplied=validateDossier(dossier),replay=createDossier(value);insist(equal(supplied,replay),'Dossier does not replay from supplied originals and frozen inputs');return{integrity:true,replayMatched:true,dossierDigest:replay.dossierDigest,assessorSourceDigest:ASSESSOR_SOURCE_DIGEST,authenticated:false,actualEffectsVerified:false,captureComplete:false};}
