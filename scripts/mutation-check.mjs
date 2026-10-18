import { mkdtemp,cp,readFile,writeFile,rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { hashBytes } from '../src/index.mjs';

const root=fileURLToPath(new URL('../',import.meta.url)),source='src/assessment/application/assess.mjs';
const original=await readFile(join(root,source),'utf8');
const mutants=[
  ['trust-anchor bypass',"const k = trusted.get(e.keyId);","const k = trusted.get(e.keyId) ?? {role:'independent'};"],
  ['revoked-key bypass',"insist(!policy.revokedKeyIds.includes(e.keyId),'Signing key is revoked');","/* mutation: skip key revocation */"],
  ['declaration laundering',"insist(p.source !== 'declaration','A declaration cannot satisfy an observed check');","/* mutation: allow declaration */"],
  ['critical-gate removal',"const criticalFailures = checks.filter(c=>c.critical && c.status==='fail');","const criticalFailures = [];"],
  ['ambiguity-gate removal',"const ambiguousRuns = tiedRuns.length>1;","const ambiguousRuns = false;"],
  ['duplicate fallback laundering',"for (const e of bound) {\n    const id = e.payload.runId;","for (const e of unique) {\n    const id = e.payload.runId;"]
,
  ['principal-binding gate removal',"const principalUnbound = policy.requirePrincipalBinding === true && !manifest.principal.accountableParty;","const principalUnbound = false;"],
  ['expiry trigger removal',"if (at >= validUntil) fire(","if (false) fire(",'src/assessment/application/currency.mjs'],
  ['subject-change trigger removal',"if (digest(manifest) !== assessment.subjectDigest) fire(","if (false) fire(",'src/assessment/application/currency.mjs'],
  ['independent-resolution requirement removal',"else if (e.role!=='independent') ignored.push","else if (false) ignored.push",'src/assessment/application/currency.mjs'],
  ['incident trust-anchor bypass',"if (!roles.has(keyId)) skip(","if (false) skip(",'src/assessment/application/currency.mjs'],
  ['blocking-severity downgrade',"const BLOCKING = ['high','critical'];","const BLOCKING = ['critical'];",'src/assessment/application/currency.mjs'],
  ['reporter self-resolution allowed',"else if (targets[0].keyId===e.keyId) ignored.push","else if (false) ignored.push",'src/assessment/application/currency.mjs'],
  ['malformed validity accepted',"insist(timestamp(assessment.validUntil,'Assessment validity') >= timestamp(assessment.assessedAt,'Assessment time'),'Assessment validity precedes its assessment time');","",'src/assessment/application/currency.mjs'],
  ['future resolution honoured',"if (e.future) { ignored.push({id:e.id,reason:'Incident is dated in the future'}); continue; }","",'src/assessment/application/currency.mjs'],
  ['envelope dedupe removed',"if (seen.has(envelopeDigest)) continue;","",'src/assessment/application/currency.mjs'],
  ['ambiguous-reference gate removed',"if ((counts.get(e.refId)??0)>1) ignored.push","if (false) ignored.push",'src/assessment/application/currency.mjs'],
  ['mandatory-minimum gate removal',"if (decision!=='revoked' && decision!=='expired') {\n    for (const m of policy.mandatoryMinimums","if (false) {\n    for (const m of policy.mandatoryMinimums"],
  ['mandatory-minimum unknown treated as met',"if (c.status==='pass' && (m.minimum==='pass'","if (c.status!=='fail' && (m.minimum==='pass'"],
  ['independent-pass downgraded to pass',"(m.minimum==='pass' || c.independence==='independent')","(true)"],
  ['mandatory-minimum overrides revoked subject',"if (decision!=='revoked' && decision!=='expired') {\n    for (const m of policy.mandatoryMinimums","if (true) {\n    for (const m of policy.mandatoryMinimums"],
  ['mandatory-minimum profile binding removed',"for (const m of policy.mandatoryMinimums ?? []) insist(checkIds.has(m.checkId),'Mandatory minimum names a check outside the frozen profile');","/* mutation: skip minimum profile binding */"],
  ['blocker code dropped from report',"blockers.push(text); blockerCodes.push(code);","blockers.push(text);"],
  ['critical failure mislabelled',"block('CRITICAL_CHECK_FAILED',","block('SCORE_BELOW_POLICY',"],
  ['blocker code validation removed',"if (!Object.hasOwn(report, 'blockerCodes')) return;","return;",'src/assessment/application/codes.mjs'],
  ['duplicate minimum accepted',"insist(!seen.has(e.checkId),'Duplicate mandatory minimum check'); ","",'src/identity/domain/services/validation.mjs'],
  ['currency trigger code removed',"code:CURRENCY_CODES[id],","",'src/assessment/application/currency.mjs'],
  ['report exit-code check removed',"else if (found[0].status === 'skip' || run.error || (run.exitCode !== 0 && !run.tests.some(x => x.status === 'fail'))) unknown = true;","else if (found[0].status === 'skip') unknown = true;",'src/conformance-report/report.mjs'],
  ['blocker-code critical count cross-check removed',"insist(c.filter(x => x === 'CRITICAL_CHECK_FAILED').length === failedCritical, 'Invalid blocker codes: critical failure count does not match the report checks');","",'src/assessment/application/codes.mjs'],
  ['unproven minimum named as failed',"else block('MANDATORY_MINIMUM_UNPROVEN',","else block('MANDATORY_MINIMUM_NOT_MET',",'src/assessment/application/assess.mjs'],
  ['ambiguity judged only over live reports',"if ((counts.get(e.refId)??0)>1) ignored.push","if (targets.length>1) ignored.push",'src/assessment/application/currency.mjs'],
  ["ledger chain commitment removal","e.prevDigest !== previous","false","src/campaign/domain/ledger.mjs"],
  ["ledger transition gate removal","if (!allowed.includes(state.status))","if (false)","src/campaign/domain/ledger.mjs"],
  ["capture-issuer role requirement removal","anchor.role !== 'capture-issuer'","false","src/campaign/domain/ledger.mjs"],
  ["unaccounted attempts leave denominator","planned: attempts.size","planned: attempts.size - open.length","src/campaign/domain/ledger.mjs"],
  ["retry of non-errored attempt allowed","original.status !== 'errored' ||","false ||","src/campaign/domain/ledger.mjs"],
  ["runner adapter source check removal","origin.source === declared.adapter.source &&","true &&","src/campaign/application/runner.mjs"],
  ["runner adapter mode check removal","origin.mode === declared.adapter.mode","true","src/campaign/application/runner.mjs"],
  ["private directory permission check removal","(stat.mode & 0o077) === 0","true","src/campaign/application/runner.mjs"],
  ["bundle overwrite allowed","flag: 'wx'","flag: 'w'","src/campaign/application/runner.mjs"],
  ["capture-issuer evidence-signer check removal","insist(!evidenceKeyIds.includes(id)","insist(true || !evidenceKeyIds.includes(id)","src/campaign/domain/roles.mjs"],
  ["capture-issuer scoring evidence allowed","insist(k.role !== 'capture-issuer','A capture-issuer key cannot issue scoring evidence');","","src/assessment/application/assess.mjs"],
  ["small-order key check removed","insist(!(q[0] === 0n && q[1] === 1n), 'Invalid Ed25519 public key: small-order point');","","src/shared/ed25519-point.mjs"],
  ["private directory real-path check removed","insist(!inside(repo, join(real, ...rest)), 'Private directory must be outside the repository');","","src/campaign/application/runner.mjs"],
  ["pinned ledger head check removed","expectHead !== undefined && expectHead !== headDigest","false","src/campaign/domain/ledger.mjs"],
  ["duplicate evidence check removed","if (runIds.has(e.runId.toLowerCase()) || bundles.has(e.evidenceBundleDigest))","if (false)","src/campaign/domain/ledger.mjs"],
  ["fixture evidence counted as reliable","if (m === 'fixture') { if (!allowFixture) out.push('FIXTURE_EVIDENCE_NOT_RELIABLE'); }","if (m === 'fixture') { }","scripts/kya-check.mjs"],
  ["expired status list accepted","if (e.code === 'EXPIRED') fail('STATUS_LIST_EXPIRED'","if (false) fail('STATUS_LIST_EXPIRED'","src/vc-bridge/status.mjs"],
  ["unpinned assessment counted as reliable","if (mode === 'currency-only' && !pins.assessmentPinned && !allowUnpinned) out.push('ASSESSMENT_NOT_PINNED');","","scripts/kya-check.mjs"],
  ["assessment digest pin check removed","if (currencyOnly) checks.push(['expect-assessment-digest'","if (false) checks.push(['expect-assessment-digest'","scripts/kya-check.mjs"],
  ["report mismatch not reported","if (diffs.length) errors.push({ code: 'REPORT_MISMATCH',","if (false) errors.push({ code: 'REPORT_MISMATCH',","src/vc-bridge/credential.mjs"],
  ["open campaign ledger exits zero in summary","if (!summary.allCompleted) process.exitCode = 2;","","scripts/kya-campaign.mjs"],
  ["run ID case-insensitivity removed","runIds.has(e.runId.toLowerCase())","runIds.has(e.runId)","src/campaign/domain/ledger.mjs"],
  ["errored entry bundle reuse allowed","if (bundles.has(e.evidenceBundleDigest)) problems.push(problem('duplicate-evidence', `Entry ${i}: Duplicate evidence bundle digest across attempts`));","","src/campaign/domain/ledger.mjs"],
  ["disclosure signature domain prefix removed on verify","verify(null, Buffer.from(DISCLOSURE_DOMAIN + canonical(payload))","verify(null, Buffer.from(canonical(payload))","src/assessor/disclosure.mjs"],
  ["disclosure domain constant emptied","export const DISCLOSURE_DOMAIN = 'kya.assessor-disclosure/v1\\n';","export const DISCLOSURE_DOMAIN = '';","src/assessor/disclosure.mjs"],
  ["disclosure signature verification skipped","insist(verify(null, Buffer.from(DISCLOSURE_DOMAIN","insist(true || verify(null, Buffer.from(DISCLOSURE_DOMAIN","src/assessor/disclosure.mjs"],
  ["disclosure proof key fingerprint check removed","insist(keyId(p.publicKey) === p.keyId, 'Proof key fingerprint differs');","","src/assessor/disclosure.mjs"],
  ["standing declarer trust check removed","const trustedDeclarer = r.keyId !== d.assessorKeyId && P.declarers.has(r.keyId);","const trustedDeclarer = r.keyId !== d.assessorKeyId;","src/assessor/standing.mjs"],
  ["standing self-declaration allowed","const trustedDeclarer = r.keyId !== d.assessorKeyId && P.declarers.has(r.keyId);","const trustedDeclarer = P.declarers.has(r.keyId);","src/assessor/standing.mjs"],
  ["standing declarer revocation ignored","if (P.revoked.has(r.keyId)) {","if (false) {","src/assessor/standing.mjs"],
  ["standing forged withdrawal honoured","if (target.keyId !== w.keyId) { ignored.push({ index: w.index, reason: 'signer-mismatch' }); continue; }","if (false) { ignored.push({ index: w.index, reason: 'signer-mismatch' }); continue; }","src/assessor/standing.mjs"],
  ["standing disclosure signer-match removed","} else if (r.keyId !== d.assessorKeyId) {","} else if (r.keyId !== d.assessorKeyId && d.kind !== 'disclosure') {","src/assessor/standing.mjs"],
  ["standing disclosure expiry boundary inclusive","const live = tops.map(e => e.r).filter(r => Date.parse(r.payload.expiresAt) > t);","const live = tops.map(e => e.r).filter(r => Date.parse(r.payload.expiresAt) >= t);","src/assessor/standing.mjs"],
  ["standing disclosure start boundary exclusive","const started = slot.own.filter(r => Date.parse(r.payload.issuedAt) <= t);","const started = slot.own.filter(r => Date.parse(r.payload.issuedAt) < t);","src/assessor/standing.mjs"],
  ["standing declaration expiry boundary inclusive","Date.parse(dec.payload.expiresAt) > t","Date.parse(dec.payload.expiresAt) >= t","src/assessor/standing.mjs"],
  ["standing cooling-off boundary inclusive","if (r.payload.priorEngagementEndedAt !== null && t < Date.parse(r.payload.priorEngagementEndedAt) + P.cool * DAY)","if (r.payload.priorEngagementEndedAt !== null && t <= Date.parse(r.payload.priorEngagementEndedAt) + P.cool * DAY)","src/assessor/standing.mjs"],
  ["bridge gate NOT_QUALIFIED refusal removed","if (options.allowNonQualified !== true) fail('NOT_QUALIFIED'","if (false) fail('NOT_QUALIFIED'","src/interop-bridges/gate.mjs"],
  ["bridge gate NOT_CURRENT refusal removed","if (options.allowNotCurrent !== true) fail('NOT_CURRENT'","if (false) fail('NOT_CURRENT'","src/interop-bridges/gate.mjs"],
  ["bridge gate CURRENCY_NOT_CHECKED refusal removed","if (options.allowNotCurrent !== true) fail('CURRENCY_NOT_CHECKED'","if (false) fail('CURRENCY_NOT_CHECKED'","src/interop-bridges/gate.mjs"],
  ["bridge gate partial currency inputs accepted","if (have.some(Boolean)) fail('CURRENCY_INPUTS_INCOMPLETE'","if (false) fail('CURRENCY_INPUTS_INCOMPLETE'","src/interop-bridges/gate.mjs"],
  ["bridge gate non-qualified override unrecorded","    overrides.push('allowNonQualified');\n","","src/interop-bridges/gate.mjs"],
  ["bridge gate not-current override unrecorded","      overrides.push('allowNotCurrent');\n    }\n    currency = { checked: true","    }\n    currency = { checked: true","src/interop-bridges/gate.mjs"],
  ["bridge gate unchecked-currency override unrecorded","    overrides.push('allowNotCurrent');\n    currency = { checked: false","    currency = { checked: false","src/interop-bridges/gate.mjs"],
  ["bridge gate qualified without passing currency","r.decision === 'qualified' && currency.current === true","r.decision === 'qualified' && currency.current !== false","src/interop-bridges/gate.mjs"],
  ["profile metadata digest mismatch accepted","insist(digest(p) === v.profileDigest, 'Profile digest mismatch');","","src/profiles/validate-metadata.mjs"],
  ["change-log sign-off claim without evidence accepted","insist(!SIGNOFF_CLAIM.test(c.summary) || v.signOff !== null, 'Change log claims sign-off without evidence');","","src/profiles/validate-metadata.mjs"],
  ["purpose and scope sign-off claim without evidence accepted","insist(typeof t !== 'string' || !SIGNOFF_CLAIM.test(t), `${k} claims review or sign-off without evidence`);","void 0;","src/profiles/validate-metadata.mjs"],
  ["sign-off evidence digest unchecked","hash(v.signOff.evidenceDigest, 'Sign-off evidence digest');","","src/profiles/validate-metadata.mjs"],
  ["sign-off record shape unchecked","exactKeys(v.signOff, ['reviewer', 'role', 'date', 'evidenceDigest'], 'Sign-off');","","src/profiles/validate-metadata.mjs"],
  ["draft profile sign-off allowed","insist(v.status !== 'draft', 'A draft profile cannot carry a sign-off; set the status through review');","","src/profiles/validate-metadata.mjs"],
  ["privacy scan echoes matched value","redacted: shapeMask(m[0]) });","redacted: m[0] });","scripts/privacy-scan.mjs"],
  ["privacy scan echoes malformed structural value","length: v.length, redacted: shapeMask(v) });\n      else if (ID_KEY","length: v.length, redacted: v });\n      else if (ID_KEY","scripts/privacy-scan.mjs"],
  ["privacy scan shape mask leaks digits","/[0-9]/.test(ch) ? '9'","/[0-9]/.test(ch) ? ch","scripts/privacy-scan.mjs"],
  ["privacy scan echoes sensitive object keys in paths","return SAFE_KEY.test(key) && scanString(key).length === 0 ?","return true ?","scripts/privacy-scan.mjs"],
  ["privacy scan echoes malformed coded value","rule: 'coded-field-free-text', category: 'structure', offset: 0, length: v.length, redacted: shapeMask(v)","rule: 'coded-field-free-text', category: 'structure', offset: 0, length: v.length, redacted: v","scripts/privacy-scan.mjs"],
  ["privacy scan echoes narrative value","rule: 'digest-only-free-text', category: 'structure', offset: 0, length: v.length, redacted: shapeMask(v)","rule: 'digest-only-free-text', category: 'structure', offset: 0, length: v.length, redacted: v","scripts/privacy-scan.mjs"]
];
const results=[];
function failedNames(output){return [...output.matchAll(/^not ok \d+ - (.+)$/gm)].map(m=>m[1]).slice(0,5);}
function counts(output){const get=name=>Number(new RegExp(`^# ${name} (\\d+)$`,'m').exec(output)?.[1]??NaN);return{tests:get('tests'),pass:get('pass'),fail:get('fail'),cancelled:get('cancelled'),skipped:get('skipped')};}
function runTests(dir){const p=spawnSync(process.execPath,['--test','--test-reporter=tap','test/assessment.test.mjs','test/incidents.test.mjs','test/refusal-codes.test.mjs','test/mandatory-minimums.test.mjs','test/conformance-report.test.mjs','test/campaign-ledger.test.mjs','test/campaign-runner.test.mjs','test/capture-issuer-scoring.test.mjs','test/vc-bridge.test.mjs','test/kya-check.test.mjs','test/assessor.test.mjs','test/interop-bridges.test.mjs','test/profiles.test.mjs','test/privacy.test.mjs','test/security-gates.test.mjs'],{cwd:dir,encoding:'utf8',timeout:300000,maxBuffer:16000000});if(p.error||p.signal)throw Error('Mutation test execution failed');return{process:p,counts:counts(p.stdout)};}
// Fail fast: report every drifted anchor before spending minutes on test runs.
{const drift=[];for(const [name,from,,target=source]of mutants){const text=target===source?original:await readFile(join(root,target),'utf8');if(!text.includes(from))drift.push(name+' ('+target+')');}if(drift.length)throw Error('Mutation anchor drift in '+drift.length+' control(s): '+drift.join('; '));
  // A mutant must stay syntactically valid; otherwise the test file crashes at import and nothing is measured.
  const broken=[];for(const [name,from,to,target=source]of mutants){const text=target===source?original:await readFile(join(root,target),'utf8');const probe=join(tmpdir(),'kya-mutant-syntax-'+process.pid+'.mjs');await writeFile(probe,text.replace(from,to));const c=spawnSync(process.execPath,['--check',probe],{encoding:'utf8'});if(c.status!==0)broken.push(name);await rm(probe,{force:true});}
  if(broken.length)throw Error('Invalid mutant (syntax error) in '+broken.length+' control(s): '+broken.join('; '));}
if(process.argv.includes('--preflight')){console.log(JSON.stringify({preflight:'ok',controls:mutants.length,anchorsPresent:true,allMutantsParse:true}));process.exit(0);}
for(const [name,from,to,target=source]of mutants){
  const base=target===source?original:await readFile(join(root,target),'utf8');
  if(!base.includes(from))throw Error('Mutation anchor drift: '+name);
  const dir=await mkdtemp(join(tmpdir(),'kya-mutant-'));
  try{await cp(join(root,'src'),join(dir,'src'),{recursive:true});await cp(join(root,'test'),join(dir,'test'),{recursive:true});await cp(join(root,'package.json'),join(dir,'package.json'));await cp(join(root,'profiles'),join(dir,'profiles'),{recursive:true});for(const extra of ['dashboard','docs','schemas','scripts','evidence','examples','suites','policies','action'])await cp(join(root,extra),join(dir,extra),{recursive:true});
    const baseline=runTests(dir);if(baseline.process.status!==0||!Number.isSafeInteger(baseline.counts.tests)||baseline.counts.tests<1||baseline.counts.fail!==0||baseline.counts.cancelled!==0||baseline.counts.skipped!==0)throw Error('Mutation baseline did not run cleanly: '+name);
    const mutated=base.replace(from,to);await writeFile(join(dir,target),mutated);const candidate=runTests(dir);
    if(candidate.counts.tests!==baseline.counts.tests||candidate.counts.cancelled!==0||candidate.counts.skipped!==0)throw Error('Mutant did not exercise identical complete test population: '+name);
    const killed=candidate.process.status!==0&&candidate.counts.fail>0;results.push({name,killed,killedBy:failedNames(candidate.process.stdout),baselineTests:baseline.counts.tests,mutantTests:candidate.counts.tests,failedAssertions:candidate.counts.fail,mutantSourceDigest:hashBytes(mutated),exitCode:candidate.process.status});
    if(!killed)throw Error('SURVIVING evaluator mutant: '+name);
  }finally{await rm(dir,{recursive:true,force:true});}
}
console.log(JSON.stringify({schema:'kya.mutation-controls/v1',baselineSourceDigest:hashBytes(original),controls:results,allKilled:true,limits:'Targeted gate mutations with textual anchors; not exhaustive security verification'},null,2));
