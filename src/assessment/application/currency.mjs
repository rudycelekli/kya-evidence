import { canonical, digest, insist } from '../../shared/canonical.mjs';
import { validateManifest, validatePolicy, timestamp } from '../../identity/domain/services/validation.mjs';
import { verifyAssessment } from './assess.mjs';

// Monitoring triggers. An assessment is a point-in-time result; reliance later needs
// evidence that nothing it depended on has changed. Any fired trigger means: reassess.
export function checkCurrency(assessment, {manifest, policy, now} = {}) {
  assessment=JSON.parse(canonical(assessment)); verifyAssessment(assessment);
  manifest=validateManifest(manifest); policy=validatePolicy(policy);
  const at=timestamp(now,'Currency check time'), assessedAt=Date.parse(assessment.assessedAt), validUntil=Date.parse(assessment.validUntil);
  const triggers=[], fire=(id,detail)=>triggers.push({id,detail});
  if (at < assessedAt) fire('clock-regression','Check time precedes the assessment time');
  if (digest(manifest) !== assessment.subjectDigest) fire('subject-changed','Manifest no longer matches the assessed subject digest');
  if (digest(policy) !== assessment.policyDigest) fire('policy-changed','Relying policy differs from the assessed policy');
  if (policy.revokedSubjectDigests.includes(assessment.subjectDigest)) fire('subject-revoked','Subject digest is revoked by the supplied policy');
  if (at > validUntil) fire('assessment-expired','Assessment validity interval has ended');
  if (policy.maxAssessmentAgeSeconds !== undefined && at - assessedAt > policy.maxAssessmentAgeSeconds*1000) fire('assessment-aged','Assessment is older than the policy maximum age');
  return {
    schema:'kya.currency/v1', assessmentDigest:assessment.reportDigest, checkedAt:new Date(at).toISOString(),
    current:triggers.length===0, reliable:triggers.length===0 && assessment.decision==='qualified', action:triggers.length ? 'reassess' : 'none', triggers,
    authenticated:false, limits:['Detects change against supplied manifest, policy and clock only; it does not observe runtime behavior','Report checksum is unauthenticated; recompute from trusted inputs before reliance','A passing check is not an authorization grant'],
  };
}
