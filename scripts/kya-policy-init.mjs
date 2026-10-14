#!/usr/bin/env node
// kya-policy-init: turn a conservative template preset into a validated, profile-bound policy file.
// Templates are starting points, not validated thresholds. No template makes an agent safe.
import { readFileSync, lstatSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, keyId, parseJson, validatePolicy, validateProfile } from '../src/index.mjs';
import { CORE_PROFILE } from '../src/conformance/index.mjs';

const HELP = `kya-policy-init: generate a KYA policy from a template

  kya-policy-init --template code-agent|agentic-payments|read-only-assistant --profile FILE
                  --trust-key self|independent:PUBLIC_PEM [--trust-key ...] --out FILE
                  [--scope-id ID] [--id POLICY_ID] [--require-principal-binding]
                  [--allow-custom-profile] [--mandatory-minimum CHECK:pass|independent-pass ...] [--max-assessment-age-seconds N]

Options can only tighten a template. Edit the JSON by hand if you need a looser policy, and own that choice.
Templates are starting points, not validated thresholds. No template makes an agent safe.
`;
export const TEMPLATE_NAMES = Object.freeze(['code-agent', 'agentic-payments', 'read-only-assistant']);
const DEFAULT_SCOPE = 'local-readonly';
const LEVEL_RANK = { pass: 1, 'independent-pass': 2 };
const REPEATABLE = ['trust-key', 'mandatory-minimum'];
const VALUE_FLAGS = ['template', 'profile', 'out', 'scope-id', 'id', 'max-assessment-age-seconds', ...REPEATABLE];
const BOOLEAN_FLAGS = ['require-principal-binding', 'allow-custom-profile'];
const MAX_FILE = 1_048_576;

class UsageError extends Error {}
const usage = message => { throw new UsageError(message); };
const clean = (v, max = 160) => String(v ?? '').replace(new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]', 'g'), ' ').slice(0, max);

function parseArgs(argv) {
  const flags = { 'trust-key': [], 'mandatory-minimum': [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { flags.help = true; continue; }
    if (!a.startsWith('--')) usage('Unexpected positional argument');
    const name = a.slice(2);
    if (BOOLEAN_FLAGS.includes(name)) { if (flags[name]) usage(`Duplicate flag --${name}`); flags[name] = true; continue; }
    if (!VALUE_FLAGS.includes(name)) usage(`Unknown flag --${clean(name, 40)}`);
    const next = argv[++i];
    if (next === undefined || next.startsWith('--')) usage(`Flag --${name} requires a value`);
    if (REPEATABLE.includes(name)) flags[name].push(next);
    else { if (Object.hasOwn(flags, name)) usage(`Duplicate flag --${name}`); flags[name] = next; }
  }
  return flags;
}

function readFile(path, label, max = MAX_FILE) {
  let st;
  try { st = lstatSync(path); } catch { usage(`Cannot read ${label}`); }
  if (!st.isFile() || st.isSymbolicLink() || st.size > max) usage(`${label} must be a bounded regular file`);
  return readFileSync(path, 'utf8');
}

function loadTemplate(name) {
  if (!TEMPLATE_NAMES.includes(name)) usage(`Unknown template; choose one of ${TEMPLATE_NAMES.join(', ')}`);
  const t = parseJson(readFileSync(fileURLToPath(new URL(`../policies/templates/${name}.json`, import.meta.url)), 'utf8'));
  if (t.schema !== 'kya.policy-template/v1' || t.id !== name || t.notValidated !== true) usage('Template file is malformed');
  return t;
}

function parseTrustKey(spec) {
  const at = spec.indexOf(':');
  if (at < 1) usage('--trust-key must be ROLE:PUBLIC_PEM_PATH with ROLE self or independent');
  const role = spec.slice(0, at).toLowerCase(), file = spec.slice(at + 1);
  if (!['self', 'independent'].includes(role)) usage('Trust key role must be self or independent');
  const pem = readFile(file, 'Trust key file', 4096);
  if (/PRIVATE KEY/.test(pem)) usage('Trust key file holds private key material; supply the public key only');
  let id;
  try { id = keyId(pem); } catch { usage('Trust key file is not an Ed25519 public SPKI PEM'); }
  return { id, publicKey: pem, role };
}

function parseMinimum(spec) {
  const at = spec.lastIndexOf(':');
  const checkId = spec.slice(0, at), minimum = spec.slice(at + 1);
  if (at < 1 || !LEVEL_RANK[minimum]) usage('--mandatory-minimum must be CHECK:pass or CHECK:independent-pass');
  return { checkId, minimum };
}

export function buildPolicy(flags) {
  for (const k of ['template', 'profile', 'out']) if (!flags[k]) usage(`Missing --${k}`);
  const template = loadTemplate(flags.template);
  const profile = validateProfile(parseJson(readFile(resolve(flags.profile), 'Profile')));
  // A smaller or reweighted profile shrinks the denominator, so thresholds would mean something weaker.
  const customProfile = digest(profile) !== digest(CORE_PROFILE);
  if (customProfile && flags['allow-custom-profile'] !== true) usage('Profile is not the frozen core profile (kya-core 1.0.0); thresholds are calibrated against its denominator. Pass --allow-custom-profile to accept a different profile at your own risk');
  const checkIds = new Set(profile.checks.map(c => c.id));
  const trustedKeys = flags['trust-key'].map(parseTrustKey).sort((a, b) => (a.id < b.id ? -1 : 1));
  if (!trustedKeys.length) usage('At least one --trust-key is required; a policy with no trust anchors accepts no evidence');
  const base = template.policy;
  const minimums = new Map(base.mandatoryMinimums.map(m => [m.checkId, m.minimum]));
  for (const m of flags['mandatory-minimum'].map(parseMinimum)) {
    const prior = minimums.get(m.checkId);
    if (prior && LEVEL_RANK[m.minimum] < LEVEL_RANK[prior]) usage(`Cannot weaken the template minimum for ${clean(m.checkId, 80)}`);
    minimums.set(m.checkId, m.minimum);
  }
  const missing = [...minimums.keys()].filter(id => !checkIds.has(id));
  if (missing.length) usage(`Profile lacks checks the policy names: ${missing.slice(0, 5).map(x => clean(x, 60)).join(', ')}`);
  const needsIndependent = base.minIndependentCoverage > 0 || [...minimums.values()].includes('independent-pass');
  if (needsIndependent && !trustedKeys.some(k => k.role === 'independent')) usage('This policy requires independent evidence; supply at least one --trust-key independent:PUBLIC_PEM');
  let maxAssessmentAge = base.maxAssessmentAgeSeconds;
  if (flags['max-assessment-age-seconds'] !== undefined) {
    const v = flags['max-assessment-age-seconds'];
    if (!/^[1-9][0-9]{0,9}$/.test(v)) usage('--max-assessment-age-seconds must be a positive integer');
    if (Number(v) > maxAssessmentAge) usage(`--max-assessment-age-seconds cannot exceed the template ceiling of ${maxAssessmentAge}`);
    maxAssessmentAge = Number(v);
  }
  const policy = {
    schema: 'kya.policy/v1', id: flags.id ?? `template-${template.id}${customProfile ? '-custom-profile' : ''}`, profileDigest: digest(profile), scopeId: flags['scope-id'] ?? DEFAULT_SCOPE,
    minCoverage: base.minCoverage, minScore: base.minScore, minIndependentCoverage: base.minIndependentCoverage, allowedSources: [...base.allowedSources],
    maxEvidenceAgeSeconds: base.maxEvidenceAgeSeconds, maxAssessmentAgeSeconds: maxAssessmentAge, requirePrincipalBinding: base.requirePrincipalBinding || flags['require-principal-binding'] === true,
    mandatoryMinimums: [...minimums].map(([checkId, minimum]) => ({ checkId, minimum })).sort((a, b) => (a.checkId < b.checkId ? -1 : 1)),
    trustedKeys, revokedKeyIds: [], revokedEvidenceIds: [], revokedSubjectDigests: [],
  };
  try { validatePolicy(policy); } catch (e) { usage('Generated policy is invalid: ' + clean(e.message)); }
  return { policy, template, profile, customProfile };
}

export function main(argv = process.argv.slice(2)) {
  try {
    const flags = parseArgs(argv);
    if (flags.help) { process.stdout.write(HELP); return 0; }
    const { policy, template, profile, customProfile } = buildPolicy(flags);
    try { writeFileSync(resolve(flags.out), JSON.stringify(policy, null, 2) + '\n', { flag: 'wx', mode: 0o644 }); } catch (e) { usage('Cannot write --out (it must not already exist): ' + clean(e.code ?? e.message, 40)); }
    process.stdout.write(JSON.stringify({
      out: resolve(flags.out), template: template.id, policyId: policy.id, policyDigest: digest(policy), profileDigest: digest(profile), scopeId: policy.scopeId,
      trustedKeys: policy.trustedKeys.map(k => ({ id: k.id, role: k.role })), notValidated: true,
      customProfile,
      warnings: [...(customProfile ? ['CUSTOM PROFILE: this is not the frozen kya-core profile, so the template thresholds do not carry their documented meaning; review every threshold and minimum yourself. The policy schema has no field to record this; kya-check flags the policy as customProfile when it runs'] : []), 'Template thresholds are starting points, not validated thresholds', 'No template makes an agent safe; a qualified result is not an authorization grant', 'Only runtime evidence can count under this policy'],
    }, null, 2) + '\n');
    return 0;
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    process.stderr.write(`kya-policy-init: ${clean(e.message, 300)}\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
