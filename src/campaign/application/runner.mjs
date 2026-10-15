import { lstat, mkdir, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, digest, hashBytes, insist } from '../../shared/canonical.mjs';
import { CORE_PROFILE, SCENARIOS, EVALUATOR_DIGEST, runConformance } from '../../conformance/index.mjs';
import { adapterOrigin } from '../../conformance/application/origins.mjs';
import { validateManifest } from '../../identity/domain/services/validation.mjs';
import { appendEntry, attemptStates, verifyLedger } from '../domain/ledger.mjs';
import { privateKeyObject, publicPem } from '../domain/records.mjs';
import { keyId } from '../../identity/domain/services/validation.mjs';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
// Adapter or transport failures are infrastructure errors. Malformed agent output is scored, not errored.
const INFRASTRUCTURE_ERRORS = new Set(['TIMEOUT', 'ABORTED', 'OUTPUT_LIMIT', 'NONZERO_EXIT', 'SPAWN_FAILED', 'INPUT_LIMIT', 'ADAPTER_ERROR']);

export function conformanceDigests() {
  return { profileDigest: digest(CORE_PROFILE), scenarioSetDigest: digest(SCENARIOS), evaluatorDigest: EVALUATOR_DIGEST };
}

const inside = (parent, child) => { const r = relative(parent, child); return r === '' || (r !== '..' && !r.startsWith('..' + sep) && !isAbsolute(r)); };
async function deepestExisting(path) {
  let current = path; const rest = [];
  for (;;) {
    try { await lstat(current); return { real: await realpath(current), rest }; }
    catch (error) { if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error; }
    const parent = dirname(current);
    insist(parent !== current, 'Private directory has no existing ancestor');
    rest.unshift(basename(current)); current = parent;
  }
}
async function preparePrivateDirectory(dir) {
  insist(typeof dir === 'string' && isAbsolute(dir), 'Private directory must be an absolute path');
  const target = resolve(dir), repo = await realpath(REPO_ROOT);
  insist(!inside(REPO_ROOT, target) && !inside(repo, target), 'Private directory must be outside the repository');
  // Resolve symlinks on the deepest existing ancestor before creating anything, so a link into the repo cannot redirect a new directory.
  const { real, rest } = await deepestExisting(target);
  insist(!inside(repo, join(real, ...rest)), 'Private directory must be outside the repository');
  let stat = null;
  try { stat = await lstat(target); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!stat) { await mkdir(target, { recursive: true, mode: 0o700 }); stat = await lstat(target); }
  insist(stat.isDirectory() && !stat.isSymbolicLink(), 'Private directory must be a real directory');
  insist(!inside(repo, await realpath(target)), 'Private directory must be outside the repository');
  insist(typeof process.getuid !== 'function' || stat.uid === process.getuid(), 'Private directory must be owned by the current user');
  insist((stat.mode & 0o077) === 0, 'Private directory permissions must exclude group and others');
  return target;
}
function bundleName(attemptId) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(attemptId) ? `${attemptId}.bundle.json` : `${attemptId.replace(/[^A-Za-z0-9._-]/g, '_')}.${hashBytes(attemptId).slice(0, 12)}.bundle.json`;
}

/**
 * Execute the planned attempts of a signed ledger one at a time through runConformance.
 * Raw evidence goes only to the caller-supplied private directory; the ledger records digests and codes.
 * An errored attempt is never retried here: a retry is a new planned attempt added by a signed amendment.
 */
export async function runCampaign({ plan, ledger, adapter, manifests, policy, trustPlanSigner = false, expectHead, expectEntries, privateKey, privateDir, clock, persist, signal } = {}) {
  insist(adapter && typeof adapter.run === 'function', 'Adapter must expose run(request, {signal})');
  insist(typeof clock === 'function', 'An explicit clock function is required');
  insist(persist === undefined || typeof persist === 'function', 'persist must be a function');
  insist(plan && digest(plan) === digest(ledger?.plan), 'Plan does not match the ledger plan');
  const verification = verifyLedger(ledger, { policy, trustPlanSigner, expectHead, expectEntries });
  if (!verification.valid) throw new Error(`Ledger failed verification: ${verification.problems[0]?.message}`);
  const declared = plan.payload, key = privateKeyObject(privateKey);
  insist(keyId(publicPem(key)) === plan.proof.keyId, 'Signing key is not the campaign capture issuer');
  const frozen = conformanceDigests();
  insist(declared.evaluatorDigest === frozen.evaluatorDigest, 'Plan evaluator digest differs from this evaluator');
  insist(declared.profileDigest === frozen.profileDigest && declared.scenarioSetDigest === frozen.scenarioSetDigest, 'Plan profile or scenario set differs from the frozen core profile');
  const origin = adapterOrigin(adapter);
  insist(origin.source === declared.adapter.source && origin.id === declared.adapter.id && origin.mode === declared.adapter.mode, 'Adapter provenance differs from the plan');
  const pending = [...attemptStates(ledger)].filter(([, s]) => s.status === 'planned');
  for (const [, s] of pending) {
    const m = manifests?.[s.subjectDigest];
    insist(m !== undefined, 'Missing manifest for a planned subject');
    insist(digest(validateManifest(m)) === s.subjectDigest, 'Manifest does not match the planned subject digest');
    insist(s.scenarioSetDigest === frozen.scenarioSetDigest, 'Attempt scenario set differs from the frozen core profile');
  }
  const directory = await preparePrivateDirectory(privateDir);

  const results = [];
  let current = ledger;
  const append = async fields => { current = appendEntry({ ledger: current, privateKey: key, entry: fields }); if (persist) await persist(current); };
  for (const [attemptId, state] of pending) {
    if (signal?.aborted) break;
    await append({ kind: 'started', attemptId, at: clock() });
    let run = null, runError = null;
    try { run = await runConformance({ adapter, manifest: manifests[state.subjectDigest], now: clock(), signal }); }
    catch { runError = 'ADAPTER_ERROR'; }
    let bundleDigest = null, bundlePath = null, errorCode = runError;
    if (run) {
      const body = canonical(run), path = join(directory, bundleName(attemptId));
      try { await writeFile(path, body, { flag: 'wx', mode: 0o600 }); bundleDigest = hashBytes(body); bundlePath = path; }
      catch { errorCode = 'BUNDLE_WRITE_FAILED'; }
      errorCode ??= run.observations.map(o => o.error).find(code => code && INFRASTRUCTURE_ERRORS.has(code)) ?? null;
    }
    if (errorCode) {
      await append({ kind: 'errored', attemptId, at: clock(), errorCode, evidenceBundleDigest: bundleDigest });
      results.push({ attemptId, outcome: 'errored', errorCode, runId: run?.runId ?? null, evidenceBundleDigest: bundleDigest, bundlePath });
    } else {
      await append({ kind: 'completed', attemptId, at: clock(), runId: run.runId, evidenceBundleDigest: bundleDigest });
      results.push({ attemptId, outcome: 'completed', errorCode: null, runId: run.runId, evidenceBundleDigest: bundleDigest, bundlePath });
    }
  }
  return { ledger: current, results };
}
