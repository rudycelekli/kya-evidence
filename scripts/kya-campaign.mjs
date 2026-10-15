#!/usr/bin/env node
// Standalone campaign harness CLI (ADR-0021). No network, no hidden clock, no real model or vendor CLI.
import { lstat, readFile, writeFile, rename, open, unlink } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { digest, parseJson } from '../src/shared/canonical.mjs';
import { validateManifest, validatePolicy, timestamp, keyId } from '../src/identity/domain/services/validation.mjs';
import { createReferenceAdapter, createCommandAdapter } from '../src/conformance/index.mjs';
import { createPlan, openLedger, verifyLedger, summarizeCampaign, runCampaign, conformanceDigests, verifyCaptureIssuerPolicy } from '../src/campaign/index.mjs';

const HELP = `kya-campaign: frozen-campaign harness with a signed, append-only planned-attempt ledger

  kya-campaign plan --campaign-id ID --use-case TEXT --manifest FILE[,FILE] --attempts N --adapter reference|command --policy FILE --key PRIVATE_PEM --now ISO --out LEDGER
  kya-campaign run --ledger LEDGER --manifest FILE[,FILE] --private-dir ABSOLUTE_DIR --adapter reference|command --policy FILE --key PRIVATE_PEM --now ISO [--expect-head DIGEST] [--expect-entries N]
  kya-campaign verify-ledger --ledger LEDGER --policy FILE [--require-closed true] [--allow-open true] [--expect-head DIGEST] [--expect-entries N]
  kya-campaign summary --ledger LEDGER --policy FILE [--expect-head DIGEST] [--expect-entries N]

run, verify-ledger and summary need --policy (the signer must be a capture-issuer anchor and the policy digest must match the plan),
or the explicit, reported-as-unsafe --trust-plan-signer true.
Exit 2 means incomplete: run and summary exit 2 unless every planned attempt completed (an errored attempt later retried by a completed amendment does not count against it); verify-ledger exits 2 for an open ledger unless --allow-open true. Exit 1 means invalid or refused.
Without an externally pinned --expect-head, a rolled-back or forked ledger cannot be detected.

Only the owned reference and command fixtures are wired. No model, vendor CLI or network call is made.
`;
const fixture = fileURLToPath(new URL('../examples/command-fixture.mjs', import.meta.url));
const ADAPTERS = {
  reference: { declaration: { source: 'fixture', id: 'reference-careful', mode: 'careful' }, create: () => createReferenceAdapter({ mode: 'careful' }) },
  command: { declaration: { source: 'runtime', id: 'command-json', mode: null }, create: () => createCommandAdapter({ command: process.execPath, args: [fixture], timeoutMs: 10000 }) }
};

function parseArgs(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) throw Error(`Unexpected argument ${a}`);
    if (Object.hasOwn(flags, a.slice(2))) throw Error(`Duplicate flag ${a}`);
    const next = argv[++i];
    if (!next || next.startsWith('--')) throw Error(`Flag ${a} requires a value`);
    flags[a.slice(2)] = next;
  }
  return flags;
}
const allow = (flags, names) => { for (const k of Object.keys(flags)) if (!names.includes(k)) throw Error(`Unknown flag --${k}`); };
const need = (flags, names) => { for (const k of names) if (!flags[k]) throw Error(`Missing --${k}`); };
async function regular(path, max = 1_048_576) {
  const st = await lstat(path);
  if (!st.isFile() || st.isSymbolicLink() || st.size > max) throw Error('Input must be a bounded regular file');
  return readFile(path, 'utf8');
}
const jsonFile = async path => parseJson(await regular(path));
async function manifestsFrom(list) {
  const out = {};
  for (const file of list.split(',')) { const m = validateManifest(await jsonFile(resolve(file))); out[digest(m)] = m; }
  return out;
}
const privateKeyFrom = async path => createPrivateKey(await regular(resolve(path), 8192));
async function saveAtomic(path, value) {
  const temp = `${path}.tmp-${process.pid}`;
  await writeFile(temp, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await rename(temp, path);
}
// A run takes an exclusive lock file (O_EXCL) beside the ledger for its whole duration. A leftover lock from a crashed run
// is reported with its owner and is never removed automatically: confirm the owner is gone, then delete the lock file by hand.
async function acquireLock(path) {
  const lockPath = `${path}.lock`, token = randomBytes(16).toString('hex');
  let handle;
  try { handle = await open(lockPath, 'wx', 0o600); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    let owner = 'unknown owner';
    try { const o = JSON.parse(await readFile(lockPath, 'utf8')); owner = `pid ${Number.isSafeInteger(o.pid) ? o.pid : '?'} since ${typeof o.createdAt === 'string' ? o.createdAt.slice(0, 24) : '?'}`; } catch { /* unreadable lock stays unreadable */ }
    throw Error(`Campaign ledger is locked (another run is in progress, or a crashed run left ${lockPath}; ${owner}). The lock is never removed automatically: confirm no run is active, then delete that file and re-run`);
  }
  try { await handle.writeFile(JSON.stringify({ pid: process.pid, token, createdAt: new Date().toISOString() })); } finally { await handle.close(); }
  return async () => { try { if (JSON.parse(await readFile(lockPath, 'utf8')).token === token) await unlink(lockPath); } catch { /* lock already gone */ } };
}
const headOf = ledger => digest(ledger.entries.length ? ledger.entries.at(-1) : ledger.plan);
const print = value => console.log(JSON.stringify(value, null, 2));
async function signerTrust(flags) {
  if (flags.policy && flags['trust-plan-signer'] !== undefined) throw Error('Use either --policy or --trust-plan-signer, not both');
  if (flags['trust-plan-signer'] !== undefined && flags['trust-plan-signer'] !== 'true') throw Error('--trust-plan-signer must be true');
  if (flags.policy) return { policy: await jsonFile(resolve(flags.policy)) };
  if (flags['trust-plan-signer'] === 'true') return { trustPlanSigner: true };
  throw Error('Missing --policy (or the explicit --trust-plan-signer true)');
}
function pins(flags) {
  const out = {};
  if (flags['expect-head'] !== undefined) { if (!/^[a-f0-9]{64}$/.test(flags['expect-head'])) throw Error('--expect-head must be a SHA-256 hex digest'); out.expectHead = flags['expect-head']; }
  if (flags['expect-entries'] !== undefined) { const n = Number(flags['expect-entries']); if (!Number.isSafeInteger(n) || n < 0) throw Error('--expect-entries must be a non-negative integer'); out.expectEntries = n; }
  return out;
}
const adapterChoice = name => { const a = ADAPTERS[name]; if (!a) throw Error('--adapter must be reference or command'); return a; };

const commands = {
  async plan(flags) {
    const names = ['campaign-id', 'use-case', 'manifest', 'attempts', 'adapter', 'policy', 'key', 'now', 'out'];
    allow(flags, names); need(flags, names);
    timestamp(flags.now, '--now');
    const count = Number(flags.attempts);
    if (!Number.isSafeInteger(count) || count < 1 || count > 128) throw Error('--attempts must be an integer from 1 to 128');
    const manifests = await manifestsFrom(flags.manifest), subjects = Object.keys(manifests);
    const attempts = []; let n = 0;
    for (const subjectDigest of subjects) for (let i = 0; i < count; i++) attempts.push({ attemptId: `a-${String(++n).padStart(3, '0')}`, subjectDigest, scenarioSetDigest: conformanceDigests().scenarioSetDigest, seed: null });
    const policy = validatePolicy(await jsonFile(resolve(flags.policy))), key = await privateKeyFrom(flags.key);
    const issuerId = keyId(createPublicKey(key).export({ format: 'pem', type: 'spki' }).toString());
    if (!verifyCaptureIssuerPolicy({ policy, requireIssuer: true }).includes(issuerId)) throw Error('Signing key is not a capture-issuer anchor of the policy');
    const { profileDigest, scenarioSetDigest, evaluatorDigest } = conformanceDigests();
    if (policy.profileDigest !== profileDigest) throw Error('Policy does not bind the frozen core profile');
    const plan = createPlan({ campaignId: flags['campaign-id'], useCase: flags['use-case'], profileDigest, scenarioSetDigest, evaluatorDigest, policyDigest: digest(policy), adapter: adapterChoice(flags.adapter).declaration, attempts, createdAt: flags.now, privateKey: key });
    const ledger = openLedger({ plan, privateKey: key, now: flags.now });
    await writeFile(resolve(flags.out), JSON.stringify(ledger, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    print({ ...summarizeCampaign(ledger), ledger: resolve(flags.out) });
  },
  async run(flags) {
    const names = ['ledger', 'manifest', 'private-dir', 'adapter', 'key', 'now'];
    allow(flags, [...names, 'policy', 'trust-plan-signer', 'expect-head', 'expect-entries']); need(flags, names);
    timestamp(flags.now, '--now');
    const trust = await signerTrust(flags);
    const path = resolve(flags.ledger);
    const release = await acquireLock(path);
    let ledger, result;
    try {
      ledger = await jsonFile(path);
      const manifests = await manifestsFrom(flags.manifest), key = await privateKeyFrom(flags.key);
      let lastHead = headOf(ledger);
      // Re-read the ledger before every replace: a head that differs from the one this process last wrote means another writer got in.
      const persist = async l => {
        const onDisk = await jsonFile(path);
        if (headOf(onDisk) !== lastHead) throw Error('Ledger changed on disk during this run (head mismatch); refusing to overwrite it');
        await saveAtomic(path, l); lastHead = headOf(l);
      };
      result = await runCampaign({ plan: ledger.plan, ledger, adapter: adapterChoice(flags.adapter).create(), manifests, ...trust, ...pins(flags), privateKey: key, privateDir: flags['private-dir'], clock: () => flags.now, persist });
    } finally { await release(); }
    const summary = summarizeCampaign(result.ledger);
    const out = { campaignId: ledger.plan.payload.campaignId, results: result.results.map(({ bundlePath, ...r }) => r), summary };
    if (trust.trustPlanSigner) out.warnings = ['Signer was NOT checked against a capture-issuer anchor (--trust-plan-signer)'];
    print(out);
    if (!summary.allCompleted) process.exitCode = 2;
  },
  async 'verify-ledger'(flags) {
    allow(flags, ['ledger', 'policy', 'trust-plan-signer', 'require-closed', 'expect-head', 'expect-entries', 'allow-open']); need(flags, ['ledger']);
    if (flags['allow-open'] !== undefined && !['true', 'false'].includes(flags['allow-open'])) throw Error('--allow-open must be true or false');
    const options = { requireClosed: flags['require-closed'] === 'true', ...pins(flags) };
    if (flags['require-closed'] !== undefined && !['true', 'false'].includes(flags['require-closed'])) throw Error('--require-closed must be true or false');
    const trust = flags.policy || flags['trust-plan-signer'] !== undefined ? await signerTrust(flags) : {};
    const result = verifyLedger(await jsonFile(resolve(flags.ledger)), { ...options, ...trust });
    const allowOpen = flags['allow-open'] === 'true';
    if (result.valid && !result.closed && allowOpen) result.warnings.push('Ledger is OPEN: attempts remain unaccounted (--allow-open)');
    print(result);
    if (!result.valid) process.exitCode = 1;
    else if (!result.closed && !allowOpen) process.exitCode = 2;
  },
  async summary(flags) {
    allow(flags, ['ledger', 'policy', 'trust-plan-signer', 'expect-head', 'expect-entries']); need(flags, ['ledger']);
    const ledger = await jsonFile(resolve(flags.ledger));
    const result = verifyLedger(ledger, { ...(await signerTrust(flags)), ...pins(flags) });
    if (!result.valid) throw Error(`Ledger failed verification: ${result.problems.map(p => `${p.code} (${p.message})`).join('; ')}`);
    print({ ...result.summary, ...(result.warnings.length ? { warnings: result.warnings } : {}) });
    if (!result.summary.allCompleted) process.exitCode = 2;
  }
};

try {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === '--help' || command === 'help') process.stdout.write(HELP);
  else if (!Object.hasOwn(commands, command)) throw Error(`Unknown command ${command}`);
  else await commands[command](parseArgs(rest));
} catch (error) {
  console.error(`kya-campaign: ${error.message}`);
  process.exitCode = 1;
}
