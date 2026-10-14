#!/usr/bin/env node
// Standalone campaign harness CLI (ADR-0021). No network, no hidden clock, no real model or vendor CLI.
import { lstat, readFile, writeFile, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { digest, parseJson } from '../src/shared/canonical.mjs';
import { validateManifest, validatePolicy, timestamp, keyId } from '../src/identity/domain/services/validation.mjs';
import { createReferenceAdapter, createCommandAdapter } from '../src/conformance/index.mjs';
import { createPlan, openLedger, verifyLedger, summarizeCampaign, runCampaign, conformanceDigests, verifyCaptureIssuerPolicy } from '../src/campaign/index.mjs';

const HELP = `kya-campaign: frozen-campaign harness with a signed, append-only planned-attempt ledger

  kya-campaign plan --campaign-id ID --use-case TEXT --manifest FILE[,FILE] --attempts N --adapter reference|command --policy FILE --key PRIVATE_PEM --now ISO --out LEDGER
  kya-campaign run --ledger LEDGER --manifest FILE[,FILE] --private-dir ABSOLUTE_DIR --adapter reference|command --key PRIVATE_PEM --now ISO
  kya-campaign verify-ledger --ledger LEDGER [--policy FILE] [--require-closed true]
  kya-campaign summary --ledger LEDGER

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
const print = value => console.log(JSON.stringify(value, null, 2));
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
    allow(flags, names); need(flags, names);
    timestamp(flags.now, '--now');
    const path = resolve(flags.ledger), ledger = await jsonFile(path);
    const manifests = await manifestsFrom(flags.manifest), key = await privateKeyFrom(flags.key);
    const result = await runCampaign({ plan: ledger.plan, ledger, adapter: adapterChoice(flags.adapter).create(), manifests, privateKey: key, privateDir: flags['private-dir'], clock: () => flags.now, persist: l => saveAtomic(path, l) });
    print({ campaignId: ledger.plan.payload.campaignId, results: result.results.map(({ bundlePath, ...r }) => r), summary: summarizeCampaign(result.ledger) });
  },
  async 'verify-ledger'(flags) {
    allow(flags, ['ledger', 'policy', 'require-closed']); need(flags, ['ledger']);
    const options = { requireClosed: flags['require-closed'] === 'true' };
    if (flags['require-closed'] !== undefined && !['true', 'false'].includes(flags['require-closed'])) throw Error('--require-closed must be true or false');
    if (flags.policy) options.policy = await jsonFile(resolve(flags.policy));
    const result = verifyLedger(await jsonFile(resolve(flags.ledger)), options);
    print(result);
    if (!result.valid) process.exitCode = 1;
  },
  async summary(flags) {
    allow(flags, ['ledger']); need(flags, ['ledger']);
    print(summarizeCampaign(await jsonFile(resolve(flags.ledger))));
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
