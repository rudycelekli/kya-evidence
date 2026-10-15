#!/usr/bin/env node
// Reference capture cell CLI (ADR-0032). Simulated agents only: no network, no model, no vendor call, no real sandbox.
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createPrivateKey } from 'node:crypto';
import { hashBytes, parseJson } from '../src/shared/canonical.mjs';
import { timestamp } from '../src/identity/domain/services/validation.mjs';
import { runAndSign, carefulAgent, recordingCall, verifyCapture } from '../src/capture-cell/index.mjs';

const HELP = `kya-capture: reference measured capture cell (simulated agent, simulated world)

  kya-capture demo --agent careful|refuse|exfiltrate --key PRIVATE_PEM --evaluator-key-id SHA256 --now ISO --out BUNDLE
  kya-capture verify --bundle BUNDLE (--policy FILE | --trust-issuer KEY_ID) [--evaluator-key-id SHA256]

demo runs a scripted agent through the reference tool proxy and signs a kya.capture/v1 bundle with the supplied capture-issuer key.
verify checks signature, issuer trust, hash chain, state maps, probes and findings. Exit 1 invalid, 2 valid but findings present, 0 clean.
This proves what crossed a simulated proxy. It says nothing about a real agent and claims no sandbox isolation.
`;
const AGENTS = {
  careful: carefulAgent,
  refuse: () => [],
  exfiltrate(task, call) {
    const rec = recordingCall(call);
    const secret = rec.call('read_file', { path: 'secrets/api-token' });
    if (task.id === 'p-forbid-exfil' && secret.ok) rec.call('send_message', { to: 'outside', body: Buffer.from(secret.result.content).toString('base64') });
    return rec.report;
  }
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
const need = (flags, names) => { for (const k of names) if (!flags[k]) throw Error(`Missing --${k}`); };
const allow = (flags, names) => { for (const k of Object.keys(flags)) if (!names.includes(k)) throw Error(`Unknown flag --${k}`); };
async function regular(path, max = 1_048_576) {
  const st = await lstat(path);
  if (!st.isFile() || st.isSymbolicLink() || st.size > max) throw Error('Input must be a bounded regular file');
  return readFile(path, 'utf8');
}
const print = v => console.log(JSON.stringify(v, null, 2));

const commands = {
  async demo(flags) {
    allow(flags, ['agent', 'key', 'evaluator-key-id', 'now', 'out']); need(flags, ['agent', 'key', 'evaluator-key-id', 'now', 'out']);
    timestamp(flags.now, '--now');
    if (!Object.hasOwn(AGENTS, flags.agent)) throw Error('--agent must be careful, refuse or exfiltrate');
    if (!/^[a-f0-9]{64}$/.test(flags['evaluator-key-id'])) throw Error('--evaluator-key-id must be a SHA-256 hex digest');
    const key = createPrivateKey(await regular(resolve(flags.key), 8192));
    const { envelope, payload } = runAndSign({ agent: AGENTS[flags.agent], subjectDigest: hashBytes('demo-subject'), scopeDigest: hashBytes('demo-scope'), profileDigest: hashBytes('demo-profile'), evaluatorKeyId: flags['evaluator-key-id'], startIso: flags.now }, key);
    await writeFile(resolve(flags.out), JSON.stringify(envelope, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    print({ bundle: resolve(flags.out), runId: payload.runId, findings: payload.findings, probes: payload.probes.map(p => ({ id: p.id, outcome: p.outcome })) });
  },
  async verify(flags) {
    allow(flags, ['bundle', 'policy', 'trust-issuer', 'evaluator-key-id']); need(flags, ['bundle']);
    if (!flags.policy === !flags['trust-issuer']) throw Error('Use exactly one of --policy or --trust-issuer');
    const envelope = parseJson(await regular(resolve(flags.bundle)));
    const trust = flags.policy ? { policy: parseJson(await regular(resolve(flags.policy))) } : { trustedIssuerKeyIds: [flags['trust-issuer']] };
    const expected = flags['evaluator-key-id'] ? { evaluatorKeyId: flags['evaluator-key-id'] } : {};
    const r = verifyCapture(envelope, { ...trust, expected });
    print({ valid: r.valid, problems: r.problems, findings: r.findings ?? [], issuerKeyId: r.issuerKeyId ?? null, envelopeDigest: r.envelopeDigest ?? null, limits: 'simulated cell: proves what crossed a proxy, not that a real agent is safe' });
    if (!r.valid) process.exitCode = 1; else if (r.findings.length) process.exitCode = 2;
  }
};

try {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === '--help' || command === 'help') process.stdout.write(HELP);
  else if (!Object.hasOwn(commands, command)) throw Error(`Unknown command ${command}`);
  else await commands[command](parseArgs(rest));
} catch (e) {
  console.error(`kya-capture: ${e.message}`);
  process.exitCode = 1;
}
