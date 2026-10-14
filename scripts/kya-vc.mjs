#!/usr/bin/env node
// kya-vc: W3C VC 2.0 export bridge CLI. No network access; every time-dependent command needs an explicit --now.
import { readFile, writeFile } from 'node:fs/promises';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { parseJson } from '../src/shared/canonical.mjs';
import { exportAssessmentCredential, verifyAssessmentCredential, didKeyFromPublicKey, buildStatusListCredential, allocateStatusIndices, revokedLedgerEntries, VcBridgeError } from '../src/vc-bridge/index.mjs';

const HELP = `kya-vc: export KYA assessments as W3C VC 2.0 (vc+jwt, EdDSA, did:key). No network. Not an authorization grant.

  kya-vc did-key --key PRIVATE_PEM | --public PUBLIC_PEM
  kya-vc export --assessment FILE --key PRIVATE_PEM [--valid-from ISO] [--valid-until ISO] [--out FILE]
                [--revocation-list URL --suspension-list URL --status-secret-file FILE --ledger FILE]
  kya-vc verify --jwt FILE --now ISO [--trust-did DID]... [--policy FILE] [--status-list URL=FILE]... [--require-status]
  kya-vc status-list --purpose revocation|suspension --url URL --ledger FILE --policy FILE --key PRIVATE_PEM
                --now ISO [--suspended-subject DIGEST]... [--size N] [--out FILE]

A valid signature proves key possession, not truthful execution, human identity or authorization.
`;

function parseArgs(argv) {
  const flags = {}, multi = new Set(['trust-did', 'status-list', 'suspended-subject']), bool = new Set(['require-status']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; if (!a.startsWith('--')) throw Error(`Unexpected argument ${a}`);
    const k = a.slice(2);
    if (bool.has(k)) { flags[k] = true; continue; }
    const v = argv[++i]; if (v === undefined || v.startsWith('--')) throw Error(`Missing value for --${k}`);
    if (multi.has(k)) (flags[k] ??= []).push(v); else { if (k in flags) throw Error(`Duplicate --${k}`); flags[k] = v; }
  }
  return flags;
}
const need = (f, ...ks) => { for (const k of ks) if (f[k] === undefined) throw Error(`--${k} is required`); };
const readJson = async p => parseJson(await readFile(p, 'utf8'));
const out = async (f, value) => { const text = JSON.stringify(value, null, 2) + '\n'; if (f.out) await writeFile(f.out, text); else process.stdout.write(text); };

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === '--help' || cmd === 'help') { process.stdout.write(HELP); return 0; }
  const f = parseArgs(rest);
  if (cmd === 'did-key') {
    if (f.key) return await out(f, { did: didKeyFromPublicKey(createPublicKey(createPrivateKey(await readFile(f.key)))) }), 0;
    need(f, 'public'); return await out(f, { did: didKeyFromPublicKey(createPublicKey(await readFile(f.public))) }), 0;
  }
  if (cmd === 'export') {
    need(f, 'assessment', 'key');
    const options = { issuerKey: createPrivateKey(await readFile(f.key)), ...(f['valid-from'] ? { validFrom: f['valid-from'] } : {}), ...(f['valid-until'] ? { validUntil: f['valid-until'] } : {}) };
    const assessment = await readJson(f.assessment);
    let ledger;
    if (f['revocation-list'] || f['suspension-list'] || f.ledger) {
      need(f, 'revocation-list', 'suspension-list', 'status-secret-file', 'ledger');
      ledger = await readFile(f.ledger, 'utf8').then(t => parseJson(t), e => { if (e.code === 'ENOENT') return []; throw e; });
      const indices = allocateStatusIndices({ secret: (await readFile(f['status-secret-file'], 'utf8')).trim(), reportDigest: assessment.reportDigest, ledger });
      options.status = { revocation: { statusListCredential: f['revocation-list'], statusListIndex: indices.revocation }, suspension: { statusListCredential: f['suspension-list'], statusListIndex: indices.suspension } };
      var pendingIndices = indices;
    }
    const result = exportAssessmentCredential(assessment, options);
    if (ledger) {
      if (!ledger.some(e => e.reportDigest === result.ledgerEntry.reportDigest)) ledger.push({ ...result.ledgerEntry, indices: pendingIndices });
      await writeFile(f.ledger, JSON.stringify(ledger, null, 2) + '\n');
    }
    if (f.out) { await writeFile(f.out, result.jwt + '\n'); await out({}, { jwt: f.out, issuer: result.issuer, reportDigest: result.ledgerEntry.reportDigest, statusIndices: pendingIndices ?? null }); }
    else process.stdout.write(result.jwt + '\n');
    return 0;
  }
  if (cmd === 'verify') {
    need(f, 'jwt', 'now');
    const statusLists = {};
    for (const spec of f['status-list'] ?? []) { const i = spec.indexOf('='); if (i < 1) throw Error('--status-list needs URL=FILE'); statusLists[spec.slice(0, i)] = (await readFile(spec.slice(i + 1), 'utf8')).trim(); }
    const result = verifyAssessmentCredential((await readFile(f.jwt, 'utf8')).trim(), { now: f.now, expectedIssuerKeys: f['trust-did'] ?? [], policy: f.policy ? await readJson(f.policy) : undefined, statusLists, requireStatusCheck: f['require-status'] === true });
    await out(f, result);
    return result.valid ? 0 : 1;
  }
  if (cmd === 'status-list') {
    need(f, 'purpose', 'url', 'ledger', 'policy', 'key', 'now');
    const ledger = await readJson(f.ledger), policy = await readJson(f.policy);
    const hit = revokedLedgerEntries(ledger, policy);
    const suspended = new Set(f['suspended-subject'] ?? []);
    const chosen = f.purpose === 'revocation' ? hit : f.purpose === 'suspension' ? ledger.filter(e => suspended.has(e.subjectDigest)) : (() => { throw Error('--purpose must be revocation or suspension'); })();
    const built = buildStatusListCredential({ issuerKey: createPrivateKey(await readFile(f.key)), id: f.url, purpose: f.purpose, indices: chosen.map(e => e.indices[f.purpose]), validFrom: f.now, ...(f.size ? { size: Number(f.size) } : {}) });
    if (f.out) { await writeFile(f.out, built.jwt + '\n'); await out({}, { out: f.out, purpose: f.purpose, setBits: chosen.length, issuer: built.issuer }); }
    else process.stdout.write(built.jwt + '\n');
    return 0;
  }
  throw Error(`Unknown command ${cmd}`);
}

main().then(code => { process.exitCode = code; }, e => {
  process.stderr.write(JSON.stringify({ error: e.message, code: e instanceof VcBridgeError ? e.code : undefined }) + '\n');
  process.exitCode = 2;
});
