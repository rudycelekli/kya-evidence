import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { verifyEvidence } from '../src/index.mjs';
import { runVectors } from '../scripts/run-vectors.mjs';
import { verifyProof } from '../interop/second-impl/kya2.mjs';
import { keys, payload, publicKey } from './helpers.mjs';
import { signEvidence } from '../src/index.mjs';

// The core refuses non-canonical spellings of a public key and small-order or non-canonical Ed25519 points.
// The second implementation (JavaScript) and the Python checker are same-team code; they are held to the same
// acceptance rule here, written separately in each file (no src/ import in either). These tests feed all three
// the same envelopes and require the same accept or reject decision.
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const PY = join(ROOT, 'interop/python/kya_portability.py');
const HEAD = '-----BEGIN PUBLIC KEY-----', TAIL = '-----END PUBLIC KEY-----';
const PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const sha = b => createHash('sha256').update(b).digest('hex');
const pemOfDer = (der, width = 60) => HEAD + '\n' + der.toString('base64').replace(new RegExp(`(.{${width}})`, 'g'), '$1\n').replace(/\n$/, '') + '\n' + TAIL + '\n';
const derOfRaw = raw => Buffer.concat([PREFIX, raw]);
const hex = h => Buffer.from(h, 'hex');

const BASE = signEvidence(payload(), keys.privateKey);
const GOOD_PEM = publicKey;
const GOOD_DER = Buffer.from(GOOD_PEM.split('\n')[1], 'base64');
assert.equal(pemOfDer(GOOD_DER), GOOD_PEM);

const withKey = (pem, der, extra = {}) => ({ payload: BASE.payload, proof: { ...BASE.proof, publicKey: pem, keyId: sha(der), ...extra } });
const withProof = patch => ({ payload: BASE.payload, proof: { ...BASE.proof, ...patch } });

const b64 = GOOD_DER.toString('base64');
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const trailingBits = HEAD + '\n' + b64.slice(0, 58) + ALPHA[(ALPHA.indexOf(b64[58]) + 1) % 64] + '=' + '\n' + TAIL + '\n';
const longFormDer = Buffer.concat([Buffer.from([0x30, 0x81, GOOD_DER[1]]), GOOD_DER.subarray(2)]);
const trailingDer = n => Buffer.concat([GOOD_DER, Buffer.alloc(n)]);

// Sloppy spellings of the same key, and of tampered DER.
const SPELLINGS = {
  crlf: [GOOD_PEM.replace(/\n/g, '\r\n'), GOOD_DER],
  wrapped40: [pemOfDer(GOOD_DER, 40), GOOD_DER],
  wrapped30: [pemOfDer(GOOD_DER, 30), GOOD_DER],
  wrapped59: [HEAD + '\n' + b64.slice(0, 59) + '\n' + b64.slice(59) + '\n' + TAIL + '\n', GOOD_DER],
  noTrailingNewline: [GOOD_PEM.replace(/\n$/, ''), GOOD_DER],
  doubleTrailingNewline: [GOOD_PEM + '\n', GOOD_DER],
  leadingNewline: ['\n' + GOOD_PEM, GOOD_DER],
  leadingSpace: [' ' + GOOD_PEM, GOOD_DER],
  trailingSpace: [GOOD_PEM.replace(/\n$/, ' \n'), GOOD_DER],
  blankLineInBase64: [HEAD + '\n\n' + b64 + '\n' + TAIL + '\n', GOOD_DER],
  blankLineAfterBase64: [HEAD + '\n' + b64 + '\n\n' + TAIL + '\n', GOOD_DER],
  splitWithBlank: [HEAD + '\n' + b64.slice(0, 30) + '\n\n' + b64.slice(30) + '\n' + TAIL + '\n', GOOD_DER],
  tabInBase64: [HEAD + '\n' + b64.slice(0, 30) + '\t' + b64.slice(30) + '\n' + TAIL + '\n', GOOD_DER],
  nonCanonicalTrailingBits: [trailingBits, GOOD_DER],
  longFormDerLength: [pemOfDer(longFormDer), longFormDer],
  trailingZero1: [pemOfDer(trailingDer(1)), trailingDer(1)],
  trailingZero2: [pemOfDer(trailingDer(2)), trailingDer(2)],
  trailingZero8: [pemOfDer(trailingDer(8)), trailingDer(8)],
  headerLowerCase: [GOOD_PEM.replace('BEGIN PUBLIC KEY', 'begin public key'), GOOD_DER],
  wrongLabel: [GOOD_PEM.replace(/PUBLIC KEY/g, 'PUBLIC  KEY'), GOOD_DER],
  barePrivateLabel: [GOOD_PEM.replace(/PUBLIC KEY/g, 'PRIVATE KEY'), GOOD_DER]
};
const SMALL_ORDER = {
  identityPoint: '01' + '00'.repeat(31),
  orderTwoPoint: 'ec' + 'ff'.repeat(30) + '7f',
  orderFourZeroY: '00'.repeat(32),
  orderFourZeroYSign: '00'.repeat(31) + '80',
  orderEightA: 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  orderEightB: 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  orderEightC: '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  orderEightD: '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85'
};
const NON_CANONICAL = {
  yEqualsPrime: 'ed' + 'ff'.repeat(30) + '7f',
  yEqualsPrimePlusOne: 'ee' + 'ff'.repeat(30) + '7f',
  yEqualsPrimePlusOneSign: 'ee' + 'ff'.repeat(30) + 'ff',
  yEqualsPrimePlusTwo: 'ef' + 'ff'.repeat(30) + '7f',
  identityWithSignBit: '01' + '00'.repeat(30) + '80',
  yAllOnes: 'ff'.repeat(32),
  yEqualsPrimePlusEighteen: 'ff' + 'ff'.repeat(30) + '7f'
};
const SIG_IDENTITY = Buffer.concat([Buffer.from([1]), Buffer.alloc(63)]).toString('base64url');
const pointEnvelope = (rawHex, signature = SIG_IDENTITY) => { const der = derOfRaw(hex(rawHex)); return withKey(pemOfDer(der), der, { signature }); };

// Every case: name -> envelope.
const CASES = { canonicalKey: BASE };
for (const [name, [pem, der]] of Object.entries(SPELLINGS)) CASES['spelling:' + name] = withKey(pem, der);
for (const [name, h] of Object.entries(SMALL_ORDER)) CASES['smallOrder:' + name] = pointEnvelope(h);
for (const [name, h] of Object.entries(NON_CANONICAL)) CASES['nonCanonicalPoint:' + name] = pointEnvelope(h);
const sigFlip = BASE.proof.signature.slice(0, 85) + (BASE.proof.signature[85] === 'A' ? 'B' : 'A');
Object.assign(CASES, {
  'proof:signatureLastCharChanged': withProof({ signature: sigFlip }),
  'proof:signatureStandardBase64': withProof({ signature: BASE.proof.signature.replace(/-/g, '+') + '=' }),
  'proof:signaturePadded': withProof({ signature: BASE.proof.signature + '==' }),
  'proof:signatureShort': withProof({ signature: BASE.proof.signature.slice(0, 80) }),
  'proof:signatureEmpty': withProof({ signature: '' }),
  'proof:signatureNonString': withProof({ signature: 7 }),
  'proof:keyIdUpperCase': withProof({ keyId: BASE.proof.keyId.toUpperCase() }),
  'proof:keyIdOtherKey': withProof({ keyId: sha(Buffer.from('other')) }),
  'proof:algorithmLowerCase': withProof({ algorithm: 'ed25519' }),
  'proof:extraMember': withProof({ extra: 1 }),
  'payload:outcomeChanged': { payload: { ...BASE.payload, outcome: 'fail' }, proof: BASE.proof },
  'payload:idChanged': { payload: { ...BASE.payload, id: 'evidence-changed' }, proof: BASE.proof },
  'key:otherEd25519KeyWrongSignature': (() => { const der = derOfRaw(hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')); return withKey(pemOfDer(der), der); })()
});
for (const w of [10, 15, 20, 25, 45, 50]) CASES['spelling:wrappedAt' + w] = withKey(pemOfDer(GOOD_DER, w), GOOD_DER);
for (const k of [1, 2, 3]) CASES['spelling:trailingBitsPlus' + k] = withKey(HEAD + '\n' + b64.slice(0, 58) + ALPHA[(ALPHA.indexOf(b64[58]) + k) % 64] + '=\n' + TAIL + '\n', GOOD_DER);
for (const [name, h] of Object.entries(SMALL_ORDER)) CASES['smallOrderRealSignature:' + name] = pointEnvelope(h, BASE.proof.signature);
const NAMES = Object.keys(CASES);

// Decisions.
const coreAccepts = env => { try { verifyEvidence(JSON.parse(JSON.stringify(env))); return true; } catch { return false; } };
const secondAccepts = env => verifyProof('kya.evidence/v1\n', env.payload, env.proof) === null;
const PY_SCRIPT = [
  'import json, runpy, sys',
  'm = runpy.run_path(sys.argv[1])',
  'out = []',
  'for e in json.load(sys.stdin):',
  '    try:',
  '        r = m["signature_bytes"](e, True)',
  '        out.append("accept" if r["status"] == "verified" else "unverified")',
  '    except m["InvalidValue"]:',
  '        out.append("reject")',
  'print(json.dumps(out))'
].join('\n');
const pyRun = spawnSync('python3', ['-I', '-c', PY_SCRIPT, PY], { input: JSON.stringify(NAMES.map(n => CASES[n])), encoding: 'utf8' });
const PYTHON = pyRun.status === 0 ? JSON.parse(pyRun.stdout) : null;
const pyDecision = name => PYTHON?.[NAMES.indexOf(name)];
const pyAccepts = name => pyDecision(name) === 'accept';

test('python helper ran and python has the optional signature backend', () => {
  assert.equal(pyRun.status, 0, pyRun.stderr);
  assert.equal(PYTHON.length, NAMES.length);
  assert.equal(pyDecision('canonicalKey'), 'accept');
});

test('canonical key is accepted by the core, the second implementation and python', () => {
  assert.equal(coreAccepts(CASES.canonicalKey), true);
  assert.equal(secondAccepts(CASES.canonicalKey), true);
  assert.equal(pyAccepts('canonicalKey'), true);
});

const refusedEverywhere = name => {
  assert.equal(coreAccepts(CASES[name]), false, 'core ' + name);
  assert.equal(secondAccepts(CASES[name]), false, 'second-impl ' + name);
  assert.equal(pyAccepts(name), false, 'python ' + name);
};

test('crlf line endings in the key PEM are refused by all three', () => refusedEverywhere('spelling:crlf'));
test('re-wrapped key PEM lines are refused by all three', () => {
  for (const n of ['wrapped40', 'wrapped30', 'wrapped59']) refusedEverywhere('spelling:' + n);
});
test('missing trailing newline in the key PEM is refused by all three', () => refusedEverywhere('spelling:noTrailingNewline'));
test('extra surrounding whitespace in the key PEM is refused by all three', () => {
  for (const n of ['doubleTrailingNewline', 'leadingNewline', 'leadingSpace', 'trailingSpace']) refusedEverywhere('spelling:' + n);
});
test('blank line inside the base64 body is refused by all three', () => {
  for (const n of ['blankLineInBase64', 'blankLineAfterBase64', 'splitWithBlank', 'tabInBase64']) refusedEverywhere('spelling:' + n);
});
test('non-canonical trailing base64 bits are refused by all three', () => refusedEverywhere('spelling:nonCanonicalTrailingBits'));
test('long-form DER length is refused by all three', () => refusedEverywhere('spelling:longFormDerLength'));
test('trailing zero bytes after the SPKI are refused by all three', () => {
  for (const n of ['trailingZero1', 'trailingZero2', 'trailingZero8']) refusedEverywhere('spelling:' + n);
});
test('wrong PEM labels are refused by all three', () => {
  for (const n of ['headerLowerCase', 'wrongLabel', 'barePrivateLabel']) refusedEverywhere('spelling:' + n);
});
test('identity point key with signature 01 followed by zeros is refused by all three', () => refusedEverywhere('smallOrder:identityPoint'));
test('every small-order Ed25519 point is refused by all three', () => {
  for (const n of Object.keys(SMALL_ORDER)) refusedEverywhere('smallOrder:' + n);
});
test('non-canonical y encodings are refused by all three', () => {
  for (const n of Object.keys(NON_CANONICAL)) refusedEverywhere('nonCanonicalPoint:' + n);
});

test('a bad signature on a canonical key is still refused after strictness changes', () => {
  refusedEverywhere('proof:signatureLastCharChanged');
  refusedEverywhere('payload:outcomeChanged');
});

test('second implementation still matches all 111 assessment vectors', async () => {
  const { summary, outcomes } = await runVectors({
    impl: `"${process.execPath}" "${join(ROOT, 'interop/second-impl/adapter.mjs')}"`,
    vectorsFile: join(ROOT, 'evidence/assessment-vectors.json'), name: 'second-impl', language: 'javascript', implVersion: '0.1', semanticOnly: true
  });
  assert.deepEqual(outcomes.filter(o => o.status !== 'semantic-pass').map(o => `${o.id}: ${o.detail}`), []);
  assert.equal(summary.vectors.total, 111);
  assert.equal(summary.vectors.semanticPass, 111);
});

test('differential run over at least 60 mutated envelopes agrees across core, second implementation and python', () => {
  // Byte-layer-only divergence, intentional and excluded: python checks the proof bytes and the signature, not the
  // payload schema, so payload members are only mutated while staying schema-valid (the tamper cases above keep a
  // valid payload shape and fail on the signature in every implementation).
  assert.ok(NAMES.length >= 60, `only ${NAMES.length} mutated envelopes`);
  const disagreements = [];
  for (const name of NAMES) {
    const c = coreAccepts(CASES[name]), s = secondAccepts(CASES[name]), p = pyAccepts(name);
    if (c !== s || c !== p) disagreements.push(`${name}: core=${c} second=${s} python=${p}`);
  }
  assert.deepEqual(disagreements, []);
  assert.equal(NAMES.filter(n => coreAccepts(CASES[n])).length, 1, 'only the canonical envelope may be accepted');
});
