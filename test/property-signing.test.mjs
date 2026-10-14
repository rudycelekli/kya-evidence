import assert from 'node:assert/strict';
import { sign } from 'node:crypto';
import { canonical, parseJson, signEvidence, verifyEvidence, signIncident, verifyIncident, keyId, digest } from '../src/index.mjs';
import { property, keyPool, hex, randomId, clone } from './helpers-fuzz.mjs';

const iso = n => new Date(n).toISOString();
function randomEvidence(rng) {
  const observed = rng.int(0, 4_000_000_000_000);
  return {
    schema: 'kya.evidence/v1', id: randomId(rng, 128), subjectDigest: hex(rng), scopeId: randomId(rng, 128), profileDigest: hex(rng), evaluatorDigest: hex(rng),
    runId: randomId(rng, 128), checkId: randomId(rng, 128), outcome: rng.pick(['pass', 'fail', 'abstain', 'error']), observedAt: iso(observed), expiresAt: iso(observed + rng.int(1, 10 ** 10)),
    artifactDigest: hex(rng), source: rng.pick(['runtime', 'fixture', 'declaration']),
  };
}
function randomIncident(rng) {
  const kind = rng.pick(['report', 'resolution', 'appeal']), id = randomId(rng, 128);
  let refId = null; if (kind !== 'report') { do { refId = randomId(rng, 128); } while (refId === id); }
  return { schema: 'kya.incident/v1', id, subjectDigest: hex(rng), kind, severity: rng.pick(['low', 'medium', 'high', 'critical']), refId, reportedAt: iso(rng.int(0, 4_000_000_000_000)), detailsDigest: hex(rng) };
}
const flipBit = (buffer, bit) => { const b = Buffer.from(buffer); b[bit >> 3] ^= 1 << (bit & 7); return b; };
const tryVerify = (verify, env) => { try { verify(env); return true; } catch { return false; } };

property('sign then verify round trips random valid evidence and incidents', 50, (rng) => {
  const key = rng.pick(keyPool);
  const e = randomEvidence(rng), env = signEvidence(e, key.privateKey);
  const v = verifyEvidence(env);
  assert.deepEqual(v.payload, e);
  assert.equal(v.keyId, keyId(key.pem));
  assert.equal(env.proof.publicKey, key.pem);
  // survives a text round trip, a key reordering and different but equal inputs
  const text = JSON.stringify(env, null, 1);
  assert.equal(verifyEvidence(parseJson(text)).envelopeDigest, v.envelopeDigest);
  assert.equal(verifyEvidence({ proof: env.proof, payload: Object.fromEntries(rng.shuffle(Object.entries(env.payload))) }).envelopeDigest, v.envelopeDigest);
  // signing is deterministic (Ed25519) and does not depend on key order
  assert.deepEqual(signEvidence(Object.fromEntries(rng.shuffle(Object.entries(e))), key.privateKey), env);
  const inc = randomIncident(rng), ienv = signIncident(inc, key.privateKey), iv = verifyIncident(ienv);
  assert.deepEqual(iv.payload, inc); assert.equal(iv.keyId, v.keyId);
});

property('any single bit flip in the signature fails verification', 25, (rng) => {
  const key = rng.pick(keyPool), env = signEvidence(randomEvidence(rng), key.privateKey), ienv = signIncident(randomIncident(rng), key.privateKey);
  for (const [verify, e] of [[verifyEvidence, env], [verifyIncident, ienv]]) {
    const raw = Buffer.from(e.proof.signature, 'base64url');
    assert.equal(raw.length, 64);
    for (let n = 0; n < 6; n++) {
      const bad = clone(e); bad.proof.signature = flipBit(raw, rng.int(0, 511)).toString('base64url');
      assert.throws(() => verify(bad), Error, 'bit flipped signature verified');
    }
    // flips of the text encoding (including the unused trailing bits) must also fail
    const chars = e.proof.signature.split(''), idx = rng.int(0, chars.length - 1), alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const other = rng.pick([...alphabet].filter(c => c !== chars[idx])); chars[idx] = other;
    const bad = clone(e); bad.proof.signature = chars.join(''); assert.throws(() => verify(bad));
    for (const sig of [e.proof.signature.slice(1), e.proof.signature + 'A', e.proof.signature.replace(/.$/, '='), '', e.proof.signature.toUpperCase() === e.proof.signature ? 'x' : e.proof.signature.toUpperCase(), e.proof.signature.replace(/[-_]/g, c => c === '-' ? '+' : '/') + '=='])
      if (sig !== e.proof.signature) assert.throws(() => verify({ ...e, proof: { ...e.proof, signature: sig } }));
  }
});

property('any single bit flip in the signed payload fails verification or is the same document', 50, (rng) => {
  const key = rng.pick(keyPool);
  const pick = rng.bool();
  const env = pick ? signEvidence(randomEvidence(rng), key.privateKey) : signIncident(randomIncident(rng), key.privateKey);
  const verify = pick ? verifyEvidence : verifyIncident;
  const bytes = Buffer.from(canonical(env.payload), 'utf8');
  for (let n = 0; n < 12; n++) {
    const flipped = flipBit(bytes, rng.int(0, bytes.length * 8 - 1)).toString('utf8');
    let payload; try { payload = parseJson(flipped); } catch { continue; }
    if (canonical(payload) === canonical(env.payload)) continue;
    assert.equal(tryVerify(verify, { payload, proof: env.proof }), false, `flipped payload still verified: ${flipped}`);
  }
  // single-character edits to string members and to timestamps
  const mutated = clone(env.payload); const k = rng.pick(Object.keys(mutated)); const s = mutated[k];
  mutated[k] = typeof s === 'string' && s.length > 1 && rng.bool() ? s.slice(0, -1) + (s.at(-1) === '0' ? '1' : '0') : s;
  if (mutated[k] !== s) assert.equal(tryVerify(verify, { payload: mutated, proof: env.proof }), false);
});

property('swapping the key or the proof fields fails verification', 40, (rng) => {
  const [a, b] = rng.sample(keyPool, 2);
  const env = signEvidence(randomEvidence(rng), a.privateKey), ienv = signIncident(randomIncident(rng), a.privateKey);
  for (const [verify, e] of [[verifyEvidence, env], [verifyIncident, ienv]]) {
    assert.throws(() => verify({ ...e, proof: { ...e.proof, publicKey: b.pem } }), Error, 'public key swapped, keyId kept');
    assert.throws(() => verify({ ...e, proof: { ...e.proof, keyId: keyId(b.pem) } }), Error, 'keyId swapped, public key kept');
    assert.throws(() => verify({ ...e, proof: { ...e.proof, publicKey: b.pem, keyId: keyId(b.pem) } }), Error, 'whole identity swapped');
    // the other signer's genuine signature over a different payload cannot be transplanted
    const other = verify === verifyEvidence ? signEvidence(randomEvidence(rng), b.privateKey) : signIncident(randomIncident(rng), b.privateKey);
    assert.throws(() => verify({ payload: e.payload, proof: other.proof }));
    assert.throws(() => verify({ payload: e.payload, proof: { ...e.proof, algorithm: rng.pick(['ed25519', 'Ed448', 'none', 'RS256', '']) } }));
    assert.throws(() => verify({ payload: e.payload, proof: { ...e.proof, extra: 1 } }));
    assert.throws(() => verify({ payload: e.payload }));
    assert.throws(() => verify({ ...e, extra: true }));
    // a trailing newline or CRLF in the PEM changes the byte form but never the key identity: verification must stay consistent
    const crlf = { ...e, proof: { ...e.proof, publicKey: e.proof.publicKey.replace(/\n/g, '\r\n') } };
    assert.equal(tryVerify(verify, crlf), true);
  }
});

property('an evidence signature never verifies as an incident signature and vice versa', 50, (rng) => {
  const key = rng.pick(keyPool);
  const ev = randomEvidence(rng), inc = randomIncident(rng);
  const evEnv = signEvidence(ev, key.privateKey), incEnv = signIncident(inc, key.privateKey);
  assert.throws(() => verifyIncident(evEnv)); assert.throws(() => verifyEvidence(incEnv));
  // The decisive test is the domain prefix itself: sign the incident payload under the evidence domain and the evidence payload under the incident domain.
  const crossA = { payload: inc, proof: { ...incEnv.proof, signature: sign(null, Buffer.from('kya.evidence/v1\n' + canonical(inc)), key.privateKey).toString('base64url') } };
  const crossB = { payload: ev, proof: { ...evEnv.proof, signature: sign(null, Buffer.from('kya.incident/v1\n' + canonical(ev)), key.privateKey).toString('base64url') } };
  assert.throws(() => verifyIncident(crossA), /signature/i);
  assert.throws(() => verifyEvidence(crossB), /signature/i);
  // no domain prefix, a wrong version prefix and a missing separator are all rejected
  for (const prefix of ['', 'kya.incident/v2\n', 'kya.incident/v1', 'kya.incident/v1\n\n', 'KYA.INCIDENT/V1\n', 'kya.evidence/v1\n']) {
    if (prefix === 'kya.incident/v1\n') continue;
    const s = sign(null, Buffer.from(prefix + canonical(inc)), key.privateKey).toString('base64url');
    assert.throws(() => verifyIncident({ payload: inc, proof: { ...incEnv.proof, signature: s } }), Error, JSON.stringify(prefix));
  }
  // the correctly prefixed signature is the only one that verifies
  const good = sign(null, Buffer.from('kya.incident/v1\n' + canonical(inc)), key.privateKey).toString('base64url');
  assert.equal(good, incEnv.proof.signature);
  assert.notEqual(digest(evEnv), digest(incEnv));
});

property('signing refuses payloads that do not validate and non Ed25519 keys', 40, (rng) => {
  const e = randomEvidence(rng);
  const bad = rng.pick([{ ...e, outcome: 'PASS' }, { ...e, id: '' }, { ...e, extra: 1 }, { ...e, observedAt: e.expiresAt }, { ...e, subjectDigest: e.subjectDigest.toUpperCase() === e.subjectDigest ? 'z' : e.subjectDigest.toUpperCase() }]);
  assert.throws(() => signEvidence(bad, keyPool[0].privateKey));
  assert.throws(() => signIncident({ ...randomIncident(rng), severity: 'urgent' }, keyPool[0].privateKey));
  assert.throws(() => signEvidence(e, keyPool[0].publicKey));
  assert.throws(() => signEvidence(e, 'not a key'));
});

// Ed25519 malleability: (R, S + L) is a second byte string for the same message. Accepting it would give one signed
// object several envelope digests, so verification must insist on the canonical scalar S < L.
const GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
property('malleated Ed25519 signatures (S plus the group order) are rejected', 40, (rng) => {
  const key = rng.pick(keyPool);
  for (const [signer, verify, body] of [[signEvidence, verifyEvidence, randomEvidence(rng)], [signIncident, verifyIncident, randomIncident(rng)]]) {
    const env = signer(body, key.privateKey), raw = Buffer.from(env.proof.signature, 'base64url');
    const s = BigInt('0x' + Buffer.from(raw.subarray(32)).reverse().toString('hex'));
    assert.ok(s < GROUP_ORDER);
    const bumped = Buffer.from(raw);
    Buffer.from((s + GROUP_ORDER).toString(16).padStart(64, '0'), 'hex').reverse().copy(bumped, 32);
    assert.throws(() => verify({ ...env, proof: { ...env.proof, signature: bumped.toString('base64url') } }), Error, 'malleated signature verified');
    assert.equal(tryVerify(verify, env), true);
  }
});
