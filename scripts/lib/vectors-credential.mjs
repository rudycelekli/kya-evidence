import { createPrivateKey, createPublicKey, createHmac, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { exportAssessmentCredential, buildStatusListCredential, didKeyFromPublicKey, base58btcEncode, encodeList, createBitstring, setBit } from '../../src/vc-bridge/index.mjs';
import { assertValidEd25519Point } from '../../src/shared/ed25519-point.mjs';

// Vectors for the contract operation verify-credential (docs/SPECIFICATION.md, "Credential verification").
// Keys are PUBLIC SYNTHETIC: seeds are SHA-256 of a published string. Every claim below is written by hand and checked against the reference
// by the generator. Called by scripts/assessment-vectors.mjs with its helpers.
export const CREDENTIAL_KEY_NAMES = ['issuer', 'other'];

export function credentialKeys(hashBytes) {
  const keys = {};
  for (const name of CREDENTIAL_KEY_NAMES) {
    const seedHex = hashBytes('kya.assessment-vectors/v2 public synthetic credential key seed: ' + name);
    const priv = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + seedHex, 'hex'), format: 'der', type: 'pkcs8' });
    const pub = createPublicKey(priv);
    keys[name] = { name, seedHex, priv, pub, pem: pub.export({ format: 'pem', type: 'spki' }).toString(), did: didKeyFromPublicKey(pub), raw: Buffer.from(pub.export({ format: 'jwk' }).x, 'base64url') };
  }
  return keys;
}

export function defineCredentialVectors({ O, OR, clone, REFUSE, world, assess, hashBytes, digest, keyId, PO0 }) {
  const K = credentialKeys(hashBytes), ISS = K.issuer, OTH = K.other;
  const VNOW = '2026-10-14T13:00:00.000Z';
  const CTX = 'https://www.w3.org/ns/credentials/v2';
  const URL_R = 'https://status.example.test/revocation', URL_S = 'https://status.example.test/suspension';
  const LIST_FROM = '2026-10-14T12:00:00.000Z', LIST_UNTIL = '2026-10-15T00:00:00.000Z';
  const b = x => Buffer.from(x).toString('base64url');
  const frag = did => did.slice('did:key:'.length);
  const hdr = (k, o = {}) => ({ alg: 'EdDSA', typ: 'vc+jwt', cty: 'vc', kid: `${k.did}#${frag(k.did)}`, ...o });

  // Build a compact token. header and payload are objects (JSON.stringify), rawHeader and rawPayload are exact text or bytes,
  // sig is exact signature bytes, mut edits the three base64url segments last.
  function tok(payload, o = {}) {
    const key = o.key ?? ISS;
    const parts = [b(o.rawHeader ?? JSON.stringify(o.header ?? hdr(key))), b(o.rawPayload ?? JSON.stringify(payload)), ''];
    const input = `${parts[0]}.${parts[1]}`;
    parts[2] = b(o.sig ?? o.signWith?.(Buffer.from(input)) ?? sign(null, Buffer.from(input), (o.sigKey ?? key).priv));
    o.mut?.(parts);
    return parts.join('.');
  }

  // ---- the assessments and credentials ----
  const wR = world(), R = assess({ manifest: wR.manifest, profile: wR.profile, policy: wR.policy, evidence: wR.evidence, evaluatorDigest: wR.evaluatorDigest, now: wR.now });
  const wF = world({ p: p => ({ ...p, allowedSources: ['runtime', 'fixture'] }), ev: t => t.all({ source: 'fixture' }) });
  const RF = assess({ manifest: wF.manifest, profile: wF.profile, policy: wF.policy, evidence: wF.evidence, evaluatorDigest: wF.evaluatorDigest, now: wF.now });
  if (R.evidenceMode !== 'runtime' || RF.evidenceMode !== 'fixture') throw Error('credential vectors need a runtime and a fixture report');
  const STATUS = { revocation: { statusListCredential: URL_R, statusListIndex: 4242 }, suspension: { statusListCredential: URL_S, statusListIndex: 77 } };
  const EXP = exportAssessmentCredential(R, { issuerKey: ISS.priv });
  const EXP_S = exportAssessmentCredential(R, { issuerKey: ISS.priv, status: STATUS });
  const EXP_F = exportAssessmentCredential(RF, { issuerKey: ISS.priv });
  const P = EXP.credential, P_S = EXP_S.credential, P_F = EXP_F.credential;
  const good = EXP.jwt;
  const edit = (base, f) => { const c = clone(base); f(c); return c; };
  const S = (base, f, o) => tok(edit(base, f), o);   // re-signed edit: the signature is valid, the content is not
  const inputs = (over = {}) => () => ({ jwt: good, now: VNOW, expectedIssuers: [], policy: null, statusLists: {}, requireStatusCheck: false, report: null, ...(typeof over === 'function' ? over() : over) });
  const VC = (name, reqs, description, rationale, over, claim) => O('verify-credential.' + name, 'verify-credential', reqs, description, rationale, inputs(over), claim);
  const VCR = (name, reqs, description, rationale, over) => O('verify-credential.refuse-' + name, 'verify-credential', reqs, description, rationale, inputs(over), REFUSE);
  const fail = (code, more = {}) => ({ valid: false, errors: [code], authenticated: false, ...more });
  const openFail = code => fail(code, { issuer: null, issuerTrust: null, issuerRole: null, status: null, reportChecked: false, reportMismatch: [] });

  // ---- valid credentials ----
  VC('valid-unchecked-issuer', ['KYA-VCB-005', 'KYA-VCB-006'], 'A credential signed by its did:key issuer, verified inside its window with no trust input.', 'KYA-VCB-005: a valid signature reports authenticated false; KYA-VCB-006: with no expected issuer and no policy the trust is unchecked, not inferred.', {}, { valid: true, errors: [], authenticated: false, issuer: ISS.did, issuerTrust: 'unchecked', issuerRole: null, reportChecked: false, reportMismatch: [], status: { checked: false, entries: [] } });
  VC('valid-with-expected-issuer', ['KYA-VCB-006'], 'The issuer is among the expected issuer keys.', 'KYA-VCB-006: trust is relative to the keys the relying party names.', { expectedIssuers: [OTH.did, ISS.did] }, { valid: true, errors: [], issuerTrust: 'expected' });
  VC('valid-anchored-by-policy', ['KYA-VCB-006'], 'The issuer key is a non-revoked trust anchor of the supplied policy.', 'KYA-VCB-006: policy-relative trust reports the anchor role.', () => ({ policy: policyWith(ISS, 'independent') }), { valid: true, errors: [], issuerTrust: 'anchored', issuerRole: 'independent' });
  VC('valid-anchored-and-expected', ['KYA-VCB-006'], 'The issuer is both an expected issuer and a policy anchor with the capture-issuer role.', 'KYA-VCB-006: a policy anchor outranks the expected-key trust level and its role is passed through.', () => ({ expectedIssuers: [ISS.did], policy: policyWith(ISS, 'capture-issuer') }), { valid: true, errors: [], issuerTrust: 'anchored', issuerRole: 'capture-issuer' });
  VC('valid-issuer-as-object', ['KYA-VCB-005'], 'The credential issuer is an object whose id is the did:key.', 'KYA-VCB-005: the issuer may be a string or an object with a string id; the signature is judged under that did:key.', { jwt: S(P, c => { c.issuer = { id: ISS.did, name: 'synthetic' }; }) }, { valid: true, errors: [], issuer: ISS.did });
  VC('valid-without-valid-until', ['KYA-VCB-006'], 'The credential has no validUntil.', 'KYA-VCB-006: an absent validUntil means no end of the window.', { jwt: S(P, c => { delete c.validUntil; }), now: '2030-01-01T00:00:00.000Z' }, { valid: true, errors: [] });
  VC('valid-without-cty', ['KYA-VCB-004'], 'The header omits cty.', 'KYA-VCB-004: cty is optional, and when present must be vc.', { jwt: tok(P, { header: { alg: 'EdDSA', typ: 'vc+jwt', kid: hdr(ISS).kid } }) }, { valid: true, errors: [] });
  VC('valid-fixture-credential', ['KYA-VCB-002'], 'A fixture credential carrying the fixture limitation.', 'KYA-VCB-002: fixture evidence is accepted only with its fixture limitation.', { jwt: EXP_F.jwt }, { valid: true, errors: [] });

  // ---- validity window ----
  VC('window-starts-at-valid-from', ['KYA-VCB-006'], 'The supplied time equals validFrom.', 'KYA-VCB-006: the window includes its start.', { now: R.assessedAt }, { valid: true, errors: [] });
  VC('window-before-valid-from', ['KYA-VCB-006'], 'The supplied time is one millisecond before validFrom.', 'KYA-VCB-006: the window is enforced at the supplied time.', { now: '2026-10-14T11:59:59.999Z' }, openFail('NOT_YET_VALID'));
  VC('window-last-millisecond', ['KYA-VCB-006'], 'The supplied time is one millisecond before validUntil.', 'KYA-VCB-006: the window includes every instant before its end.', { now: new Date(Date.parse(P.validUntil) - 1).toISOString() }, { valid: true, errors: [] });
  VC('window-ends-at-valid-until', ['KYA-VCB-006'], 'The supplied time equals validUntil.', 'KYA-VCB-006: the window excludes its end.', { now: P.validUntil }, openFail('EXPIRED'));
  VC('window-exp-passed', ['KYA-VCB-006'], 'The payload carries an exp claim in the past inside an otherwise valid window.', 'KYA-VCB-006: a JWT exp claim is enforced as well as validUntil.', { jwt: S(P, c => { c.exp = Date.parse(VNOW) / 1000 - 10; }) }, openFail('EXPIRED'));
  VC('window-exp-equal-to-now', ['KYA-VCB-006'], 'The exp claim equals the supplied time in seconds.', 'KYA-VCB-006: at or after exp is expired.', { jwt: S(P, c => { c.exp = Date.parse(VNOW) / 1000; }) }, openFail('EXPIRED'));
  VC('window-exp-one-second-later', ['KYA-VCB-006'], 'The exp claim is one second after the supplied time.', 'KYA-VCB-006: before exp is valid.', { jwt: S(P, c => { c.exp = Date.parse(VNOW) / 1000 + 1; }) }, { valid: true, errors: [] });
  VC('window-exp-is-a-string', ['KYA-VCB-006'], 'The exp claim is a string.', 'KYA-VCB-006: a malformed exp is not ignored.', { jwt: S(P, c => { c.exp = '9999999999'; }) }, openFail('EXPIRED'));
  VC('window-nbf-in-the-future', ['KYA-VCB-006'], 'The nbf claim is one second after the supplied time.', 'KYA-VCB-006: a JWT nbf claim is enforced.', { jwt: S(P, c => { c.nbf = Date.parse(VNOW) / 1000 + 1; }) }, openFail('NOT_YET_VALID'));
  VC('window-valid-until-equals-valid-from', ['KYA-VCB-006'], 'validUntil equals validFrom.', 'KYA-VCB-006: a window must have positive length.', { jwt: S(P, c => { c.validUntil = c.validFrom; }) }, openFail('PAYLOAD_INVALID'));
  VC('window-valid-from-is-a-date', ['KYA-VCB-006'], 'validFrom is a date without a time.', 'KYA-VCB-006: times are exact UTC timestamps.', { jwt: S(P, c => { c.validFrom = '2026-10-14'; }) }, openFail('TIME_INVALID'));
  VC('window-valid-until-is-null', ['KYA-VCB-006'], 'validUntil is present and null.', 'KYA-VCB-006: only an absent validUntil means no end; null is malformed.', { jwt: S(P, c => { c.validUntil = null; }) }, openFail('TIME_INVALID'));
  VC('window-now-is-not-a-timestamp', ['KYA-VCB-006'], 'The supplied time is not a timestamp and the token is garbage.', 'KYA-VCB-006: the supplied time is judged first, so an unusable time is never read as a verdict on the token.', { jwt: 'x', now: 'yesterday' }, openFail('TIME_INVALID'));

  // ---- issuer trust ----
  VC('trust-issuer-not-expected', ['KYA-VCB-006'], 'Expected issuers name only another key.', 'KYA-VCB-006: a valid signature by an unexpected issuer is not accepted.', { expectedIssuers: [OTH.did] }, openFail('ISSUER_NOT_EXPECTED'));
  VC('trust-policy-without-the-issuer', ['KYA-VCB-006'], 'A policy whose anchors do not include the issuer.', 'KYA-VCB-006: a signature alone never makes the issuer trusted; the policy must anchor it.', () => ({ policy: policyWith(OTH, 'independent') }), { valid: false, errors: ['ISSUER_NOT_TRUSTED'], issuerTrust: 'unchecked', issuerRole: null });
  VC('trust-policy-anchor-revoked', ['KYA-VCB-006'], 'The issuer is an anchor of the policy and its key is also revoked there.', 'KYA-VCB-006: a revoked anchor is not trusted.', () => ({ policy: { ...policyWith(ISS, 'independent'), revokedKeyIds: [keyId(ISS.pem)] } }), { valid: false, errors: ['ISSUER_NOT_TRUSTED'], issuerRole: null });
  VC('trust-expected-fails-before-the-policy', ['KYA-VCB-006'], 'The issuer is an anchor but expected issuers name another key.', 'KYA-VCB-006: the expected issuer check is part of opening and is judged before policy trust.', () => ({ expectedIssuers: [OTH.did], policy: policyWith(ISS, 'independent') }), openFail('ISSUER_NOT_EXPECTED'));

  // ---- header and token form ----
  VC('alg-none', ['KYA-VCB-004'], 'The header names alg none and the signature is empty.', 'KYA-VCB-004: only EdDSA is accepted.', { jwt: tok(P, { header: hdr(ISS, { alg: 'none' }), sig: Buffer.alloc(0) }) }, openFail('ALG_NOT_ALLOWED'));
  VC('alg-hs256-keyed-with-the-public-key', ['KYA-VCB-004', 'KYA-VCB-016'], 'The header names HS256 and the token is an HMAC keyed with the issuer public key bytes.', 'KYA-VCB-016: HMAC keyed with a public key is refused because the algorithm is judged first.', { jwt: tok(P, { header: hdr(ISS, { alg: 'HS256' }), signWith: input => createHmac('sha256', ISS.raw).update(input).digest() }) }, openFail('ALG_NOT_ALLOWED'));
  VC('alg-in-lowercase', ['KYA-VCB-004'], 'The header names eddsa in lowercase.', 'KYA-VCB-004: the algorithm name is exact.', { jwt: tok(P, { header: hdr(ISS, { alg: 'eddsa' }) }) }, openFail('ALG_NOT_ALLOWED'));
  VC('alg-is-missing', ['KYA-VCB-004'], 'The header has no alg member.', 'KYA-VCB-004: a missing algorithm is refused.', { jwt: tok(P, { header: (() => { const h = hdr(ISS); delete h.alg; return h; })() }) }, openFail('ALG_NOT_ALLOWED'));
  VC('alg-is-judged-before-the-payload', ['KYA-VCB-004'], 'The header names alg none and the payload is not JSON.', 'KYA-VCB-004: the algorithm is judged before the payload is touched.', { jwt: tok(P, { header: hdr(ISS, { alg: 'none' }), rawPayload: 'not json' }) }, openFail('ALG_NOT_ALLOWED'));
  VC('alg-is-judged-before-other-header-members', ['KYA-VCB-004'], 'The header names alg none and also carries an embedded key.', 'KYA-VCB-004: the algorithm step comes before the header member step.', { jwt: tok(P, { header: hdr(ISS, { alg: 'none', jwk: { kty: 'OKP', crv: 'Ed25519', x: b(ISS.raw) } }) }) }, openFail('ALG_NOT_ALLOWED'));
  VC('header-embeds-a-jwk', ['KYA-VCB-004', 'KYA-VCB-016'], 'The header carries a jwk member and is validly signed.', 'KYA-VCB-016: embedded key headers are refused.', { jwt: tok(P, { header: hdr(ISS, { jwk: { kty: 'OKP', crv: 'Ed25519', x: b(ISS.raw) } }) }) }, openFail('HEADER_MEMBER_NOT_ALLOWED'));
  VC('header-names-a-key-url', ['KYA-VCB-004'], 'The header carries a jku member.', 'KYA-VCB-004: URL header members are refused.', { jwt: tok(P, { header: hdr(ISS, { jku: 'https://keys.example.test/set' }) }) }, openFail('HEADER_MEMBER_NOT_ALLOWED'));
  VC('header-has-crit', ['KYA-VCB-016'], 'The header carries a crit member.', 'KYA-VCB-016: crit headers are refused.', { jwt: tok(P, { header: hdr(ISS, { crit: ['exp'] }) }) }, openFail('HEADER_MEMBER_NOT_ALLOWED'));
  VC('header-has-b64-false', ['KYA-VCB-016'], 'The header carries b64 false, the unencoded payload option.', 'KYA-VCB-016: b64 headers are refused.', { jwt: tok(P, { header: hdr(ISS, { b64: false, crit: ['b64'] }) }) }, openFail('HEADER_MEMBER_NOT_ALLOWED'));
  VC('header-member-is-judged-before-typ', ['KYA-VCB-004'], 'The header has an unknown member and a wrong typ.', 'KYA-VCB-004: the member step comes before the typ step.', { jwt: tok(P, { header: hdr(ISS, { typ: 'JWT', extra: 1 }) }) }, openFail('HEADER_MEMBER_NOT_ALLOWED'));
  VC('typ-jwt', ['KYA-VCB-004'], 'The header typ is JWT.', 'KYA-VCB-004: only typ vc+jwt is accepted.', { jwt: tok(P, { header: hdr(ISS, { typ: 'JWT' }) }) }, openFail('TYP_NOT_ALLOWED'));
  VC('typ-is-missing', ['KYA-VCB-004'], 'The header has no typ.', 'KYA-VCB-004: a missing typ is refused.', { jwt: tok(P, { header: (() => { const h = hdr(ISS); delete h.typ; return h; })() }) }, openFail('TYP_NOT_ALLOWED'));
  VC('cty-is-not-vc', ['KYA-VCB-004'], 'The header cty is application/json.', 'KYA-VCB-004: cty, when present, must be vc.', { jwt: tok(P, { header: hdr(ISS, { cty: 'application/json' }) }) }, openFail('TYP_NOT_ALLOWED'));
  VC('typ-is-judged-before-kid', ['KYA-VCB-004'], 'The header has a wrong typ and no kid.', 'KYA-VCB-004: the typ step comes before the kid step.', { jwt: tok(P, { header: { alg: 'EdDSA', typ: 'JWT' } }) }, openFail('TYP_NOT_ALLOWED'));
  VC('kid-is-missing', ['KYA-VCB-004'], 'The header has no kid.', 'KYA-VCB-004: a kid naming the issuer method is required.', { jwt: tok(P, { header: { alg: 'EdDSA', typ: 'vc+jwt', cty: 'vc' } }) }, openFail('MALFORMED'));
  VC('kid-is-judged-before-the-payload', ['KYA-VCB-004'], 'The header has no kid and the payload is not JSON.', 'KYA-VCB-004: the header is judged before the payload is parsed.', { jwt: tok(P, { header: { alg: 'EdDSA', typ: 'vc+jwt' }, rawPayload: 'not json' }) }, openFail('MALFORMED'));
  VC('kid-names-another-key', ['KYA-VCB-004'], 'The kid names the did:key of another key and the token is signed by the issuer.', 'KYA-VCB-004: a kid that does not name the issuer did:key method is refused.', { jwt: tok(P, { header: hdr(ISS, { kid: hdr(OTH).kid }) }) }, openFail('KID_MISMATCH'));
  VC('kid-has-no-fragment', ['KYA-VCB-004'], 'The kid is the did:key without a fragment.', 'KYA-VCB-004: the kid names the verification method with its fragment.', { jwt: tok(P, { header: hdr(ISS, { kid: ISS.did }) }) }, openFail('KID_MISMATCH'));
  VC('header-with-a-duplicate-member', ['KYA-VCB-016'], 'The header text writes alg twice.', 'KYA-VCB-016: duplicate header members are refused.', { jwt: tok(P, { rawHeader: `{"alg":"EdDSA","alg":"EdDSA","typ":"vc+jwt","cty":"vc","kid":${JSON.stringify(hdr(ISS).kid)}}` }) }, openFail('MALFORMED'));
  VC('header-with-an-aliased-member', ['KYA-VCB-016'], 'The header text writes alg once as an escape that decodes to alg, with the value none, and once plainly.', 'KYA-VCB-016: aliased header members are refused because names are compared after unescaping.', { jwt: tok(P, { rawHeader: `{"\\u0061lg":"none","alg":"EdDSA","typ":"vc+jwt","kid":${JSON.stringify(hdr(ISS).kid)}}` }) }, openFail('MALFORMED'));
  VC('header-with-a-prototype-name', ['KYA-VCB-016'], 'The header carries the member name __proto__.', 'KYA-VCB-016: prototype names are refused by the strict parser.', { jwt: tok(P, { rawHeader: `{"alg":"EdDSA","typ":"vc+jwt","kid":${JSON.stringify(hdr(ISS).kid)},"__proto__":{}}` }) }, openFail('MALFORMED'));
  VC('header-is-an-array', ['KYA-VCB-004'], 'The header is a JSON array.', 'KYA-VCB-004: a header must be an object.', { jwt: tok(P, { rawHeader: '[]' }) }, openFail('MALFORMED'));
  VC('header-with-trailing-text', ['KYA-VCB-016'], 'The header text has text after the object.', 'KYA-VCB-016: strict parsing refuses trailing text.', { jwt: tok(P, { rawHeader: JSON.stringify(hdr(ISS)) + ' x' }) }, openFail('MALFORMED'));
  VC('segment-with-padding', ['KYA-VCB-016'], 'The payload segment ends with an equals sign.', 'KYA-VCB-016: non-canonical encodings are refused; base64url has no padding.', { jwt: tok(P, { mut: p => { p[1] += '='; } }) }, openFail('MALFORMED'));
  VC('segment-with-nonzero-trailing-bits', ['KYA-VCB-016'], 'The signature segment is changed in its last character so the text no longer re-encodes to itself.', 'KYA-VCB-016: a signature has one spelling, which closes malleable encodings.', { jwt: tok(P, { mut: p => { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'; p[2] = p[2].slice(0, -1) + a[(a.indexOf(p[2].at(-1)) + 1) % 64]; } }) }, openFail('MALFORMED'));
  VC('segment-in-the-standard-base64-alphabet', ['KYA-VCB-016'], 'A character of the payload segment is replaced by a plus sign.', 'KYA-VCB-016: only the base64url alphabet is accepted.', { jwt: tok(P, { mut: p => { p[1] = '+' + p[1].slice(1); } }) }, openFail('MALFORMED'));
  VC('token-with-two-segments', ['KYA-VCB-016'], 'The token has only a header and a payload.', 'KYA-VCB-016: a compact JWS has exactly three segments.', { jwt: good.split('.').slice(0, 2).join('.') }, openFail('MALFORMED'));
  VC('token-with-four-segments', ['KYA-VCB-016'], 'The token has a fourth segment.', 'KYA-VCB-016: a compact JWS has exactly three segments.', { jwt: good + '.AAAA' }, openFail('MALFORMED'));
  VC('token-with-a-detached-payload', ['KYA-VCB-016'], 'The payload segment is empty.', 'KYA-VCB-016: detached payloads are refused.', { jwt: (() => { const [h, , s] = good.split('.'); return `${h}..${s}`; })() }, openFail('MALFORMED'));
  VC('token-is-empty', ['KYA-VCB-016'], 'The token is the empty string.', 'KYA-VCB-016: an empty token is malformed.', { jwt: '' }, openFail('MALFORMED'));
  VC('payload-with-a-vc-claim', ['KYA-VCB-004'], 'The payload nests the credential under a vc claim.', 'KYA-VCB-004: the payload is the credential itself; vc and vp claims are refused.', { jwt: tok({ iss: ISS.did, vc: P }) }, openFail('PAYLOAD_INVALID'));
  VC('payload-with-a-duplicate-member', ['KYA-VCB-016'], 'The payload text writes validFrom twice.', 'KYA-VCB-016: duplicate members are refused by strict parsing.', { jwt: tok(P, { rawPayload: JSON.stringify(P).replace('{', `{"validFrom":${JSON.stringify(P.validFrom)},`) }) }, openFail('MALFORMED'));
  VC('payload-is-ill-formed-utf8', ['KYA-VCB-016'], 'The payload bytes contain a lone 0xff byte inside a string.', 'KYA-VCB-016: ill-formed UTF-8 is refused, never replaced.', { jwt: tok(P, { rawPayload: Buffer.concat([Buffer.from('{"issuer":"'), Buffer.from([0xff]), Buffer.from('"}')]) }) }, openFail('MALFORMED'));
  VC('payload-is-an-array', ['KYA-VCB-004'], 'The payload is a JSON array.', 'KYA-VCB-004: a payload must be an object.', { jwt: tok(P, { rawPayload: '[]' }) }, openFail('MALFORMED'));

  // ---- signatures ----
  const goodSig = Buffer.from(good.split('.')[2], 'base64url');
  const flip = (buf, i) => { const c = Buffer.from(buf); c[i] ^= 1; return c; };
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const sPlusL = (() => { const c = Buffer.from(goodSig); let s = 0n; for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(c[i]); s += L; for (let i = 32; i < 64; i++) { c[i] = Number(s & 0xffn); s >>= 8n; } return c; })();
  VC('signature-payload-edited', ['KYA-VCB-005'], 'The decision in the payload is edited and the original signature kept.', 'KYA-VCB-005: any change to the payload is detected.', { jwt: tok(edit(P, c => { c.credentialSubject.decision = 'blocked'; }), { sig: goodSig }) }, openFail('SIGNATURE_INVALID'));
  VC('signature-header-respaced', ['KYA-VCB-005'], 'The header is rewritten with extra whitespace and the original signature kept.', 'KYA-VCB-005: the signature covers the header bytes as sent, so any change is detected.', { jwt: tok(P, { rawHeader: JSON.stringify(hdr(ISS), null, 1), sig: goodSig }) }, openFail('SIGNATURE_INVALID'));
  VC('signature-bit-flipped', ['KYA-VCB-005'], 'One bit of the signature is flipped.', 'KYA-VCB-005: any change to the signature is detected.', { jwt: tok(P, { sig: flip(goodSig, 3) }) }, openFail('SIGNATURE_INVALID'));
  VC('signature-is-empty', ['KYA-VCB-005'], 'The signature segment is empty.', 'KYA-VCB-005: an empty signature is a failed verification, not a malformed token.', { jwt: tok(P, { sig: Buffer.alloc(0) }) }, openFail('SIGNATURE_INVALID'));
  VC('signature-is-63-bytes', ['KYA-VCB-005'], 'The signature has 63 bytes.', 'KYA-VCB-005: an Ed25519 signature has 64 bytes.', { jwt: tok(P, { sig: goodSig.subarray(0, 63) }) }, openFail('SIGNATURE_INVALID'));
  VC('signature-by-another-key', ['KYA-VCB-005'], 'The token is signed by another key while the issuer names the first.', 'KYA-VCB-005: a signature by a key other than the issuer did:key is refused.', { jwt: tok(P, { sigKey: OTH }) }, openFail('SIGNATURE_INVALID'));
  VC('signature-with-s-plus-group-order', ['KYA-VCB-016'], 'The scalar half of a valid signature is replaced by S plus the group order.', 'KYA-VCB-016: malleable signatures are refused; the scalar must be below the group order.', { jwt: tok(P, { sig: sPlusL }) }, openFail('SIGNATURE_INVALID'));
  VC('signature-is-judged-before-the-window', ['KYA-VCB-005', 'KYA-VCB-006'], 'The signature is wrong and the supplied time is also past the window.', 'KYA-VCB-005: the signature step comes before the window steps.', { jwt: tok(P, { sig: flip(goodSig, 3) }), now: '2030-01-01T00:00:00.000Z' }, openFail('SIGNATURE_INVALID'));
  VC('signature-is-judged-before-the-claims', ['KYA-VCB-005'], 'The signature is wrong and the context is also wrong.', 'KYA-VCB-005: the signature step comes before the credential member steps.', { jwt: tok(edit(P, c => { c['@context'] = ['https://example.test/other']; }), { sig: goodSig }) }, openFail('SIGNATURE_INVALID'));

  // ---- issuer did:key ----
  const didOf = bytes => 'did:key:z' + base58btcEncode(bytes);
  const withIssuer = did => S(P, c => { c.issuer = did; }, { header: hdr(ISS, { kid: `${did}#${frag(did)}` }) });
  const MULTI = Buffer.from([0xed, 0x01]);
  const offCurve = (() => { for (let y = 2; y < 400; y++) { const raw = Buffer.alloc(32); raw.writeUInt16LE(y); try { assertValidEd25519Point(raw); } catch (e) { if (/not on the curve/.test(e.message)) return raw; } } throw Error('no off-curve y found'); })();
  VC('did-with-another-multicodec', ['KYA-VCB-007'], 'The issuer is a did:key whose multicodec is secp256k1-pub (0xe701).', 'KYA-VCB-007: other multicodecs are rejected.', { jwt: withIssuer(didOf(Buffer.concat([Buffer.from([0xe7, 0x01]), ISS.raw]))) }, openFail('ISSUER_INVALID'));
  VC('did-with-an-extra-leading-one', ['KYA-VCB-007'], 'The issuer text has an extra 1 after the z, which base58btc reads as a leading zero byte.', 'KYA-VCB-007: non-canonical strings are rejected.', { jwt: withIssuer('did:key:z1' + base58btcEncode(Buffer.concat([MULTI, ISS.raw]))) }, openFail('ISSUER_INVALID'));
  VC('did-with-a-33-byte-key', ['KYA-VCB-007'], 'The issuer holds the Ed25519 multicodec and 31 key bytes.', 'KYA-VCB-007: the key must be 32 bytes.', { jwt: withIssuer(didOf(Buffer.concat([MULTI, ISS.raw.subarray(0, 31)]))) }, openFail('ISSUER_INVALID'));
  VC('did-with-a-35-byte-key', ['KYA-VCB-007'], 'The issuer holds the Ed25519 multicodec and 33 key bytes.', 'KYA-VCB-007: the key must be 32 bytes.', { jwt: withIssuer(didOf(Buffer.concat([MULTI, ISS.raw, Buffer.from([7])]))) }, openFail('ISSUER_INVALID'));
  const identity = Buffer.alloc(32); identity[0] = 1;
  VC('did-of-the-identity-key-with-the-forged-signature', ['KYA-VCB-012', 'KYA-VCB-005'], 'The issuer is the small-order identity point and the signature is 01 followed by zeros, which a verifier without point checks accepts over any payload.', 'KYA-VCB-012: an identity-key forgery must not verify.', { jwt: tok(edit(P, c => { c.issuer = didOf(Buffer.concat([MULTI, identity])); }), { header: hdr(ISS, { kid: `${didOf(Buffer.concat([MULTI, identity]))}#${frag(didOf(Buffer.concat([MULTI, identity])))}` }), sig: Buffer.concat([identity, Buffer.alloc(32)]) }) }, openFail('ISSUER_INVALID'));
  const orderTwo = Buffer.alloc(32, 0xff); orderTwo[0] = 0xec; orderTwo[31] = 0x7f;
  VC('did-of-a-small-order-key', ['KYA-VCB-012'], 'The issuer is the point of order 2 (y equal to minus 1).', 'KYA-VCB-012: small-order points are rejected wherever a did:key is admitted.', { jwt: withIssuer(didOf(Buffer.concat([MULTI, orderTwo]))) }, openFail('ISSUER_INVALID'));
  VC('did-of-an-off-curve-key', ['KYA-VCB-012'], 'The issuer holds a 32 byte value that is not a curve point.', 'KYA-VCB-012: off-curve keys are rejected.', { jwt: withIssuer(didOf(Buffer.concat([MULTI, offCurve]))) }, openFail('ISSUER_INVALID'));
  const nonCanonicalY = Buffer.alloc(32, 0xff); nonCanonicalY[0] = 0xed; nonCanonicalY[31] = 0x7f;
  VC('did-of-a-non-canonical-y', ['KYA-VCB-012'], 'The issuer key encodes y equal to the field prime.', 'KYA-VCB-012: non-canonical encodings are rejected.', { jwt: withIssuer(didOf(Buffer.concat([MULTI, nonCanonicalY]))) }, openFail('ISSUER_INVALID'));
  VC('did-is-not-a-did-key', ['KYA-VCB-007'], 'The issuer is a did:web identifier.', 'KYA-VCB-007: only did:key with the Ed25519 multicodec is accepted.', { jwt: withIssuer('did:web:example.test') }, openFail('ISSUER_INVALID'));
  VC('did-with-a-character-outside-base58', ['KYA-VCB-007'], 'The issuer text contains a zero, which is not in the base58btc alphabet.', 'KYA-VCB-007: non-canonical strings are rejected.', { jwt: withIssuer(ISS.did.slice(0, -1) + '0') }, openFail('ISSUER_INVALID'));
  VC('issuer-is-missing', ['KYA-VCB-005'], 'The payload has no issuer.', 'KYA-VCB-005: the issuer names the verification key and is required.', { jwt: S(P, c => { delete c.issuer; }) }, openFail('PAYLOAD_INVALID'));
  VC('issuer-is-a-number', ['KYA-VCB-005'], 'The issuer is the number 7.', 'KYA-VCB-005: the issuer is a string or an object with a string id.', { jwt: S(P, c => { c.issuer = 7; }) }, openFail('PAYLOAD_INVALID'));
  VC('issuer-object-without-an-id', ['KYA-VCB-005'], 'The issuer is an object with no id.', 'KYA-VCB-005: an issuer object needs a string id.', { jwt: S(P, c => { c.issuer = { name: 'x' }; }) }, openFail('PAYLOAD_INVALID'));

  // ---- credential members ----
  VC('context-does-not-start-with-the-v2-context', ['KYA-VCB-005'], 'The first context is not the VC 2.0 context.', 'KYA-VCB-005: the credential is a VC 2.0 document.', { jwt: S(P, c => { c['@context'] = ['https://example.test/other', CTX]; }) }, openFail('PAYLOAD_INVALID'));
  VC('type-lacks-verifiable-credential', ['KYA-VCB-005'], 'The type array lacks VerifiableCredential.', 'KYA-VCB-005: the type must include VerifiableCredential.', { jwt: S(P, c => { c.type = ['KyaAssessmentCredential']; }) }, openFail('PAYLOAD_INVALID'));
  VC('iss-conflicts-with-the-issuer', ['KYA-VCB-005'], 'An iss claim names another did:key than the issuer.', 'KYA-VCB-005: conflicting issuer claims are refused.', { jwt: S(P, c => { c.iss = OTH.did; }) }, openFail('PAYLOAD_INVALID'));
  VC('subject-is-an-array', ['KYA-VCB-005'], 'The credentialSubject is an array.', 'KYA-VCB-005: the credential has one subject object.', { jwt: S(P, c => { c.credentialSubject = [c.credentialSubject]; }) }, openFail('PAYLOAD_INVALID'));

  // ---- claims of a credential that opens ----
  VC('claims-fixture-mode-without-the-limitation', ['KYA-VCB-002'], 'A validly signed credential says evidence mode fixture and carries no fixture limitation.', 'KYA-VCB-002: verification rejects a credential whose evidence mode and fixture limitation disagree even when the signature is valid.', { jwt: S(P_F, c => { c.credentialSubject.limitations = c.credentialSubject.limitations.filter(l => !l.startsWith('Includes synthetic')); }) }, { valid: false, errors: ['EVIDENCE_MODE_LIMITATION_MISMATCH'] });
  VC('claims-runtime-mode-with-the-fixture-limitation', ['KYA-VCB-002'], 'A credential says evidence mode runtime and carries the fixture limitation.', 'KYA-VCB-002: the disagreement is an error in both directions.', { jwt: S(P, c => { c.credentialSubject.limitations = [...c.credentialSubject.limitations, 'Includes synthetic fixture evidence; not a real product benchmark']; }) }, { valid: false, errors: ['EVIDENCE_MODE_LIMITATION_MISMATCH'] });
  VC('claims-mixed-mode-without-the-limitation', ['KYA-VCB-002'], 'A credential says evidence mode mixed and carries no fixture limitation.', 'KYA-VCB-002: mixed evidence needs the fixture limitation like fixture evidence.', { jwt: S(P, c => { c.credentialSubject.evidenceMode = 'mixed'; }) }, { valid: false, errors: ['EVIDENCE_MODE_LIMITATION_MISMATCH'] });
  VC('claims-unknown-evidence-mode', ['KYA-VCB-002'], 'A credential says evidence mode live.', 'KYA-VCB-002: the evidence mode is a closed vocabulary.', { jwt: S(P, c => { c.credentialSubject.evidenceMode = 'live'; }) }, { valid: false, errors: ['PAYLOAD_INVALID'] });
  VC('claims-several-failures-are-all-listed', ['KYA-VCB-005'], 'The subject digest is not a hash, so the subject id and the evidence block also disagree.', 'KYA-VCB-005: every broken rule is reported, in specification order, one entry each.', { jwt: S(P, c => { c.credentialSubject.subjectDigest = 'xyz'; }) }, { valid: false, errors: ['PAYLOAD_INVALID', 'PAYLOAD_INVALID', 'EVIDENCE_REFERENCE_MISMATCH'] });
  VC('claims-evidence-block-differs', ['KYA-VCB-005'], 'The evidence block names another policy digest.', 'KYA-VCB-005: the evidence input digests must match the subject.', { jwt: S(P, c => { c.evidence[0].policyDigest = hashBytes('another policy'); }) }, { valid: false, errors: ['EVIDENCE_REFERENCE_MISMATCH'] });
  VC('claims-evidence-is-an-object-keyed-zero', ['KYA-VCB-005'], 'The evidence member is an object with the member name 0 instead of an array.', 'KYA-VCB-005: the evidence block is element 0 of an array, so an object keyed 0 is not one.', { jwt: S(P, c => { c.evidence = { 0: c.evidence[0] }; }) }, { valid: false, errors: ['EVIDENCE_REFERENCE_MISMATCH'] });
  VC('claims-empty-limitations', ['KYA-VCB-005'], 'The limitations array is empty.', 'KYA-VCB-005: limitations are required and are never dropped.', { jwt: S(P, c => { c.credentialSubject.limitations = []; }) }, { valid: false, errors: ['PAYLOAD_INVALID'] });
  VC('claims-not-an-assessment-credential', ['KYA-VCB-005'], 'The type lacks KyaAssessmentCredential.', 'KYA-VCB-005: a verifier of assessment credentials refuses another credential type.', { jwt: S(P, c => { c.type = ['VerifiableCredential']; }) }, { valid: false, errors: ['PAYLOAD_INVALID'] });
  VC('claims-subject-id-differs-from-the-digest', ['KYA-VCB-005'], 'The subject id names another digest than subjectDigest.', 'KYA-VCB-005: the subject is bound by its digest.', { jwt: S(P, c => { c.credentialSubject.id = 'urn:kya:subject:sha256:' + hashBytes('another subject'); }) }, { valid: false, errors: ['PAYLOAD_INVALID'] });

  // ---- binding to the source report ----
  const reseal = r => { const { reportDigest, ...body } = r; return { ...body, reportDigest: digest(body) }; };
  const Rj = clone(R), RFj = clone(RF);
  VC('report-matches', ['KYA-VCB-014'], 'The source report is supplied and the credential is exactly what the report builds.', 'KYA-VCB-014: with the report the credential is compared as a whole and a match reports reportChecked.', { report: Rj }, { valid: true, errors: [], reportChecked: true, reportMismatch: [] });
  VC('report-matches-with-status-entries', ['KYA-VCB-014'], 'The credential carries status entries and the source report is supplied.', 'KYA-VCB-014: status entries are rebuilt through the same constructor, so well formed entries match.', { jwt: EXP_S.jwt, report: Rj }, { valid: true, errors: [], reportChecked: true, reportMismatch: [] });
  VC('resigned-edit-verifies-without-the-report', ['KYA-VCB-014', 'KYA-VCB-005'], 'A holder of the issuer key empties notAsserted and re-signs; no report is supplied.', 'KYA-VCB-014: without the report the result claims internal consistency only, so the edit verifies.', { jwt: S(P, c => { c.credentialSubject.notAsserted = []; }) }, { valid: true, errors: [], reportChecked: false });
  VC('resigned-edit-is-caught-by-the-report', ['KYA-VCB-014'], 'The same re-signed edit with the source report supplied.', 'KYA-VCB-014: rebuilding the credential from the report reports any difference and names the member.', { jwt: S(P, c => { c.credentialSubject.notAsserted = []; }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportChecked: true, reportMismatch: ['credentialSubject'] });
  VC('fixture-credential-relabelled-runtime-verifies-alone', ['KYA-VCB-002', 'KYA-VCB-014'], 'A fixture credential is relabelled runtime with its fixture limitation removed and re-signed; no report.', 'KYA-VCB-002: the mode and limitation agree, so the credential is consistent; KYA-VCB-014 states that nothing binds it to the assessment without the report.', { jwt: S(P_F, c => { c.credentialSubject.evidenceMode = 'runtime'; c.credentialSubject.limitations = c.credentialSubject.limitations.filter(l => !l.startsWith('Includes synthetic')); }) }, { valid: true, errors: [] });
  VC('fixture-credential-relabelled-runtime-is-caught-by-the-report', ['KYA-VCB-002', 'KYA-VCB-014'], 'The relabelled fixture credential with the fixture report supplied.', 'KYA-VCB-014: the report shows the evidence mode was fixture; KYA-VCB-002: fixture must stay fixture.', { jwt: S(P_F, c => { c.credentialSubject.evidenceMode = 'runtime'; c.credentialSubject.limitations = c.credentialSubject.limitations.filter(l => !l.startsWith('Includes synthetic')); }), report: RFj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['credentialSubject'] });
  VC('report-digest-is-wrong', ['KYA-VCB-014'], 'The supplied report has a decision edited and its checksum kept.', 'KYA-VCB-014: a report that fails its own checksum is REPORT_INVALID and nothing is claimed from it.', { report: { ...Rj, decision: 'blocked' } }, { valid: false, errors: ['REPORT_INVALID'], reportChecked: false });
  VC('report-lacks-a-member-the-rebuild-needs', ['KYA-VCB-014'], 'The report is re-sealed without evidenceBundleDigest.', 'KYA-VCB-014: a report that cannot be rebuilt from is invalid, not a crash and not a match.', () => ({ report: (() => { const r = clone(R); delete r.evidenceBundleDigest; return reseal(r); })() }), { valid: false, errors: ['REPORT_INVALID'], reportChecked: false });
  VC('report-credential-id-differs', ['KYA-VCB-014'], 'The credential id is edited and re-signed.', 'KYA-VCB-014: the whole credential is compared, so the id is bound to the report.', { jwt: S(P, c => { c.id = 'urn:kya:assessment:sha256:' + hashBytes('other'); }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['id'] });
  VC('report-credential-has-an-extra-member', ['KYA-VCB-014'], 'The credential carries a member the rebuilt credential does not have.', 'KYA-VCB-014: added members are differences.', { jwt: S(P, c => { c.name = 'extra'; }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['name'] });
  VC('report-evidence-block-differs', ['KYA-VCB-014'], 'The evidence block lists another accepted evidence digest, kept consistent with the subject.', 'KYA-VCB-014: the evidence block is rebuilt from the report.', { jwt: S(P, c => { c.evidence[0].acceptedEvidenceDigests = [...c.evidence[0].acceptedEvidenceDigests, hashBytes('extra')]; }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['evidence'] });
  VC('report-valid-from-predates-the-assessment', ['KYA-VCB-014', 'KYA-VCB-003'], 'The credential validFrom is an hour before the assessment time.', 'KYA-VCB-003: a credential must not predate its assessment; KYA-VCB-014 checks it against the report.', { jwt: S(P, c => { c.validFrom = '2026-10-14T11:00:00.000Z'; }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['validFrom'] });
  VC('report-valid-until-outlives-the-assessment', ['KYA-VCB-014', 'KYA-VCB-003'], 'The credential validUntil is a day after the assessment validUntil.', 'KYA-VCB-003: a credential must not outlive its assessment; KYA-VCB-014 checks it against the report.', { jwt: S(P, c => { c.validUntil = new Date(Date.parse(R.validUntil) + 86400000).toISOString(); }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['validUntil'] });
  VC('report-status-entry-with-an-ftp-url', ['KYA-VCB-014'], 'A status entry names an ftp URL.', 'KYA-VCB-014: status entries must be well formed to be rebuilt; the credentialStatus member then differs.', { jwt: S(P_S, c => { c.credentialStatus[0].statusListCredential = 'ftp://status.example.test/revocation'; }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['credentialStatus'] });
  VC('report-status-is-a-single-object', ['KYA-VCB-014'], 'credentialStatus is one object instead of an array.', 'KYA-VCB-014: the rebuilt credential writes an array, so a single object differs.', { jwt: S(P_S, c => { c.credentialStatus = c.credentialStatus[0]; }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['credentialStatus'] });

  VC('report-lacks-a-copied-member-but-passes-its-checksum', ['KYA-VCB-014'], 'The report is re-sealed without scopeDigest, a member copied into the credential subject.', 'KYA-VCB-014: the comparison shape checks do not apply, but a report that lacks a member the rebuild copies cannot be rebuilt from, which is REPORT_INVALID.', () => ({ report: (() => { const r = clone(R); delete r.scopeDigest; return reseal(r); })() }), { valid: false, errors: ['REPORT_INVALID'], reportChecked: false });
  VC('report-without-blocker-codes-matches', ['KYA-VCB-014'], 'A report written before blockerCodes existed, and the credential exported from it with blockerCodes null.', 'KYA-VCB-014: blockerCodes may be absent from the report and is then written as null, and the rebuild matches.', () => { const r = clone(R); delete r.blockerCodes; const legacy = reseal(r); return { jwt: exportAssessmentCredential(legacy, { issuerKey: ISS.priv }).jwt, report: legacy }; }, { valid: true, errors: [], reportChecked: true, reportMismatch: [] });
  VC('report-status-entry-without-a-purpose', ['KYA-VCB-014'], 'A status entry has no statusPurpose member.', 'KYA-VCB-014: an entry that cannot be rebuilt makes credentialStatus differ.', { jwt: S(P_S, c => { delete c.credentialStatus[0].statusPurpose; }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['credentialStatus'] });
  VC('report-credential-without-valid-until', ['KYA-VCB-014', 'KYA-VCB-003'], 'The credential has no validUntil and the report is supplied.', 'KYA-VCB-003: a credential must not outlive its assessment, so a missing end is treated as failing the bound; KYA-VCB-014 checks it against the report.', { jwt: S(P, c => { delete c.validUntil; }), report: Rj }, { valid: false, errors: ['REPORT_MISMATCH'], reportMismatch: ['validUntil'] });

  // ---- status lists ----
  const ctxOf = (id, purpose, extra = {}) => ({ '@context': [CTX], id, type: ['VerifiableCredential', 'BitstringStatusListCredential'], issuer: ISS.did, validFrom: LIST_FROM, validUntil: LIST_UNTIL, credentialSubject: { id: `${id}#list`, type: 'BitstringStatusList', statusPurpose: purpose, encodedList: encodeList(createBitstring()), ...extra } });
  const list = (id, purpose, indices = [], o = {}) => buildStatusListCredential({ issuerKey: o.key ?? ISS.priv, id, purpose, indices, validFrom: LIST_FROM, validUntil: o.validUntil ?? LIST_UNTIL, ...(o.ttl === undefined ? {} : { ttl: o.ttl }) }).jwt;
  const LISTS = (r = [], s = []) => ({ [URL_R]: list(URL_R, 'revocation', r), [URL_S]: list(URL_S, 'suspension', s) });
  const withList = (payload, o = {}) => tok(payload, o);
  const only = (url, purpose, payloadEdit, mutBits) => { const p = ctxOf(url, purpose); if (payloadEdit) payloadEdit(p); return tok(p); };
  const bitsList = (indices, bytes = 16384) => { const bits = createBitstring(bytes * 8); for (const i of indices) setBit(bits, i); return 'u' + b(gzipSync(Buffer.from(bits), { level: 9 })); };
  const entry = (purpose, url, index, o = {}) => ({ type: 'BitstringStatusListEntry', statusPurpose: purpose, statusListIndex: String(index), statusListCredential: url, ...o });
  const credWith = entries => S(P, c => { c.credentialStatus = entries; });
  const entryOne = (extra = {}) => credWith([entry('revocation', URL_R, 4242, extra)]);
  const oneList = (listJwt) => ({ [URL_R]: listJwt });
  const entries = e => ({ status: { entries: e } });
  const checkedClear = p => ({ purpose: p, checked: true, set: false, error: null });
  const errEntry = (p, code) => ({ purpose: p, checked: false, set: null, error: code });

  VC('status-both-lists-clear', ['KYA-VCB-010'], 'Both status lists are supplied and neither bit is set.', 'KYA-VCB-010: a status check verifies each list and reports the purposes separately.', { jwt: EXP_S.jwt, statusLists: LISTS() }, { valid: true, errors: [], status: { checked: true, entries: [checkedClear('revocation'), checkedClear('suspension')] } });
  VC('status-revoked', ['KYA-VCB-010'], 'The revocation bit of the credential is set.', 'KYA-VCB-010: a revoked credential fails verification when its list is supplied.', { jwt: EXP_S.jwt, statusLists: LISTS([4242]) }, { valid: false, errors: ['REVOKED'], status: { checked: true, entries: [{ purpose: 'revocation', checked: true, set: true, error: null }, checkedClear('suspension')] } });
  VC('status-suspended', ['KYA-VCB-010'], 'The suspension bit of the credential is set.', 'KYA-VCB-010: revocation and suspension are separate purposes.', { jwt: EXP_S.jwt, statusLists: LISTS([], [77]) }, { valid: false, errors: ['SUSPENDED'] });
  VC('status-list-supplied-for-one-purpose-only', ['KYA-VCB-010'], 'Only the revocation list is supplied.', 'KYA-VCB-010: an entry without a supplied list is not checked, and status is not reported as checked.', { jwt: EXP_S.jwt, statusLists: { [URL_R]: list(URL_R, 'revocation') } }, { valid: true, errors: [], status: { checked: false, entries: [checkedClear('revocation'), { purpose: 'suspension', checked: false, set: null, error: null }] } });
  VC('status-required-but-no-list-supplied', ['KYA-VCB-010'], 'Status is required and no list is supplied.', 'KYA-VCB-010: a verifier can require the status check, and then missing evidence is an error.', { jwt: EXP_S.jwt, requireStatusCheck: true }, { valid: false, errors: ['STATUS_NOT_CHECKED'] });
  VC('status-required-but-the-credential-has-no-status', ['KYA-VCB-010'], 'Status is required and the credential has no status entry.', 'KYA-VCB-010: with no entry nothing was checked, so a required check fails.', { requireStatusCheck: true }, { valid: false, errors: ['STATUS_NOT_CHECKED'], status: { checked: false, entries: [] } });
  VC('status-lists-supplied-without-an-entry-are-ignored', ['KYA-VCB-010'], 'Lists are supplied and the credential has no status entry.', 'KYA-VCB-010: only entries of the credential select a list.', { statusLists: LISTS([4242]) }, { valid: true, errors: [], status: { checked: false, entries: [] } });
  VC('status-url-is-a-prototype-member-name', ['KYA-VCB-016'], 'The status entry names the list toString.', 'KYA-VCB-016: a prototype-keyed lookup must not find an inherited member as a list.', { jwt: credWith([entry('revocation', 'toString', 1)]) }, { valid: true, errors: [], status: { checked: false, entries: [{ purpose: 'revocation', checked: false, set: null, error: null }] } });
  VC('status-bit-zero-is-the-leftmost-bit', ['KYA-VCB-008'], 'One list has bits 0 and 9 set, and entries name indexes 0, 1, 7, 8 and 9.', 'KYA-VCB-008: index 0 is the leftmost bit of the first byte, so 0 and 9 are set and 1, 7 and 8 are not.', { jwt: credWith([0, 1, 7, 8, 9].map(i => entry('revocation', URL_R, i))), statusLists: oneList(tok(ctxOf(URL_R, 'revocation', { encodedList: bitsList([0, 9]) }))) }, { valid: false, errors: ['REVOKED', 'REVOKED'], status: { checked: true, entries: [{ set: true }, { set: false }, { set: false }, { set: false }, { set: true }] } });
  VC('status-list-signed-by-another-key', ['KYA-VCB-010'], 'The status list is signed by another key.', 'KYA-VCB-010: the list must be signed by the credential issuer.', { jwt: EXP_S.jwt, statusLists: { ...LISTS(), [URL_R]: list(URL_R, 'revocation', [], { key: OTH.priv }) } }, { valid: false, errors: ['STATUS_VERIFICATION_ERROR'], status: { checked: false, entries: [errEntry('revocation', 'STATUS_VERIFICATION_ERROR'), checkedClear('suspension')] } });
  VC('status-list-expired', ['KYA-VCB-010', 'KYA-VCB-013'], 'The status list validUntil is before the supplied time.', 'KYA-VCB-013: an expired list is refused and reported distinctly.', { jwt: EXP_S.jwt, statusLists: { ...LISTS(), [URL_R]: list(URL_R, 'revocation', [], { validUntil: '2026-10-14T12:30:00.000Z' }) } }, { valid: false, errors: ['STATUS_LIST_EXPIRED'], status: { checked: false, entries: [errEntry('revocation', 'STATUS_LIST_EXPIRED'), checkedClear('suspension')] } });
  VC('status-list-without-valid-until', ['KYA-VCB-013'], 'The status list has no validUntil.', 'KYA-VCB-013: a list with no expiry is refused and reported distinctly.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { delete p.validUntil; })) }, { valid: false, errors: ['STATUS_LIST_NO_EXPIRY'] });
  VC('status-list-ttl-elapsed', ['KYA-VCB-013'], 'The status list ttl of one minute has elapsed an hour after validFrom.', 'KYA-VCB-013: a list past its ttl is refused as expired.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.ttl = 60000; })) }, { valid: false, errors: ['STATUS_LIST_EXPIRED'] });
  VC('status-list-ttl-is-malformed', ['KYA-VCB-013'], 'The status list ttl is zero.', 'KYA-VCB-013: a malformed ttl is an error, not ignored.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.ttl = 0; })) }, { valid: false, errors: ['STATUS_VERIFICATION_ERROR'] });
  VC('status-list-has-fewer-than-131072-entries', ['KYA-VCB-009'], 'The decoded list has 16383 bytes, 131064 entries.', 'KYA-VCB-009: lists shorter than 131072 entries are refused.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.encodedList = bitsList([], 16383); })) }, { valid: false, errors: ['STATUS_LIST_LENGTH_ERROR'] });
  VC('status-list-of-the-largest-allowed-size', ['KYA-VCB-009'], 'The decoded list is exactly 2097152 bytes and the entry names its last index.', 'KYA-VCB-009: decoding is bounded at 2097152 bytes and a list of exactly that size is accepted.', { jwt: credWith([entry('revocation', URL_R, 16777215)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.encodedList = bitsList([16777215], 2097152); })) }, { valid: false, errors: ['REVOKED'] });
  VC('status-list-inflates-past-the-bound', ['KYA-VCB-009', 'KYA-VCB-008'], 'The list is a small GZIP stream that inflates to 2097153 bytes.', 'KYA-VCB-009: decoding bounds the decompressed size, so a small stream cannot exhaust memory.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.encodedList = 'u' + b(gzipSync(Buffer.alloc(2097153), { level: 9 })); })) }, { valid: false, errors: ['STATUS_LIST_INVALID'] });
  VC('status-list-with-the-wrong-multibase-prefix', ['KYA-VCB-008'], 'The encoded list begins with z instead of u.', 'KYA-VCB-008: a wrong prefix is refused on decode.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.encodedList = 'z' + p.credentialSubject.encodedList.slice(1); })) }, { valid: false, errors: ['STATUS_LIST_INVALID'] });
  VC('status-list-with-padding', ['KYA-VCB-008'], 'The encoded list ends with an equals sign.', 'KYA-VCB-008: padding is refused on decode.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.encodedList += '='; })) }, { valid: false, errors: ['STATUS_LIST_INVALID'] });
  VC('status-list-is-not-gzip', ['KYA-VCB-008'], 'The encoded list decodes to bytes that are not a GZIP stream.', 'KYA-VCB-008: corrupt data is refused on decode.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.encodedList = 'u' + b('not gzip data at all'); })) }, { valid: false, errors: ['STATUS_LIST_INVALID'] });
  VC('status-list-is-not-a-string', ['KYA-VCB-008'], 'The encoded list is a number.', 'KYA-VCB-008: the encoded list is a string.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'revocation', p => { p.credentialSubject.encodedList = 5; })) }, { valid: false, errors: ['STATUS_LIST_INVALID'] });
  VC('status-list-for-another-purpose', ['KYA-VCB-009'], 'The list at the revocation URL provides suspension only.', 'KYA-VCB-009: mismatched purposes are refused.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only(URL_R, 'suspension')) }, { valid: false, errors: ['STATUS_VERIFICATION_ERROR'] });
  VC('status-list-id-differs-from-the-url', ['KYA-VCB-010'], 'The list credential id is another URL than the entry names.', 'KYA-VCB-010: the list is bound to the URL the entry names.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(only('https://status.example.test/other', 'revocation')) }, { valid: false, errors: ['STATUS_VERIFICATION_ERROR'] });
  VC('status-list-is-another-credential-type', ['KYA-VCB-010'], 'The list token is a valid credential of the assessment kind, not a list.', 'KYA-VCB-010: the list must be a BitstringStatusListCredential.', { jwt: credWith([entry('revocation', URL_R, 4242)]), statusLists: oneList(good) }, { valid: false, errors: ['STATUS_VERIFICATION_ERROR'] });
  VC('status-index-beyond-the-list', ['KYA-VCB-009'], 'The entry index is 131072 on a list of 131072 entries.', 'KYA-VCB-009: out-of-range indices are refused.', { jwt: credWith([entry('revocation', URL_R, 131072)]), statusLists: oneList(list(URL_R, 'revocation')) }, { valid: false, errors: ['STATUS_VERIFICATION_ERROR'], status: { checked: false, entries: [errEntry('revocation', 'RANGE_ERROR')] } });
  VC('status-entry-index-with-a-leading-zero', ['KYA-VCB-009'], 'The entry index is the string 04242.', 'KYA-VCB-009: malformed entries are refused.', { jwt: credWith([entry('revocation', URL_R, '04242')]), statusLists: oneList(list(URL_R, 'revocation')) }, { valid: false, errors: ['STATUS_ENTRY_INVALID'] });
  VC('status-entry-with-status-size-two', ['KYA-VCB-009'], 'The entry carries statusSize 2.', 'KYA-VCB-009: only statusSize 1 is supported.', { jwt: credWith([entry('revocation', URL_R, 4242, { statusSize: 2 })]), statusLists: oneList(list(URL_R, 'revocation')) }, { valid: false, errors: ['STATUS_ENTRY_INVALID'] });
  VC('status-entry-with-an-unknown-purpose', ['KYA-VCB-009'], 'The entry purpose is message.', 'KYA-VCB-009: only revocation and suspension are supported.', { jwt: credWith([entry('message', URL_R, 4242)]), statusLists: oneList(list(URL_R, 'revocation')) }, { valid: false, errors: ['STATUS_ENTRY_INVALID'] });
  VC('status-entry-of_the-wrong-type', ['KYA-VCB-009'], 'The entry type is StatusList2021Entry.', 'KYA-VCB-009: only BitstringStatusListEntry is supported.', { jwt: credWith([entry('revocation', URL_R, 4242, { type: 'StatusList2021Entry' })]), statusLists: oneList(list(URL_R, 'revocation')) }, { valid: false, errors: ['STATUS_ENTRY_INVALID'] });

  // ---- refusals: input outside the contract ----
  const sl = LISTS();
  const REF = (name, rationale, over, req = ['KYA-INT-004']) => VCR(name, req, rationale[0], 'KYA-INT-004: ' + rationale[1], over);
  REF('jwt-is-a-number', ['The jwt is the number 1.', 'input of the wrong type is refused.'], { jwt: 1 });
  REF('jwt-is-null', ['The jwt is null.', 'input of the wrong type is refused.'], { jwt: null });
  REF('now-is-a-number', ['The now is a number.', 'input of the wrong type is refused.'], { now: 1760446800000 });
  REF('now-is-null', ['The now is null.', 'input of the wrong type is refused.'], { now: null });
  REF('expected-issuers-is-a-string', ['expectedIssuers is a string.', 'input of the wrong type is refused.'], { expectedIssuers: ISS.did });
  REF('expected-issuers-is-null', ['expectedIssuers is null.', 'input of the wrong type is refused.'], { expectedIssuers: null });
  REF('expected-issuer-without-the-did-key-prefix', ['An expectedIssuers entry is a did:web identifier.', 'the contract accepts only did:key strings, so another form is refused, not approximated.'], { expectedIssuers: ['did:web:example.test'] });
  REF('expected-issuer-is-a-number', ['An expectedIssuers entry is a number.', 'input of the wrong type is refused.'], { expectedIssuers: [1] });
  REF('expected-issuer-is-a-public-key-pem', ['An expectedIssuers entry is a PEM public key.', 'the library accepts keys, but the contract names issuers by did:key only.'], { expectedIssuers: [ISS.pem] });
  REF('policy-is-an-array', ['The policy is an empty array.', 'a policy must be an object or null.'], { policy: [] });
  REF('policy-is-a-string', ['The policy is a string.', 'a policy must be an object or null.'], { policy: 'policy' });
  REF('policy-is-an-empty-object', ['The policy is an empty object.', 'a policy that breaks its field rules is refused.'], { policy: {} });
  REF('policy-with-an-unknown-member', ['The policy carries an unknown member.', 'a policy has exactly the members its schema lists.'], () => ({ policy: { ...policyWith(ISS, 'independent'), note: 'x' } }));
  REF('policy-with-a-trust-anchor-id-that-is-not-the-key-fingerprint', ['A trust anchor id is not the SHA-256 of its key.', 'a policy that breaks its field rules is refused.'], () => ({ policy: (() => { const p = policyWith(ISS, 'independent'); p.trustedKeys[0].id = hashBytes('not the key'); return p; })() }));
  REF('policy-with-an-unknown-role', ['A trust anchor has the role admin.', 'a policy that breaks its field rules is refused.'], () => ({ policy: (() => { const p = policyWith(ISS, 'independent'); p.trustedKeys[0].role = 'admin'; return p; })() }));
  REF('status-lists-is-an-array', ['statusLists is an array.', 'statusLists is an object.'], { statusLists: [] });
  REF('status-lists-is-null', ['statusLists is null.', 'statusLists is an object.'], { statusLists: null });
  REF('status-list-value-is-a-number', ['A statusLists value is a number.', 'every statusLists value is a string.'], { statusLists: { [URL_R]: 1 } });
  REF('status-list-value-is-empty', ['A statusLists value is the empty string.', 'every statusLists value is a non-empty string.'], { statusLists: { [URL_R]: '' } });
  REF('status-list-value-is-an-object', ['A statusLists value is an object.', 'every statusLists value is a string.'], { statusLists: { [URL_R]: {} } });
  REF('require-status-check-is-a-string', ['requireStatusCheck is the string true.', 'input of the wrong type is refused.'], { requireStatusCheck: 'true' });
  REF('require-status-check-is-a-number', ['requireStatusCheck is 1.', 'input of the wrong type is refused.'], { requireStatusCheck: 1 });
  REF('report-is-an-array', ['The report is an empty array.', 'a report is an object or null.'], { report: [] });
  REF('report-is-a-string', ['The report is a string.', 'a report is an object or null.'], { report: 'report' });
  for (const m of ['jwt', 'now', 'expectedIssuers', 'policy', 'statusLists', 'requireStatusCheck', 'report']) {
    O('verify-credential.refuse-missing-' + m, 'verify-credential', ['KYA-INT-004'], `The inputs have no ${m} member.`, 'KYA-INT-004: a missing member is refused.', () => { const i = inputs()(); delete i[m]; return i; }, REFUSE);
  }
  REF('extra-input-member', ['The inputs carry a member besides the seven.', 'operation inputs have exactly the listed members.'], { trusted: true });
  O('verify-credential.refuse-inputs-are-empty', 'verify-credential', ['KYA-INT-004'], 'The inputs are an empty object.', 'KYA-INT-004: a missing member is refused.', {}, REFUSE);
  O('verify-credential.refuse-inputs-are-an-array', 'verify-credential', ['KYA-INT-004'], 'The inputs are an array.', 'KYA-INT-004: operation inputs are an object.', [], REFUSE);

  // More wrong types, one per member and kind of value.
  const KINDS = { 'true': true, 'an-array': [], 'an-object': {} };
  const typed = (member, label, kinds, over = {}) => { for (const [k, v] of Object.entries(kinds)) REF(`${label}-is-${k}`, [`${member} is ${k.replace(/-/g, ' ')}.`, 'input of the wrong type is refused.'], { [member]: v, ...over }); };
  typed('jwt', 'jwt', KINDS);
  typed('now', 'now', KINDS);
  REF('expected-issuers-is-true', ['expectedIssuers is true.', 'input of the wrong type is refused.'], { expectedIssuers: true });
  REF('expected-issuers-is-an-object', ['expectedIssuers is an object.', 'input of the wrong type is refused.'], { expectedIssuers: {} });
  REF('expected-issuer-is-null', ['An expectedIssuers entry is null.', 'input of the wrong type is refused.'], { expectedIssuers: [null] });
  REF('expected-issuer-is-an-object', ['An expectedIssuers entry is an object.', 'input of the wrong type is refused.'], { expectedIssuers: [{ id: ISS.did }] });
  REF('expected-issuer-is-empty', ['An expectedIssuers entry is the empty string.', 'the contract accepts only strings that begin did:key:.'], { expectedIssuers: [''] });
  REF('expected-issuer-with-upper-case-prefix', ['An expectedIssuers entry begins DID:KEY:.', 'the prefix is exact, so another spelling is refused, not approximated.'], { expectedIssuers: [ISS.did.replace('did:key:', 'DID:KEY:')] });
  REF('policy-is-a-number', ['The policy is the number 1.', 'a policy must be an object or null.'], { policy: 1 });
  REF('policy-is-true', ['The policy is true.', 'a policy must be an object or null.'], { policy: true });
  REF('status-lists-is-a-string', ['statusLists is a string.', 'statusLists is an object.'], { statusLists: 'lists' });
  REF('status-lists-is-a-number', ['statusLists is a number.', 'statusLists is an object.'], { statusLists: 1 });
  REF('status-lists-is-true', ['statusLists is true.', 'statusLists is an object.'], { statusLists: true });
  REF('status-list-value-is-null', ['A statusLists value is null.', 'every statusLists value is a string.'], { statusLists: { [URL_R]: null } });
  REF('status-list-value-is-an-array', ['A statusLists value is an array of tokens.', 'every statusLists value is a string.'], { statusLists: { [URL_R]: [sl[URL_R]] } });
  REF('require-status-check-is-null', ['requireStatusCheck is null.', 'input of the wrong type is refused.'], { requireStatusCheck: null });
  REF('require-status-check-is-an-array', ['requireStatusCheck is an array.', 'input of the wrong type is refused.'], { requireStatusCheck: [] });
  REF('require-status-check-is-an-object', ['requireStatusCheck is an object.', 'input of the wrong type is refused.'], { requireStatusCheck: {} });
  REF('report-is-a-number', ['The report is the number 1.', 'a report is an object or null.'], { report: 1 });
  REF('report-is-true', ['The report is true.', 'a report is an object or null.'], { report: true });

  // A policy must satisfy its field rules, one rule per vector.
  const badPolicy = (name, description, mut) => REF('policy-' + name, [description, 'a policy that breaks its field rules is refused, never approximated.'], () => ({ policy: (() => { const p = policyWith(ISS, 'independent'); mut(p); return p; })() }));
  badPolicy('min-score-above-1000', 'minScore is 1001.', p => { p.minScore = 1001; });
  badPolicy('min-coverage-above-1', 'minCoverage is 1.5.', p => { p.minCoverage = 1.5; });
  badPolicy('allowed-source-is-unknown', 'allowedSources names live.', p => { p.allowedSources = ['live']; });
  badPolicy('allowed-sources-repeat', 'allowedSources lists runtime twice.', p => { p.allowedSources = ['runtime', 'runtime']; });
  badPolicy('max-evidence-age-is-zero', 'maxEvidenceAgeSeconds is 0.', p => { p.maxEvidenceAgeSeconds = 0; });
  badPolicy('scope-id-is-not-an-identifier', 'scopeId begins with a dash.', p => { p.scopeId = '-scope'; });
  badPolicy('profile-digest-is-not-a-hash', 'profileDigest is not a hash.', p => { p.profileDigest = 'nope'; });
  badPolicy('trusted-key-ids-repeat', 'The same trust anchor appears twice.', p => { p.trustedKeys.push(clone(p.trustedKeys[0])); });
  badPolicy('revoked-key-id-is-not-a-hash', 'revokedKeyIds holds a non-hash.', p => { p.revokedKeyIds = ['key']; });
  badPolicy('schema-is-another-record', 'The schema member is kya.profile/v1.', p => { p.schema = 'kya.profile/v1'; });
  badPolicy('anchor-public-key-is-not-the-canonical-spelling', 'An anchor public key has CRLF line ends.', p => { const a = p.trustedKeys.find(k => k.id === keyId(ISS.pem)); a.publicKey = a.publicKey.replace(/\n/g, '\r\n'); });

  // Text the strict stdin parser refuses, so there is no value to verify.
  const rawVc = (name, description, rationale, rawEdit, over = {}) => OR('verify-credential.refuse-' + name, 'verify-credential', ['KYA-INT-002', 'KYA-INT-004'], description, 'KYA-INT-002: ' + rationale, inputs(over), rawEdit);
  rawVc('input-with-a-duplicate-now-member', 'The stdin text writes the now member twice.', 'strict parsing refuses duplicate members anywhere in the input.', t => t.replace('"now":"2026-10-14T13:00:00.000Z"', '"now":"2026-10-14T13:00:00.000Z","now":"2026-10-14T13:00:00.000Z"'));
  rawVc('policy-with-a-prototype-member', 'The policy text carries the member name __proto__.', 'the member names __proto__, prototype and constructor are refused at any depth.', t => t.replace('"policy":{', '"policy":{"__proto__":{},'), () => ({ policy: policyWith(ISS, 'independent') }));
  rawVc('status-lists-keyed-by-proto', 'statusLists has the member name __proto__.', 'KYA-VCB-016: prototype-keyed status list lookups are refused; the strict parser refuses the name before any lookup.', t => t.replace('"statusLists":{}', '"statusLists":{"__proto__":"x"}'));
  rawVc('status-lists-keyed-by-constructor', 'statusLists has the member name constructor.', 'KYA-VCB-016: prototype-keyed status list lookups are refused; the strict parser refuses the name before any lookup.', t => t.replace('"statusLists":{}', '"statusLists":{"constructor":"x"}'));
  rawVc('status-lists-keyed-by-prototype', 'statusLists has the member name prototype.', 'KYA-VCB-016: prototype-keyed status list lookups are refused; the strict parser refuses the name before any lookup.', t => t.replace('"statusLists":{}', '"statusLists":{"prototype":"x"}'));
  rawVc('input-with-text-after-the-object', 'The stdin text has text after the closing brace.', 'text after the value is refused.', t => t + '\n{}');
  rawVc('input-with-a-byte-order-mark', 'A byte order mark precedes the object.', 'a byte order mark is not whitespace and is refused.', t => '﻿' + t);
  rawVc('report-with-a-duplicate-member', 'The report text writes decision twice.', 'strict parsing refuses duplicate members in the report as in any other input.', t => t.replace('"decision":', '"decision":"qualified","decision":'), () => ({ report: clone(R) }));
  rawVc('report-with-an-unsafe-integer', 'The report text writes an integer above 9007199254740991.', 'integer-valued numbers above 9007199254740991 are refused whatever their spelling.', t => t.replace('"earned":1000', '"earned":9007199254740993'), () => ({ report: clone(R) }));
  rawVc('policy-nested-beyond-depth-32', 'The policy text carries a member holding an array nested 31 deep.', 'a value deeper than 32 is refused.', t => t.replace('"policy":{', '"policy":{"note":' + '['.repeat(31) + ']'.repeat(31) + ','), () => ({ policy: policyWith(ISS, 'independent') }));

  function policyWith(key, role) {
    const p = clone(PO0);
    p.trustedKeys = [...p.trustedKeys.filter(k => k.id !== keyId(key.pem)), { id: keyId(key.pem), publicKey: key.pem, role }].sort((a, c) => a.id < c.id ? -1 : 1);
    p.revokedKeyIds = p.revokedKeyIds.filter(k => k !== keyId(key.pem));
    return p;
  }
  return { keys: K };
}
