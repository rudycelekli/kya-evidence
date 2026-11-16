import { verify } from 'node:crypto';
import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, keyId, publicKeyObject, text, timestamp, validatePublicPem } from '../identity/domain/services/validation.mjs';

function captureIntent(input) {
  const intent = JSON.parse(canonical(input));
  exactKeys(intent, ['issuer', 'audience', 'challenge', 'publicKey', 'previousKeyId'], 'Enrollment intent');
  text(intent.issuer, 'Identity issuer');
  text(intent.audience, 'Audience');
  hash(intent.challenge, 'Enrollment challenge');
  validatePublicPem(intent.publicKey);
  if (intent.previousKeyId !== null) hash(intent.previousKeyId, 'Previous key ID');
  return {
    schema: 'kya.oidc-enrollment/v1', issuer: intent.issuer, audience: intent.audience,
    challenge: intent.challenge, keyId: keyId(intent.publicKey), previousKeyId: intent.previousKeyId,
  };
}

export function oidcEnrollmentNonce(intent) {
  return digest(captureIntent(intent));
}

export function oidcEnrollmentMessage(intent) {
  return Buffer.from('kya.oidc-enrollment/v1\n' + canonical(captureIntent(intent)), 'utf8');
}

export function createOidcEnrollmentAuthenticator({
  issuer, audience, verifyIdToken, resolvePrincipal, consumeNonce,
  clock = () => new Date().toISOString(),
}) {
  text(issuer, 'Identity issuer');
  text(audience, 'Audience');
  return async function authenticate(input, previousKeyId = null) {
    const session = JSON.parse(canonical(input));
    exactKeys(session, ['idToken', 'challenge', 'publicKey', 'signature'], 'OIDC enrollment');
    text(session.idToken, 'ID token', 24_000);
    const intent = { issuer, audience, previousKeyId, challenge: session.challenge, publicKey: session.publicKey };
    const nonce = oidcEnrollmentNonce(intent);
    const signature = session.signature;
    insist(typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), 'Invalid signature encoding');
    const bytes = Buffer.from(signature, 'base64url');
    insist(bytes.toString('base64url') === signature
      && verify(null, oidcEnrollmentMessage(intent), publicKeyObject(session.publicKey), bytes), 'Enrollment signature verification failed');

    // The host must authenticate token bytes using its OIDC verifier. This layer
    // applies the stricter enrollment claims and resolves the registered principal.
    const claims = JSON.parse(canonical(await verifyIdToken(session.idToken)));
    insist(claims && claims.iss === issuer && claims.aud === audience
      && (!Object.hasOwn(claims, 'azp') || claims.azp === audience)
      && claims.nonce === nonce, 'Enrollment claims differ');
    text(claims.sub, 'Identity subject', 255);
    const now = Math.floor(timestamp(clock()) / 1000);
    const { iat, exp, auth_time: authTime } = claims;
    insist([iat, exp, authTime].every(Number.isSafeInteger) && authTime <= iat && iat <= now
      && exp > now && now - authTime <= 300, 'Fresh login required');
    const principalId = await resolvePrincipal(issuer, claims.sub);
    insist(await consumeNonce(session.challenge) === true, 'Enrollment challenge unavailable');
    return { issuer, subject: claims.sub, principalId, publicKey: session.publicKey };
  };
}
