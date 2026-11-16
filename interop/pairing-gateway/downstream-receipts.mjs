import { verify } from 'node:crypto';
import { canonical, digest, exactKeys, insist, parseJson } from '../../src/shared/canonical.mjs';
import { hash, keyId, publicKeyObject, validatePublicPem } from '../../src/identity/domain/services/validation.mjs';
import { https } from './pilot-settings.mjs';

export function validateReceiptProfile(profile) {
  exactKeys(profile, ['url', 'publicKey', 'credentialRef'], 'Receipt profile');
  https(profile.url, 'Receipt endpoint', { pathOnly: true });
  validatePublicPem(profile.publicKey);
  insist(profile.credentialRef === null || (typeof profile.credentialRef === 'string' && profile.credentialRef.length > 0),
    'Invalid receipt credential reference');
  return profile;
}

export function pilotRouteRevision(mcp, { server, permission, passportId }, receiptProfile) {
  return digest({ server, endpoint: mcp.url, tool: mcp.tool, schemaDigest: mcp.schemaDigest, permission, passportId,
    ...(receiptProfile ? { receipts: {
      profile: 'kya.mcp-receipt/v1', endpoint: receiptProfile.url, keyId: keyId(receiptProfile.publicKey),
    } } : {}),
  });
}

export function receiptBytes(receipt) {
  return Buffer.from('kya.mcp-receipt/v1\n' + canonical(receipt), 'utf8');
}

export function receiptObserver(input, { server, tool, routeRevision, bearer, networkFetch = fetch }) {
  const profile = validateReceiptProfile(JSON.parse(canonical(input)));
  insist(profile.credentialRef === null || (typeof bearer === 'string' && /^[\x21-\x7e]+$/.test(bearer)),
    'Receipt credential missing or invalid');
  const key = publicKeyObject(profile.publicKey);
  const base = profile.url.replace(/\/$/, '');
  return async delivery => {
    const { operationId, requestDigest } = delivery;
    insist(delivery.server === server && delivery.tool === tool && delivery.routeRevision === routeRevision,
      'Receipt route differs from recorded delivery');
    hash(operationId, 'Operation ID');
    hash(requestDigest, 'Request digest');
    const reply = await networkFetch(base + '/' + operationId, {
      method: 'GET', redirect: 'error', signal: AbortSignal.timeout(10_000), cache: 'no-store',
      headers: { accept: 'application/json', ...(profile.credentialRef === null ? {} : { authorization: 'Bearer ' + bearer }) },
    });
    if (reply.status === 404 || reply.status === 202) {
      await reply.body?.cancel();
      return { operationId, outcome: 'unknown', receiptDigest: null };
    }
    insist(reply.status === 200, 'Receipt lookup failed');
    const chunks = [];
    let length = 0;
    for await (const chunk of reply.body) {
      length += chunk.length;
      insist(length <= 16_384, 'Receipt exceeds size limit');
      chunks.push(chunk);
    }
    const envelope = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    exactKeys(envelope, ['receipt', 'signature'], 'Receipt envelope');
    const { receipt, signature } = envelope;
    exactKeys(receipt, ['schema', 'operationId', 'requestDigest', 'routeRevision', 'outcome'], 'Terminal receipt');
    insist(receipt.schema === 'kya.mcp-receipt/v1' && receipt.operationId === operationId
      && receipt.requestDigest === requestDigest && receipt.routeRevision === routeRevision, 'Receipt binding mismatch');
    insist(receipt.outcome === 'confirmed-applied' || receipt.outcome === 'confirmed-not-applied', 'Invalid receipt outcome');
    insist(typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), 'Invalid receipt signature');
    const bytes = Buffer.from(signature, 'base64url');
    insist(bytes.toString('base64url') === signature && verify(null, receiptBytes(receipt), key, bytes), 'Invalid receipt signature');
    return { operationId, outcome: receipt.outcome, receiptDigest: digest(envelope) };
  };
}
