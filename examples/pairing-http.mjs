import { digest, hashBytes, parseJson } from 'kya-evidence';
import { verifyPairedAction } from 'kya-evidence/pairing';

const maxBodyBytes = 65_536;
const maxProofHeader = 8_192;

export function actionRequestDigest(method, target, body) {
  return digest({ method, target, bodyDigest: hashBytes(body) });
}

// A single route receives opaque bytes. The server supplies the exact route policy
// and the current trust context. The store owns atomic consumption and expiry.
export function createPairingHandler({ getContext, consumeChallenge, onAction }) {
  return async function handle(request, response) {
    if (request.method !== 'POST' || request.url !== '/action') {
      response.writeHead(404).end();
      return;
    }
    let action;
    let body;
    let accepted;
    try {
      const headers = request.headersDistinct['kya-pairing-proof'];
      const encoded = headers?.[0];
      if (headers?.length !== 1 || encoded.length > maxProofHeader || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
        throw new Error('Invalid proof header');
      }
      const wire = Buffer.from(encoded, 'base64url');
      if (wire.toString('base64url') !== encoded) throw new Error('Invalid proof encoding');
      const proof = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(wire));
      action = proof?.action?.payload;

      const chunks = [];
      let size = 0;
      for await (const chunk of request.iterator({ destroyOnReturn: false })) {
        size += chunk.length;
        if (size > maxBodyBytes) {
          response.writeHead(413, { connection: 'close' }).end();
          return;
        }
        chunks.push(chunk);
      }
      body = Buffer.concat(chunks);
      const context = await getContext(action?.challenge);
      accepted = verifyPairedAction(proof, {
        ...context,
        requestDigest: actionRequestDigest(request.method, request.url, body),
      });
      if (await consumeChallenge(context) !== true) throw new Error('Challenge unavailable');
    } catch {
      response.writeHead(403).end();
      return;
    }
    try {
      await onAction(body, accepted);
      response.writeHead(204).end();
    } catch {
      response.writeHead(500).end();
    }
  };
}
