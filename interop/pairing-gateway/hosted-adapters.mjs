import { createServer } from 'node:http';
import * as oidc from 'openid-client';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { digest, insist } from '../../src/shared/canonical.mjs';
import { oidcEnrollmentNonce } from '../../src/pairing/oidc-enrollment.mjs';

export async function discoverPilotOidc(settings, credential) {
  const issuer = new URL(settings.issuer);
  insist(issuer.protocol === 'https:' && !issuer.username && !issuer.password && !issuer.search && !issuer.hash,
    'Pilot issuer requires HTTPS');
  const authentication = {
    none: oidc.None,
    client_secret_basic: oidc.ClientSecretBasic,
    client_secret_post: oidc.ClientSecretPost,
    private_key_jwt: oidc.PrivateKeyJwt,
  };
  insist(Object.hasOwn(authentication, settings.authentication), 'Unsupported client authentication');
  insist(settings.authentication === 'none' || credential, 'OIDC credential missing');
  return oidc.discovery(issuer, settings.clientId, undefined, authentication[settings.authentication](credential), {
    execute: [oidc.enableNonRepudiationChecks], timeout: 10,
    [oidc.customFetch]: (input, init) => fetch(input, { ...init, redirect: 'error' }),
  });
}

export async function receivePilotLogin(configuration, { callback, port, intent, onAuthorizationUrl, timeoutMs = 300_000 }) {
  const registered = new URL(callback);
  insist(!registered.search && !registered.hash && !registered.username && !registered.password, 'Invalid callback URL');
  const nonce = oidcEnrollmentNonce(intent);
  const state = oidc.randomState();
  const verifier = oidc.randomPKCECodeVerifier();
  const authorization = oidc.buildAuthorizationUrl(configuration, {
    redirect_uri: callback, scope: 'openid', state, nonce, code_challenge_method: 'S256',
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier), max_age: '300', prompt: 'login',
  });

  let consumed = false;
  let server;
  let timer;
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('OIDC login timed out')), timeoutMs);
      server = createServer({ requestTimeout: 10_000, headersTimeout: 5_000 }, async (request, response) => {
        const reply = (status, message) => {
          response.writeHead(status, {
            'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store',
            'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'none'",
          });
          response.end(message);
        };
        if (request.method !== 'GET' || !request.url?.startsWith('/') || request.url.startsWith('//')) {
          return reply(404, 'Callback unavailable');
        }
        let inbound;
        try { inbound = new URL(request.url, registered.origin); }
        catch { return reply(400, 'Invalid callback URL'); }
        if (inbound.pathname !== registered.pathname || inbound.origin !== registered.origin) return reply(404, 'Callback unavailable');
        const query = inbound.searchParams;
        if (query.getAll('state').length !== 1 || query.get('state') !== state) return reply(400, 'Invalid callback state');
        if (consumed) return reply(409, 'Callback already used');
        consumed = true;
        if (query.getAll('code').length !== 1 || !query.get('code') || query.has('error')) {
          reply(400, 'Sign-in did not complete');
          return reject(new Error('OIDC authorization refused'));
        }
        try {
          // The reverse proxy's Host and forwarding headers cannot change redirect_uri.
          const current = new URL(callback);
          current.search = inbound.search;
          const tokens = await oidc.authorizationCodeGrant(configuration, current, {
            pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, maxAge: 300, idTokenExpected: true,
          });
          const claims = tokens.claims();
          insist(tokens.id_token && claims, 'Verified ID token missing');
          reply(200, 'Sign-in verified. Return to the pilot console.');
          resolve({ idToken: tokens.id_token, claims });
        } catch {
          reply(400, 'Unable to verify sign-in');
          reject(new Error('OIDC token exchange or verification failed'));
        }
      });
      server.on('error', reject);
      server.listen(port, '127.0.0.1', () => {
        Promise.resolve().then(() => onAuthorizationUrl(authorization.href, server.address().port)).catch(reject);
      });
    });
  } finally {
    clearTimeout(timer);
    if (server?.listening) {
      await new Promise(resolve => server.close(resolve));
    }
  }
}

export async function openPilotMcp(settings, {
  bearer, server, revision, networkFetch = fetch,
}) {
  const endpoint = new URL(settings.url);
  insist(endpoint.protocol === 'https:' && !endpoint.username && !endpoint.password && !endpoint.hash,
    'Pilot MCP endpoint requires HTTPS');
  insist(bearer === undefined || (typeof bearer === 'string' && /^[\x21-\x7e]+$/.test(bearer)), 'Invalid MCP credential');
  const client = new Client({ name: 'kya-hosted-pilot', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(endpoint, {
    requestInit: bearer === undefined ? {} : { headers: { authorization: 'Bearer ' + bearer } },
    fetch(input, init) {
      const target = new URL(input instanceof Request ? input.url : input);
      insist(target.href === endpoint.href, 'MCP transport attempted an unpinned endpoint');
      return networkFetch(input, { ...init, redirect: 'error' });
    },
    reconnectionOptions: { maxRetries: 0, initialReconnectionDelay: 1,
      maxReconnectionDelay: 1, reconnectionDelayGrowFactor: 1 },
  });

  async function checkTool() {
    let cursor;
    let found;
    for (let page = 0; page < 20; page++) {
      const listed = await client.listTools(cursor ? { cursor } : undefined, { timeout: 10_000 });
      for (const tool of listed.tools) {
        if (tool.name !== settings.tool) continue;
        insist(!found, 'Duplicate MCP pilot tool');
        found = tool;
      }
      if (listed.nextCursor === undefined) {
        insist(found && digest(found.inputSchema) === settings.schemaDigest, 'MCP tool schema differs from approved schema');
        return;
      }
      insist(listed.nextCursor && listed.nextCursor !== cursor, 'Invalid MCP pagination');
      cursor = listed.nextCursor;
    }
    throw new Error('MCP tool listing exceeded pilot limit');
  }

  try {
    await client.connect(transport, { timeout: 10_000 });
    await checkTool();
  } catch (error) {
    await client.close();
    throw error;
  }
  return {
    async forward(serverId, routeRevision, request) {
      insist(serverId === server && routeRevision === revision && request.method === 'tools/call'
        && request.params.name === settings.tool, 'MCP route differs from approved pilot route');
      await checkTool();
      return client.callTool(request.params, undefined, { timeout: 30_000 });
    },
    close: () => client.close(),
  };
}
