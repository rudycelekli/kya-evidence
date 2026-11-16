import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Provider from 'oidc-provider';
import * as oidc from 'openid-client';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { digest, keyId } from '../../src/index.mjs';
import { signPairedAction, signPairingGrant } from '../../src/pairing/index.mjs';
import { mcpToolCallDigest, openPairingGateway } from '../../src/pairing/mcp-gateway.mjs';
import { createOidcEnrollmentAuthenticator, oidcEnrollmentMessage, oidcEnrollmentNonce } from '../../src/pairing/oidc-enrollment.mjs';

import { passportId, signPassportEvent } from '../../src/passport/index.mjs';
import { openPassportRegistry } from '../../src/passport/registry.mjs';

const directory = await mkdtemp(join(tmpdir(), 'kya-local-interop-'));
const manifest = JSON.parse(await readFile(new URL('../../examples/manifest.json', import.meta.url)));
const principalId = manifest.principal.id;
const date = offset => new Date(Date.now() + offset).toISOString();
manifest.issuedAt = date(-60_000);
manifest.expiresAt = date(3_600_000);
manifest.scope.permissions.push('read:fixture');
manifest.system.tools.push({ id: 'read_fixture', version: '1', permissions: ['read:fixture'] });
const call = { server: 'fixture:stdio', tool: 'read_fixture', arguments: { path: 'synthetic.txt' } };
const route = { manifest, audience: 'fixture:gateway', permission: 'read:fixture', revision: 'ab'.repeat(32),
  revokedKeyIds: [], revokedGrantDigests: [] };
const clientId = 'kya-fixture';
const providerKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
let provider;
let providerCallback;
const http = createServer((request, response) => {
  if (!request.url.startsWith('/interaction/')) return providerCallback(request, response);
  (async () => {
    const { prompt, params, session } = await provider.interactionDetails(request, response);
    if (prompt.name === 'login') {
      return provider.interactionFinished(request, response, { login: { accountId: 'synthetic-user' } },
        { mergeWithLastSubmission: false });
    }
    assert.equal(prompt.name, 'consent');
    const grant = new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
    grant.addOIDCScope(prompt.details.missingOIDCScope.join(' '));
    return provider.interactionFinished(request, response, { consent: { grantId: await grant.save() } });
  })().catch(error => { console.error(error.message); response.writeHead(500).end(); });
});
await new Promise(resolve => http.listen(0, '127.0.0.1', resolve));
const issuer = 'http://127.0.0.1:' + http.address().port;
const redirectUri = issuer + '/callback';
provider = new Provider(issuer, {
  clients: [{ client_id: clientId, token_endpoint_auth_method: 'none', redirect_uris: [redirectUri],
    grant_types: ['authorization_code'], response_types: ['code'] }],
  jwks: { keys: [{ ...providerKey, kid: 'local-fixture', alg: 'RS256', use: 'sig' }] },
  cookies: { keys: [generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex')], short: { secure: false }, long: { secure: false } },
  features: { devInteractions: { enabled: false } },
  interactions: { url: (_ctx, interaction) => '/interaction/' + interaction.uid },
  findAccount(_ctx, id) { return { accountId: id, claims: () => ({ sub: id }) }; },
});
providerCallback = provider.callback();
const client = new Client({ name: 'kya-fixture', version: '1.0.0' });
let gateway;
let passports;
try {
  await client.connect(new StdioClientTransport({
    command: process.execPath, args: [fileURLToPath(new URL('./mcp-fixture.mjs', import.meta.url))],
  }));
  const config = await oidc.discovery(new URL(issuer), clientId, undefined, oidc.None(), {
    execute: [oidc.allowInsecureRequests, oidc.enableNonRepudiationChecks],
  });
  const checkedTokens = new Map();
  passports = openPassportRegistry(join(directory, 'passports.sqlite'), issuer);
  gateway = openPairingGateway(join(directory, 'gateway.sqlite'), {
    authenticateIdentity: createOidcEnrollmentAuthenticator({
      issuer, audience: clientId,
      verifyIdToken(idToken) {
        const claims = checkedTokens.get(idToken);
        assert.ok(claims, 'ID token must come from the verified code exchange');
        return claims;
      },
      resolvePrincipal(iss, sub) {
        assert.equal(iss, issuer);
        assert.equal(sub, 'synthetic-user');
        return principalId;
      },
      consumeNonce: challenge => gateway.consumeEnrollmentChallenge(challenge),
    }),
    resolveRoute: () => route,
    passports: { registry: issuer, readHistory: id => passports.read(id)?.history ?? null },
    forward(server, revision, request) {
      assert.equal(server, call.server);
      assert.equal(revision, route.revision);
      return client.callTool(request.params);
    },
  });

  async function login(key, previousKeyId) {
    const intent = {
      issuer, audience: clientId, challenge: gateway.issueEnrollmentChallenge(), previousKeyId,
      publicKey: key.publicKey.export({ format: 'pem', type: 'spki' }),
    };
    const nonce = oidcEnrollmentNonce(intent);
    const state = oidc.randomState();
    const codeVerifier = oidc.randomPKCECodeVerifier();
    let url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri, scope: 'openid', nonce, state, max_age: '300', prompt: 'login',
      code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier), code_challenge_method: 'S256',
    });
    const cookies = new Map();
    for (let redirects = 0; !url.href.startsWith(redirectUri + '?'); redirects++) {
      assert.ok(redirects < 12);
      const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5000),
        headers: { cookie: [...cookies.values()].join('; ') } });
      for (const value of response.headers.getSetCookie()) {
        const pair = value.split(';', 1)[0];
        cookies.set(pair.split('=', 1)[0], pair);
      }
      assert.ok(response.headers.has('location'), 'Expected provider redirect, got HTTP ' + response.status);
      url = new URL(response.headers.get('location'), url);
      assert.equal(url.origin, issuer);
      await response.body?.cancel();
    }
    const tokens = await oidc.authorizationCodeGrant(config, url, {
      pkceCodeVerifier: codeVerifier, expectedNonce: nonce, expectedState: state, maxAge: 300, idTokenExpected: true,
    });
    checkedTokens.set(tokens.id_token, tokens.claims());
    return { idToken: tokens.id_token, publicKey: intent.publicKey, challenge: intent.challenge,
      signature: sign(null, oidcEnrollmentMessage(intent), key.privateKey).toString('base64url') };
  }

  const [old, current, agent, replacement, recovery, newController, newAgent] = Array.from({ length: 7 }, () => generateKeyPairSync('ed25519'));
  const pem = key => key.publicKey.export({ format: 'pem', type: 'spki' });
  const event = {
    schema: 'kya.passport-event/v2', recoveryPublicKey: pem(recovery), registry: issuer, operation: 'register', previous: null,
    principalId, agentId: manifest.agent.id, manifestDigest: digest(manifest),
    controllerPublicKey: pem(current), agentPublicKey: pem(agent),
  };
  event.passportId = passportId(event);
  route.passportId = event.passportId;
  const register = (payload, key, controller = current) => passports.append({
    event: payload, controllerSignature: signPassportEvent(payload, controller.privateKey),
    agentSignature: key ? signPassportEvent(payload, key.privateKey) : null,
    recoverySignature: ['register', 'recover'].includes(payload.operation)
      ? signPassportEvent(payload, recovery.privateKey) : null,
  });
  const initial = register(event, agent);
  const enrolled = await gateway.enrollIdentity(await login(old, null));
  const stale = gateway.issueChallenge(call);
  const rotated = await gateway.rotateIdentity(await login(current, enrolled.keyId), enrolled.keyId);
  assert.equal(rotated.keyId, keyId(current.publicKey));

  function proof(challenge, signer, agentKey = agent) {
    const grant = signPairingGrant({ schema: 'kya.pairing-grant/v1', principalId,
      agentKeyId: keyId(agentKey.publicKey), manifestDigest: digest(manifest),
      audience: route.audience, permission: route.permission,
      issuedAt: date(-10_000), expiresAt: date(300_000),
    }, signer.privateKey);
    return { grant, action: signPairedAction({ schema: 'kya.paired-action/v1',
      grantDigest: digest(grant), challenge, requestDigest: mcpToolCallDigest(call),
    }, agentKey.privateKey) };
  }
  await assert.rejects(gateway.invoke(call, proof(stale, old)), /challenge/i);
  const challenge = gateway.issueChallenge(call);
  const accepted = proof(challenge, current);
  await assert.rejects(gateway.invoke({ ...call, arguments: { path: 'different.txt' } }, accepted), /challenge/i);
  const { result, audit } = await gateway.invoke(call, accepted);
  assert.deepEqual(JSON.parse(result.content[0].text), { name: call.tool, arguments: call.arguments });
  assert.equal(audit.principalKeyId, rotated.keyId);
  assert.deepEqual(gateway.readAudit(challenge), audit);
  await assert.rejects(gateway.invoke(call, accepted), /challenge/i);
  assert.equal(audit.passportHead, initial.head);
  const update = gateway.issueChallenge(call);
  const nextPassport = register({
    ...event, operation: 'rotate', previous: initial.head, agentPublicKey: pem(replacement),
  }, replacement);
  await assert.rejects(gateway.invoke(call, proof(update, current)), /passport authorization refused/i);
  assert.equal((await gateway.invoke(call, proof(update, current, replacement))).audit.passportHead, nextPassport.head);
  const afterRecovery = gateway.issueChallenge(call);
  const recovered = register({
    ...event, operation: 'recover', previous: nextPassport.head,
    controllerPublicKey: pem(newController), agentPublicKey: pem(newAgent),
  }, newAgent, newController);
  await assert.rejects(gateway.invoke(call, proof(afterRecovery, current, replacement)), /passport authorization refused/i);
  assert.equal((await gateway.invoke(call, proof(afterRecovery, current, newAgent))).audit.passportHead, recovered.head);
  const revoked = gateway.issueChallenge(call);
  register({ ...event, operation: 'revoke', previous: recovered.head,
    controllerPublicKey: pem(newController), agentPublicKey: null }, null, newController);
  await assert.rejects(gateway.invoke(call, proof(revoked, current, newAgent)), /passport authorization refused/i);
  console.log('Passed: OIDC PKCE, principal rotation, Passport recovery and revocation, exact MCP stdio and replay refusal');
} finally {
  gateway?.close();
  passports?.close();
  await client.close();
  await new Promise(resolve => http.close(resolve));
  await rm(directory, { recursive: true, force: true });
}
