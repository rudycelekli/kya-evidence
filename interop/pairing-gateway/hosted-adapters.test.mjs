import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { digest } from '../../src/index.mjs';
import { openPilotMcp } from './hosted-adapters.mjs';

test('authenticated MCP transport forwards the pinned tool and refuses a modified schema before dispatch', async () => {
  let inputSchema = { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] };
  const calls = [];
  const sdk = new Server({ name: 'fixture-tool', version: '1' }, { capabilities: { tools: {} } });
  sdk.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'read_fixture', inputSchema }] }));
  sdk.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
    calls.push(params);
    return { content: [{ type: 'text', text: 'fixture response' }] };
  });
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: randomUUID, enableJsonResponse: true,
  });
  await sdk.connect(transport);
  const http = createServer((req, res) => {
    if (req.headers.authorization !== 'Bearer synthetic-token') return res.writeHead(401).end();
    return transport.handleRequest(req, res);
  });
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve));
  let adapter;
  try {
    const pinned = 'https://tool.example.test/mcp';
    const local = 'http://127.0.0.1:' + http.address().port + '/mcp';
    adapter = await openPilotMcp({ url: pinned, tool: 'read_fixture', schemaDigest: digest(inputSchema) }, {
      server: 'test:tools', revision: '01'.repeat(32), bearer: 'synthetic-token',
      networkFetch(input, init) {
        assert.equal(String(input), pinned);
        assert.equal(init.redirect, 'error');
        return fetch(local, init);
      },
    });
    const request = { method: 'tools/call', params: { name: 'read_fixture', arguments: { path: 'synthetic' } } };
    await assert.rejects(adapter.forward('other:tools', '01'.repeat(32), request), /approved pilot route/);
    const approvedSchema = inputSchema;
    inputSchema = { ...inputSchema, required: [] };
    await assert.rejects(adapter.forward('test:tools', '01'.repeat(32), request), /approved schema/);
    assert.deepEqual(calls, []);
    inputSchema = approvedSchema;
    const response = await adapter.forward('test:tools', '01'.repeat(32), request);
    assert.deepEqual(response.content, [{ type: 'text', text: 'fixture response' }]);
    assert.deepEqual(calls, [request.params]);
  } finally {
    await adapter?.close();
    await sdk.close();
    http.closeAllConnections();
    await new Promise(resolve => http.close(resolve));
  }
});

test('pilot runner pins the enrolled subject and Passport and returns only outcome digests', async t => {
  const { generateKeyPairSync } = await import('node:crypto');
  const { mkdtempSync, readFileSync, rmSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { runPilot } = await import('./hosted-pilot.mjs');
  const { oidcEnrollmentNonce } = await import('../../src/pairing/oidc-enrollment.mjs');
  const { passportId, passportPublicKey, signPassportEvent } = await import('../../src/passport/index.mjs');
  const { openPassportRegistry } = await import('../../src/passport/registry.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'kya-hosted-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const paths = name => join(dir, name);
  const settings = {
    oidc: { issuer: 'https://id.example.test/tenant', clientId: 'test-client', callback: 'https://gateway.example.test/callback',
      authentication: 'none', credentialRef: null, testIdentityRef: 'pilot:user' },
    gateway: { url: 'https://gateway.example.test', registry: 'https://registry.example.test',
      deploymentRef: 'pilot:deploy', storageRef: 'pilot:sqlite' },
    mcp: { url: 'https://tool.example.test/mcp', transport: 'streamable-http', tool: 'read',
      schemaDigest: digest({ type: 'object' }), credentialRef: null, testCaseRef: 'pilot:case', receiptRef: null },
  };
  const manifest = JSON.parse(readFileSync(new URL('../../examples/manifest.json', import.meta.url)));
  manifest.issuedAt = new Date(Date.now() - 30_000).toISOString();
  manifest.expiresAt = new Date(Date.now() + 300_000).toISOString();
  writeFileSync(paths('manifest.json'), JSON.stringify(manifest));
  const [controller, principal, agent] = ['controller', 'principal', 'agent'].map(name => {
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(paths(name + '.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    return privateKey;
  });
  const event = {
    schema: 'kya.passport-event/v1', operation: 'register', registry: settings.gateway.registry, previous: null,
    agentId: manifest.agent.id, principalId: manifest.principal.id, manifestDigest: digest(manifest),
    controllerPublicKey: passportPublicKey(controller), agentPublicKey: passportPublicKey(agent),
  };
  event.passportId = passportId(event);
  const registry = openPassportRegistry(paths('registry.sqlite'), settings.gateway.registry);
  const registered = registry.append({ event, controllerSignature: signPassportEvent(event, controller),
    agentSignature: signPassportEvent(event, agent) });
  registry.close();
  const expected = { content: [{ type: 'text', text: 'fixture output' }] };
  const inputs = {
    expectedSubject: 'synthetic-user', callbackPort: 7338, gatewayDatabase: paths('gateway.sqlite'),
    registryDatabase: paths('registry.sqlite'), passportId: registered.passportId, manifestFile: paths('manifest.json'),
    principalKeyFile: paths('principal.pem'), agentKeyFile: paths('agent.pem'), previousPrincipalKeyId: null,
    server: 'pilot:server', permission: 'read', arguments: { path: 'fixture' }, expectedResultDigest: digest(expected),
  };
  let subject = 'different-user';
  const forwarded = [];
  const adapters = {
    login(oidc, intent) {
      const now = Math.floor(Date.now() / 1000);
      return { idToken: 'local-adapter-fixture', claims: {
        iss: oidc.issuer, aud: oidc.clientId, sub: subject, nonce: oidcEnrollmentNonce(intent),
        iat: now, exp: now + 60, auth_time: now,
      } };
    },
    connect() {
      return {
        forward(server, revision, request, { operationId }) {
          forwarded.push({ server, revision, request, operationId });
          return expected;
        },
        close() {},
      };
    },
  };
  await assert.rejects(runPilot(settings, inputs, adapters), /unexpected pilot identity/i);
  assert.deepEqual(forwarded, []);
  subject = inputs.expectedSubject;
  const result = await runPilot(settings, inputs, adapters);
  assert.equal(result.resultMatched, true);
  assert.equal(result.passportHead, registered.head);
  assert.equal(result.operationId, forwarded[0].operationId);
  assert.equal(result.resultDigest, inputs.expectedResultDigest);
  assert.deepEqual(forwarded[0].request.params, { name: 'read', arguments: inputs.arguments });
  assert.deepEqual(Object.keys(result).sort(), ['operationId', 'passportHead', 'requestDigest', 'resultDigest', 'resultMatched'].sort());
});
