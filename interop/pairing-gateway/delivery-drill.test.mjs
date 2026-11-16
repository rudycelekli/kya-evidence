import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { digest } from '../../src/index.mjs';
import { mcpToolCallDigest, openPairingGateway } from '../../src/pairing/mcp-gateway.mjs';
import { passportId, passportPublicKey, signPassportEvent } from '../../src/passport/index.mjs';
import { openPassportRegistry } from '../../src/passport/registry.mjs';
import { receiptBytes } from './downstream-receipts.mjs';

test('crash after an MCP response reconciles a signed receipt without resending the tool call', { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kya-receipt-drill-'));
  const path = name => join(dir, name);
  const save = (name, data) => writeFileSync(path(name), JSON.stringify(data), { mode: 0o600 });
  const keys = ['controller', 'principal', 'agent', 'receipt'].map(name => {
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(path(name + '.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    return privateKey;
  });
  const [controller, , agent, receiptKey] = keys;
  const schema = { type: 'object', additionalProperties: false };
  const settings = {
    oidc: { issuer: 'https://identity.example.test', clientId: 'fixture-client', callback: 'https://gateway.example.test/callback',
      authentication: 'none', credentialRef: null, testIdentityRef: 'pilot:fixture' },
    gateway: { url: 'https://gateway.example.test', registry: 'https://registry.example.test',
      deploymentRef: 'pilot:gateway', storageRef: 'pilot:sqlite' },
    mcp: { url: 'https://tool.example.test/mcp', transport: 'streamable-http', tool: 'read',
      schemaDigest: digest(schema), credentialRef: 'vault://pilot/tool', testCaseRef: 'pilot:case', receiptRef: 'pilot:receipt' },
  };
  const receiptProfile = { url: 'https://receipt.example.test/status', publicKey: passportPublicKey(receiptKey),
    credentialRef: 'vault://pilot/receipt' };
  const manifest = JSON.parse(readFileSync(new URL('../../examples/manifest.json', import.meta.url)));
  manifest.issuedAt = new Date(Date.now() - 30_000).toISOString();
  manifest.expiresAt = new Date(Date.now() + 300_000).toISOString();
  save('manifest.json', manifest);
  const event = {
    schema: 'kya.passport-event/v1', operation: 'register', registry: settings.gateway.registry, previous: null,
    agentId: manifest.agent.id, principalId: manifest.principal.id, manifestDigest: digest(manifest),
    controllerPublicKey: passportPublicKey(controller), agentPublicKey: passportPublicKey(agent),
  };
  event.passportId = passportId(event);
  const registry = openPassportRegistry(path('registry.sqlite'), settings.gateway.registry);
  registry.append({ event, controllerSignature: signPassportEvent(event, controller), agentSignature: signPassportEvent(event, agent) });
  registry.close();
  const result = { content: [{ type: 'text', text: 'synthetic response' }] };
  const inputs = {
    expectedSubject: 'fixture-user', callbackPort: 7338, gatewayDatabase: path('gateway.sqlite'),
    registryDatabase: path('registry.sqlite'), passportId: event.passportId, manifestFile: path('manifest.json'),
    principalKeyFile: path('principal.pem'), agentKeyFile: path('agent.pem'), previousPrincipalKeyId: null,
    server: 'pilot:tool', permission: 'read', arguments: {}, expectedResultDigest: digest(result),
  };
  save('settings.json', settings);
  save('inputs.json', inputs);
  save('receipt.json', receiptProfile);

  const sdk = new Server({ name: 'receipt-fixture', version: '1' }, { capabilities: { tools: {} } });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: randomUUID, enableJsonResponse: true });
  const calls = [];
  let receiptMode = 'pending';
  sdk.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'read', inputSchema: schema }] }));
  sdk.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
    const metadata = params._meta?.['kya-evidence/delivery'];
    assert.equal(metadata?.requestDigest, mcpToolCallDigest({
      server: inputs.server, tool: params.name, arguments: params.arguments,
    }));
    calls.push(params);
    return result;
  });
  await sdk.connect(transport);
  const http = createServer((request, response) => {
    if (request.url === '/mcp') {
      if (request.headers.authorization !== 'Bearer fixture-mcp') return response.writeHead(401).end();
      return transport.handleRequest(request, response);
    }
    if (request.method !== 'GET' || request.headers.authorization !== 'Bearer fixture-receipt') {
      return response.writeHead(401).end();
    }
    const metadata = calls[0]?._meta?.['kya-evidence/delivery'];
    if (!metadata || request.url !== '/status/' + metadata.operationId || receiptMode === 'pending') {
      return response.writeHead(404).end();
    }
    const receipt = {
      schema: 'kya.mcp-receipt/v1', ...metadata, outcome: 'confirmed-applied',
      ...(receiptMode === 'wrong-request' ? { requestDigest: digest('wrong request') } : {}),
    };
    const key = receiptMode === 'wrong-key' ? controller : receiptKey;
    const signature = sign(null, receiptBytes(receipt), key).toString('base64url');
    return response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ receipt, signature }));
  });
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve));
  try {
    const local = 'http://127.0.0.1:' + http.address().port;
    writeFileSync(path('loopback.mjs'), `
      const realFetch = globalThis.fetch;
      globalThis.fetch = (input, options) => {
        const url = new URL(input instanceof Request ? input.url : input);
        if (!['https://tool.example.test', 'https://receipt.example.test'].includes(url.origin) || options.redirect !== 'error') {
          throw new Error('Unexpected fixture network request');
        }
        return realFetch(${JSON.stringify(local)} + url.pathname, options);
      };
    `);
    const child = `
      import { readFileSync } from 'node:fs';
      import { runPilot } from './interop/pairing-gateway/hosted-pilot.mjs';
      import { openPilotMcp } from './interop/pairing-gateway/hosted-adapters.mjs';
      import { oidcEnrollmentNonce } from './src/pairing/oidc-enrollment.mjs';
      const [settings, inputs, receiptProfile] = process.argv.slice(1).map(path => JSON.parse(readFileSync(path)));
      await runPilot(settings, inputs, {
        receiptProfile,
        login(oidc, intent) {
          const now = Math.floor(Date.now() / 1000);
          return { idToken: 'fixture-login', claims: { iss: oidc.issuer, aud: oidc.clientId, sub: inputs.expectedSubject,
            nonce: oidcEnrollmentNonce(intent), iat: now, exp: now + 60, auth_time: now } };
        },
        async connect(settings, hint) {
          const adapter = await openPilotMcp(settings, { ...hint, bearer: 'fixture-mcp' });
          return { close: adapter.close, async forward(...args) {
            await adapter.forward(...args);
            process.exit(75);
          } };
        },
      });
    `;
    const invoke = args => promisify(execFile)(process.execPath, ['--import', path('loopback.mjs'), ...args], {
      cwd: new URL('../..', import.meta.url), timeout: 8_000,
      env: { ...process.env, KYA_PILOT_RECEIPT_BEARER: 'fixture-receipt' },
    });
    await assert.rejects(invoke(['--input-type=module', '-e', child, path('settings.json'), path('inputs.json'), path('receipt.json')]), { code: 75 });
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].arguments, {});
    const metadata = calls[0]._meta['kya-evidence/delivery'];
    assert.equal(metadata.requestDigest, mcpToolCallDigest({ server: inputs.server, tool: 'read', arguments: {} }));
    const reconcile = ['interop/pairing-gateway/hosted-pilot.mjs', path('settings.json'), path('inputs.json'),
      '--reconcile', path('receipt.json'), metadata.operationId];
    await assert.rejects(invoke(reconcile), error => error.code === 1 && JSON.parse(error.stdout).state === 'dispatching');
    for (const mode of ['wrong-key', 'wrong-request']) {
      receiptMode = mode;
      await assert.rejects(invoke(reconcile), error => error.code === 1 && error.stdout === '');
    }
    receiptMode = 'valid';
    const verified = JSON.parse((await invoke(reconcile)).stdout);
    assert.equal(verified.operationId, metadata.operationId);
    assert.equal(verified.state, 'confirmed-applied');
    assert.match(verified.receiptDigest, /^[a-f0-9]{64}$/);
    const reopened = openPairingGateway(inputs.gatewayDatabase, {});
    try {
      assert.equal(reopened.readDelivery(metadata.operationId).receiptDigest, verified.receiptDigest);
    } finally {
      reopened.close();
    }
    assert.equal(calls.length, 1);
  } finally {
    await sdk.close();
    http.closeAllConnections();
    await new Promise(resolve => http.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});
