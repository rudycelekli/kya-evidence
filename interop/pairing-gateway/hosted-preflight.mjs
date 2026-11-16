import { readFile } from 'node:fs/promises';
import { exactKeys, insist, parseJson } from '../../src/shared/canonical.mjs';
import { hash, identifier, text } from '../../src/identity/domain/services/validation.mjs';

function https(value, label, { pathOnly = false } = {}) {
  text(value, label, 2048);
  const url = new URL(value);
  insist(url.protocol === 'https:' && !url.username && !url.password && !url.hash && (!pathOnly || !url.search),
    label + ' must be an HTTPS URL');
  return url;
}

function validate(config) {
  exactKeys(config, ['oidc', 'gateway', 'mcp'], 'Pilot configuration');
  const { oidc, gateway, mcp } = config;
  exactKeys(oidc, ['issuer', 'clientId', 'callback', 'authentication', 'credentialRef', 'testIdentityRef'], 'Pilot OIDC');
  const issuer = https(oidc.issuer, 'OIDC issuer', { pathOnly: true });
  text(oidc.clientId, 'OIDC client ID');
  https(oidc.callback, 'OIDC callback', { pathOnly: true });
  insist(['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'].includes(oidc.authentication),
    'Unsupported OIDC client authentication');
  if (oidc.authentication === 'none') insist(oidc.credentialRef === null, 'Public clients use a null credential reference');
  else identifier(oidc.credentialRef, 'OIDC credential reference');
  identifier(oidc.testIdentityRef, 'Test identity reference');

  exactKeys(gateway, ['url', 'registry', 'deploymentRef', 'storageRef'], 'Pilot gateway');
  https(gateway.url, 'Gateway URL', { pathOnly: true });
  https(gateway.registry, 'Registry URL', { pathOnly: true });
  identifier(gateway.deploymentRef, 'Deployment reference');
  identifier(gateway.storageRef, 'Storage reference');

  exactKeys(mcp, ['url', 'transport', 'tool', 'schemaDigest', 'credentialRef', 'testCaseRef', 'receiptRef'], 'Pilot MCP');
  https(mcp.url, 'MCP URL', { pathOnly: true });
  insist(mcp.transport === 'streamable-http', 'Pilot requires the streamable HTTP adapter');
  insist(typeof mcp.tool === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(mcp.tool), 'Invalid MCP tool');
  hash(mcp.schemaDigest, 'Tool schema digest');
  if (mcp.credentialRef !== null) identifier(mcp.credentialRef, 'MCP credential reference');
  identifier(mcp.testCaseRef, 'MCP test case reference');
  if (mcp.receiptRef !== null) identifier(mcp.receiptRef, 'MCP receipt interface reference');
  return { issuer, oidc, mcp };
}

async function discovery(issuer, config) {
  const url = issuer.href.replace(/\/$/, '') + '/.well-known/openid-configuration';
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
  insist(response.ok, 'OIDC discovery request failed');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    insist(size <= 65_536, 'OIDC discovery document is too large');
    chunks.push(chunk);
  }
  const metadata = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  insist(metadata.issuer === config.issuer, 'OIDC issuer metadata mismatch');
  for (const name of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) https(metadata[name], 'OIDC endpoint');
  insist(metadata.response_types_supported?.includes('code'), 'Authorization Code flow unavailable');
  if (metadata.code_challenge_methods_supported !== undefined) {
    insist(metadata.code_challenge_methods_supported.includes('S256'), 'OIDC metadata does not advertise S256');
  }
  const methods = metadata.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
  insist(methods.includes(config.authentication), 'OIDC client authentication unavailable');
  return metadata.code_challenge_methods_supported === undefined ? 'unadvertised' : 'advertised';
}

try {
  const [file, mode] = process.argv.slice(2);
  insist(mode === undefined || mode === '--discover', 'Expected optional --discover');
  const { issuer, oidc, mcp } = validate(parseJson(await readFile(file, 'utf8')));
  const pkce = mode === '--discover' ? await discovery(issuer, oidc) : null;
  console.log(JSON.stringify({
    configuration: 'validated', oidcDiscovery: mode === '--discover' ? 'passed' : 'not-run',
    pkceS256: pkce, receiptInterfaceConfigured: mcp.receiptRef !== null,
    browserSignIn: 'pending', externalMcpInvocation: 'pending',
  }));
} catch (error) {
  // Errors from fetch and URL parsing may contain configuration values.
  console.error(error.name === 'TypeError' ? 'Invalid pilot configuration or failed discovery' : error.message);
  process.exitCode = 1;
}
