import { readFile } from 'node:fs/promises';
import { insist, parseJson } from '../../src/shared/canonical.mjs';
import { https, validatePilotSettings } from './pilot-settings.mjs';

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
  const { issuer, oidc, mcp } = validatePilotSettings(parseJson(await readFile(file, 'utf8')));
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
