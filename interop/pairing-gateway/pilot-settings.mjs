import { exactKeys, insist } from '../../src/shared/canonical.mjs';
import { hash, identifier, text } from '../../src/identity/domain/services/validation.mjs';

export function https(value, label, { pathOnly = false } = {}) {
  text(value, label, 2048);
  const url = new URL(value);
  insist(url.protocol === 'https:' && !url.username && !url.password && !url.hash && (!pathOnly || !url.search),
    label + ' must be an HTTPS URL');
  return url;
}

export function validatePilotSettings(config) {
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
