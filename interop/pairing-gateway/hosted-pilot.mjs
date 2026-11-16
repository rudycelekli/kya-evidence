import { createPrivateKey, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { digest, exactKeys, insist, parseJson } from '../../src/shared/canonical.mjs';
import { hash, identifier, keyId, text, validateManifest } from '../../src/identity/domain/services/validation.mjs';
import { signPairedAction, signPairingGrant } from '../../src/pairing/index.mjs';
import { mcpToolCallDigest, openPairingGateway } from '../../src/pairing/mcp-gateway.mjs';
import { createOidcEnrollmentAuthenticator, oidcEnrollmentMessage } from '../../src/pairing/oidc-enrollment.mjs';
import { passportPublicKey } from '../../src/passport/index.mjs';
import { openPassportRegistry } from '../../src/passport/registry.mjs';
import { discoverPilotOidc, openPilotMcp, receivePilotLogin } from './hosted-adapters.mjs';
import { validatePilotSettings } from './pilot-settings.mjs';

const json = async path => parseJson(await readFile(path, 'utf8'));

async function clientCredential(mode) {
  if (mode === 'none') return undefined;
  if (mode === 'private_key_jwt') {
    const jwk = parseJson(process.env.KYA_PILOT_OIDC_PRIVATE_JWK);
    insist(jwk.kty === 'RSA' && (!jwk.alg || jwk.alg === 'RS256'), 'Pilot client assertion requires an RS256 key');
    const key = await crypto.subtle.importKey('jwk', jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    return jwk.kid ? { key, kid: jwk.kid } : key;
  }
  return process.env.KYA_PILOT_OIDC_SECRET;
}

function validateInputs(inputs) {
  exactKeys(inputs, ['expectedSubject', 'callbackPort', 'gatewayDatabase', 'registryDatabase',
    'passportId', 'manifestFile', 'principalKeyFile', 'agentKeyFile', 'previousPrincipalKeyId',
    'server', 'permission', 'arguments', 'expectedResultDigest'], 'Pilot inputs');
  text(inputs.expectedSubject, 'OIDC subject', 255);
  insist(Number.isInteger(inputs.callbackPort) && inputs.callbackPort >= 1 && inputs.callbackPort <= 65_535,
    'Invalid pilot callback port');
  for (const field of ['gatewayDatabase', 'registryDatabase', 'manifestFile', 'principalKeyFile', 'agentKeyFile']) {
    text(inputs[field], field, 2048);
  }
  hash(inputs.passportId, 'Passport ID');
  hash(inputs.expectedResultDigest, 'Result digest');
  if (inputs.previousPrincipalKeyId !== null) hash(inputs.previousPrincipalKeyId, 'Previous principal key');
  identifier(inputs.server, 'Server ID');
  identifier(inputs.permission, 'Permission');
}

export async function runPilot(settings, inputs, adapters) {
  const { oidc, mcp } = validatePilotSettings(settings);
  validateInputs(inputs);
  const manifest = validateManifest(await json(inputs.manifestFile));
  const now = Date.now();
  insist(Date.parse(manifest.issuedAt) <= now && now < Date.parse(manifest.expiresAt), 'Pilot manifest is outside its validity window');
  insist(manifest.scope.permissions.includes(inputs.permission) && !manifest.scope.approvalRequired.includes(inputs.permission)
    && manifest.system.tools.some(tool => tool.id === mcp.tool && tool.permissions.includes(inputs.permission)),
  'Pilot tool and permission are not authorized by the manifest');
  const principalId = manifest.principal.id;
  const principalKey = createPrivateKey(await readFile(inputs.principalKeyFile));
  const agentKey = createPrivateKey(await readFile(inputs.agentKeyFile));
  const publicKey = passportPublicKey(principalKey);
  const agentFingerprint = keyId(passportPublicKey(agentKey));
  const call = { server: inputs.server, tool: mcp.tool, arguments: inputs.arguments };
  const requestDigest = mcpToolCallDigest(call);
  const route = {
    manifest, audience: new URL(settings.gateway.url).origin, permission: inputs.permission, passportId: inputs.passportId,
    revision: digest({ server: inputs.server, endpoint: mcp.url, tool: mcp.tool, schemaDigest: mcp.schemaDigest,
      permission: inputs.permission, passportId: inputs.passportId }),
    revokedKeyIds: [], revokedGrantDigests: [],
  };
  const registry = openPassportRegistry(inputs.registryDatabase, settings.gateway.registry);
  let gateway;
  let downstream;
  let login;
  try {
    const passport = registry.read(inputs.passportId);
    insist(passport?.status === 'active' && passport.principalId === principalId && passport.agentId === manifest.agent.id
      && passport.current.fingerprint === agentFingerprint && passport.current.manifestDigest === digest(manifest),
    'Pilot Passport does not match the pinned keys and manifest');
    gateway = openPairingGateway(inputs.gatewayDatabase, {
      authenticateIdentity: createOidcEnrollmentAuthenticator({
        issuer: oidc.issuer, audience: oidc.clientId,
        verifyIdToken(idToken) {
          insist(login && login.idToken === idToken, 'OIDC token was not verified by this callback');
          return login.claims;
        },
        resolvePrincipal(issuer, subject) {
          insist(issuer === oidc.issuer && subject === inputs.expectedSubject, 'Unexpected pilot identity');
          return principalId;
        },
        consumeNonce: challenge => gateway.consumeEnrollmentChallenge(challenge),
      }),
      resolveRoute: () => route,
      passports: { registry: settings.gateway.registry, readHistory: id => registry.read(id)?.history ?? null },
      forward: (...args) => downstream.forward(...args),
    });
    downstream = await adapters.connect(mcp, { server: call.server, revision: route.revision });
    const intent = {
      issuer: oidc.issuer, audience: oidc.clientId, challenge: gateway.issueEnrollmentChallenge(),
      publicKey, previousKeyId: inputs.previousPrincipalKeyId,
    };
    login = await adapters.login(oidc, intent);
    const session = { idToken: login.idToken, challenge: intent.challenge, publicKey,
      signature: sign(null, oidcEnrollmentMessage(intent), principalKey).toString('base64url') };
    if (inputs.previousPrincipalKeyId === null) await gateway.enrollIdentity(session);
    else await gateway.rotateIdentity(session, inputs.previousPrincipalKeyId);
    login = null;
    const challenge = gateway.issueChallenge(call);
    const acceptedAt = Date.now();
    const grant = signPairingGrant({
      schema: 'kya.pairing-grant/v1', principalId, agentKeyId: agentFingerprint, manifestDigest: digest(manifest),
      audience: route.audience, permission: route.permission,
      issuedAt: new Date(acceptedAt).toISOString(),
      expiresAt: new Date(Math.min(acceptedAt + 60_000, Date.parse(manifest.expiresAt))).toISOString(),
    }, principalKey);
    const action = signPairedAction({
      schema: 'kya.paired-action/v1', grantDigest: digest(grant), challenge, requestDigest,
    }, agentKey);
    const { audit, result } = await gateway.invoke(call, { grant, action });
    const resultDigest = digest(result);
    return {
      operationId: audit.operationId, passportHead: audit.passportHead, requestDigest, resultDigest,
      resultMatched: result.isError !== true && resultDigest === inputs.expectedResultDigest,
    };
  } finally {
    login = null;
    try { await downstream?.close(); }
    finally {
      gateway?.close();
      registry.close();
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [settingsPath, inputsPath] = process.argv.slice(2);
    const settings = await json(settingsPath);
    const inputs = await json(inputsPath);
    const result = await runPilot(settings, inputs, {
      async login(oidc, intent) {
        const configuration = await discoverPilotOidc(oidc, await clientCredential(oidc.authentication));
        return receivePilotLogin(configuration, {
          callback: oidc.callback, port: inputs.callbackPort, intent,
          onAuthorizationUrl: url => process.stderr.write('Open this URL in your test browser\n' + url + '\n'),
        });
      },
      connect(mcp, route) {
        const bearer = mcp.credentialRef === null ? undefined : process.env.KYA_PILOT_MCP_BEARER;
        insist(mcp.credentialRef === null || bearer, 'MCP credential missing');
        return openPilotMcp(mcp, { ...route, bearer });
      },
    });
    console.log(JSON.stringify(result));
    if (!result.resultMatched) process.exitCode = 1;
  } catch {
    console.error('Hosted pilot stopped. Check private operator logs and gateway delivery state before retrying.');
    process.exitCode = 1;
  }
}
