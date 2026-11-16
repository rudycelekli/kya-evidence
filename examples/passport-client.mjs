import { readFile } from 'node:fs/promises';
import { digest, parseJson, validateManifest } from 'kya-evidence';
import { passportId, passportPublicKey, signPassportEvent, verifyPassport } from 'kya-evidence/passport';

const [operation, address, ...args] = process.argv.slice(2);
const target = new URL(address);
if (target.protocol !== 'https:' && !(target.protocol === 'http:' && target.hostname === '127.0.0.1')) {
  throw new Error('Expected HTTPS or loopback HTTP');
}
const origin = target.origin;
const request = async (path, options) => {
  const response = await fetch(origin + path, { ...options, redirect: 'error', signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error('Registry returned HTTP ' + response.status);
  return parseJson(await response.text());
};
const getPassport = async id => {
  if (!/^[a-f0-9]{64}$/.test(id)) throw new Error('Expected passport ID');
  const passport = await request('/v1/passports/' + id);
  const verified = verifyPassport(passport.history, origin);
  if (verified.passportId !== id) throw new Error('Passport ID mismatch');
  return { ...verified, history: passport.history, url: origin + '/passports/' + id };
};

let result;
if (operation === 'verify') {
  result = await getPassport(args[0]);
  if (args[1] && result.head !== args[1]) throw new Error('Passport head differs from expected head');
} else if (operation === 'lookup') {
  if (!/^[a-f0-9]{64}$/.test(args[0])) throw new Error('Expected fingerprint');
  result = await request('/v1/fingerprints/' + args[0]);
} else {
  if (!['register', 'rotate', 'revise', 'revoke'].includes(operation)) throw new Error('Unknown passport command');
  const [idOrManifest, controllerFile, agentFile, revisionFile] = args;
  const controller = await readFile(controllerFile);
  const agent = operation === 'revoke' ? null : await readFile(agentFile);
  const prior = operation === 'register' ? null : await getPassport(idOrManifest);
  if (prior?.status === 'revoked') throw new Error('Passport revoked');
  const manifestFile = operation === 'register' ? idOrManifest : revisionFile;
  const manifest = manifestFile ? validateManifest(parseJson(await readFile(manifestFile, 'utf8'))) : null;
  if (manifest && prior && (manifest.agent.id !== prior.agentId || manifest.principal.id !== prior.principalId)) {
    throw new Error('Manifest identity mismatch');
  }
  const event = {
    schema: 'kya.passport-event/v1', operation, registry: origin,
    previous: prior?.head ?? null, agentId: prior?.agentId ?? manifest.agent.id,
    principalId: prior?.principalId ?? manifest.principal.id,
    controllerPublicKey: passportPublicKey(controller), agentPublicKey: agent && passportPublicKey(agent),
    manifestDigest: manifest ? digest(manifest) : prior.current.manifestDigest,
  };
  event.passportId = passportId(event);
  if (prior && event.passportId !== prior.passportId) throw new Error('Controller key mismatch');
  const record = {
    event, controllerSignature: signPassportEvent(event, controller),
    agentSignature: agent ? signPassportEvent(event, agent) : null,
  };
  verifyPassport([...(prior?.history ?? []), record], origin);
  await request('/v1/events', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(record) });
  result = await getPassport(event.passportId);
}
if (result.history) delete result.history;
console.log(JSON.stringify(result, null, 2));
