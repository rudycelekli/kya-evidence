import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { digest, keyId } from '../src/index.mjs';
import { signPairingGrant, signPairedAction, verifyPairedAction } from '../src/pairing/index.mjs';
import { mcpToolCallDigest, openPairingGateway } from 'kya-evidence/pairing/mcp-gateway';

const keys = Array.from({ length: 3 }, () => generateKeyPairSync('ed25519'));
const [principal, next, agent] = keys;
const manifest = JSON.parse(readFileSync(new URL('../examples/manifest.json', import.meta.url)));
manifest.issuedAt = '2026-11-14T13:00:00.000Z';
manifest.expiresAt = '2026-11-14T15:00:00.000Z';
manifest.scope.permissions.push('read:tool');
manifest.system.tools.push(...['read_file', 'write_file'].map(id => ({ id, version: '1', permissions: ['read:tool'] })));
const principalId = manifest.principal.id;
const call = { server: 'local:files', tool: 'read_file', arguments: { path: 'example.txt' } };
const initialTime = '2026-11-14T14:00:00.000Z';
const pem = key => key.publicKey.export({ format: 'pem', type: 'spki' });

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'kya-gateway-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const route = {
    manifest, audience: 'local:gateway', permission: 'read:tool', revision: 'ab'.repeat(32),
    revokedKeyIds: [], revokedGrantDigests: [],
  };
  let time = initialTime;
  const forwarded = [];
  const dependencies = {
    async authenticateIdentity(session) {
      const key = session === 'fixture-login' ? principal : session === 'fixture-rotation' ? next : null;
      if (!key) throw new Error('Login refused');
      return { issuer: 'https://issuer.example', subject: 'synthetic', principalId, publicKey: pem(key) };
    },
    resolveRoute() { return route; },
    async forward(server, revision, request) {
      forwarded.push({ server, revision, request });
      return 'fixture-result';
    },
    clock: () => time,
  };
  const filename = join(dir, 'gateway.sqlite');
  const open = () => openPairingGateway(filename, dependencies);
  const makeProof = (challenge, key = principal, requested = call, agentKeys = agent) => {
    const grant = signPairingGrant({
      schema: 'kya.pairing-grant/v1', principalId, agentKeyId: keyId(agentKeys.publicKey),
      manifestDigest: digest(manifest), audience: route.audience, permission: route.permission,
      issuedAt: '2026-11-14T13:55:00.000Z', expiresAt: '2026-11-14T14:10:00.000Z',
    }, key.privateKey);
    const action = signPairedAction({
      schema: 'kya.paired-action/v1', grantDigest: digest(grant),
      challenge, requestDigest: mcpToolCallDigest(requested),
    }, agentKeys.privateKey);
    return { grant, action };
  };
  return { route, forwarded, dependencies, open, makeProof, setTime: value => { time = value; }, filename };
}

test('blocks unauthenticated enrollment and keeps identity and replay state across connections and restart', async t => {
  const f = fixture(t);
  const gateway = f.open();
  await assert.rejects(gateway.enrollIdentity('forged-login'), /login/i);
  assert.throws(() => gateway.issueChallenge(call), /enrollment/i);
  await gateway.enrollIdentity('fixture-login');
  const challenge = gateway.issueChallenge(call);
  const proof = f.makeProof(challenge);
  const second = f.open();
  const runs = await Promise.allSettled([gateway.invoke(call, proof), second.invoke(call, proof)]);
  assert.deepEqual(runs.map(run => run.status).sort(), ['fulfilled', 'rejected']);
  assert.deepEqual(f.forwarded, [{
    server: call.server, revision: f.route.revision,
    request: { method: 'tools/call', params: { name: call.tool, arguments: call.arguments } },
  }]);
  const audit = gateway.readAudit(challenge);
  assert.equal(audit.downstreamResponseObserved, true);
  assert.equal(audit.actionDigest, digest(proof.action));
  gateway.close();
  second.close();
  const restarted = f.open();
  try {
    assert.deepEqual(restarted.readAudit(challenge), audit);
    await assert.rejects(restarted.invoke(call, proof), /challenge/i);
  } finally {
    restarted.close();
  }
});

test('binds exact server, tool, arguments and route revision and checks expiry', async t => {
  const f = fixture(t);
  const gateway = f.open();
  t.after(() => gateway.close());
  await gateway.enrollIdentity('fixture-login');
  const challenge = gateway.issueChallenge(call);
  const proof = f.makeProof(challenge);
  for (const changed of [
    { ...call, server: 'local:other' },
    { ...call, tool: 'write_file' },
    { ...call, arguments: { path: 'changed.txt' } },
  ]) {
    assert.notEqual(mcpToolCallDigest(changed), mcpToolCallDigest(call));
    await assert.rejects(gateway.invoke(changed, proof), /challenge/i);
  }
  f.route.revision = 'cd'.repeat(32);
  await assert.rejects(gateway.invoke(call, proof), /challenge/i);
  f.route.revision = 'ab'.repeat(32);
  f.setTime('2026-11-14T14:01:00.000Z');
  await assert.rejects(gateway.invoke(call, proof), /challenge/i);
  assert.deepEqual(f.forwarded, []);
});

test('rotates an authenticated identity and rejects stale sessions, grants and challenges', async t => {
  const f = fixture(t);
  const gateway = f.open();
  t.after(() => gateway.close());
  const enrolled = await gateway.enrollIdentity('fixture-login');
  const stale = gateway.issueChallenge(call);
  await assert.rejects(gateway.rotateIdentity('forged-login', enrolled.keyId), /login/i);
  const rotated = await gateway.rotateIdentity('fixture-rotation', enrolled.keyId);
  assert.equal(rotated.keyId, keyId(next.publicKey));
  await assert.rejects(gateway.rotateIdentity('fixture-login', rotated.keyId), /rotation/i);
  await assert.rejects(gateway.rotateIdentity('fixture-rotation', enrolled.keyId), /rotation/i);
  await assert.rejects(gateway.invoke(call, f.makeProof(stale)), /challenge/i);
  const fresh = gateway.issueChallenge(call);
  await assert.rejects(gateway.invoke(call, f.makeProof(fresh)), /principal/i);
  assert.equal((await gateway.invoke(call, f.makeProof(fresh, next))).audit.principalKeyId, rotated.keyId);
});

test('commits acceptance before forwarding and refuses automatic retries after a downstream error', async t => {
  const f = fixture(t);
  let attempts = 0;
  f.dependencies.forward = async () => {
    attempts++;
    throw new Error('Downstream outcome unknown');
  };
  const gateway = f.open();
  t.after(() => gateway.close());
  await gateway.enrollIdentity('fixture-login');
  const challenge = gateway.issueChallenge(call);
  const proof = f.makeProof(challenge);
  await assert.rejects(gateway.invoke(call, proof), /downstream/i);
  assert.equal(gateway.readAudit(challenge).downstreamResponseObserved, undefined);
  await assert.rejects(gateway.invoke(call, proof), /challenge/i);
  assert.equal(attempts, 1);
});

test('signed OIDC login binds a one-time nonce to possession of the new key and rotation intent', async t => {
  const { sign, verify } = await import('node:crypto');
  const { createOidcEnrollmentAuthenticator, oidcEnrollmentMessage, oidcEnrollmentNonce } =
    await import('kya-evidence/pairing/oidc-enrollment');
  const f = fixture(t);
  const issuer = 'https://issuer.example';
  const audience = 'fixture-client';
  const provider = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const now = Date.parse(initialTime) / 1000;
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encode({ alg: 'RS256', typ: 'JWT' });
  function token(claims) {
    const content = header + '.' + encode(claims);
    return content + '.' + sign('sha256', Buffer.from(content), provider.privateKey).toString('base64url');
  }
  f.dependencies.authenticateIdentity = createOidcEnrollmentAuthenticator({
    issuer, audience, clock: f.dependencies.clock,
    async verifyIdToken(idToken) {
      const [head, data, signature, extra] = idToken.split('.');
      assert.equal(head, header);
      assert.equal(extra, undefined);
      assert.ok(verify('sha256', Buffer.from(head + '.' + data), provider.publicKey, Buffer.from(signature, 'base64url')));
      return JSON.parse(Buffer.from(data, 'base64url').toString());
    },
    resolvePrincipal(expectedIssuer, subject) {
      assert.equal(expectedIssuer, issuer);
      assert.equal(subject, 'synthetic');
      return principalId;
    },
    consumeNonce(challenge) { return gateway.consumeEnrollmentChallenge(challenge); },
  });
  const gateway = f.open();
  t.after(() => gateway.close());
  function session(key, previousKeyId, overrides = {}) {
    const intent = { issuer, audience, challenge: gateway.issueEnrollmentChallenge(), publicKey: pem(key), previousKeyId };
    return {
      idToken: token({ iss: issuer, aud: audience, sub: 'synthetic', nonce: oidcEnrollmentNonce(intent),
        iat: now, exp: now + 300, auth_time: now, ...overrides }),
      challenge: intent.challenge, publicKey: intent.publicKey,
      signature: sign(null, oidcEnrollmentMessage(intent), key.privateKey).toString('base64url'),
    };
  }
  const enrollment = session(principal, null);
  await assert.rejects(gateway.enrollIdentity({ ...enrollment, publicKey: pem(next) }), /signature/i);
  await assert.rejects(gateway.enrollIdentity(session(principal, null, { auth_time: now - 301 })), /fresh/i);
  await assert.rejects(gateway.enrollIdentity(session(principal, null, { aud: 'another-client' })), /claims/i);
  await assert.rejects(gateway.enrollIdentity(session(principal, null, { nonce: '00'.repeat(32) })), /claims/i);
  const original = await gateway.enrollIdentity(enrollment);
  await assert.rejects(gateway.enrollIdentity(enrollment), /challenge/i);
  const renewal = session(next, original.keyId);
  await assert.rejects(gateway.enrollIdentity(renewal), /signature/i);
  const rotated = await gateway.rotateIdentity(renewal, original.keyId);
  assert.equal(rotated.keyId, keyId(next.publicKey));
  await assert.rejects(gateway.rotateIdentity(renewal, original.keyId), /challenge/i);
});

test('separate processes contend on the same durable challenge and only one forwards', async t => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const f = fixture(t);
  const gateway = f.open();
  try {
    await gateway.enrollIdentity('fixture-login');
    const challenge = gateway.issueChallenge(call);
    const input = JSON.stringify({
      filename: f.filename, call, proof: f.makeProof(challenge), route: f.route, now: initialTime,
    });
    const childCode = `
      import { openPairingGateway } from 'kya-evidence/pairing/mcp-gateway';
      const { filename, call, proof, route, now } = JSON.parse(process.argv[1]);
      const gateway = openPairingGateway(filename, {
        authenticateIdentity() { throw Error('Unexpected enrollment'); },
        resolveRoute: () => route,
        clock: () => now,
        forward: () => process.stdout.write('forwarded'),
      });
      try {
        await gateway.invoke(call, proof);
      } catch (error) {
        if (error.message !== 'Challenge unavailable') throw error;
        process.stdout.write('replayed');
      } finally {
        gateway.close();
      }
    `;
    const run = () => promisify(execFile)(process.execPath, ['--input-type=module', '-e', childCode, input], {
      cwd: new URL('..', import.meta.url), timeout: 15_000,
    });
    const results = await Promise.all([run(), run()]);
    assert.deepEqual(results.map(result => result.stdout).sort(), ['forwarded', 'replayed']);
    assert.equal(gateway.readAudit(challenge).requestDigest, mcpToolCallDigest(call));
  } finally {
    gateway.close();
  }
});

test('requires the currently registered passport key and manifest before consuming or forwarding', async t => {
  const { passportId, signPassportEvent } = await import('kya-evidence/passport');
  const { openPassportRegistry } = await import('kya-evidence/passport/registry');
  const f = fixture(t);
  const registry = 'https://registry.example';
  const store = openPassportRegistry(f.filename + '.passports', registry);
  t.after(() => store.close());
  const event = {
    schema: 'kya.passport-event/v1', registry, operation: 'register', previous: null,
    principalId, agentId: manifest.agent.id, manifestDigest: digest(manifest),
    controllerPublicKey: pem(principal), agentPublicKey: pem(agent),
  };
  event.passportId = passportId(event);
  f.route.passportId = event.passportId;
  const seal = (payload, keys = agent) => ({
    event: payload, controllerSignature: signPassportEvent(payload, principal.privateKey),
    agentSignature: keys === null ? null : signPassportEvent(payload, keys.privateKey),
  });
  let state = store.append(seal(event));
  f.dependencies.passports = { registry, readHistory: id => store.read(id)?.history ?? null };
  const gateway = f.open();
  t.after(() => gateway.close());
  await gateway.enrollIdentity('fixture-login');

  const first = gateway.issueChallenge(call);
  const admitted = await gateway.invoke(call, f.makeProof(first));
  assert.equal(admitted.audit.passportHead, state.head);
  assert.equal(gateway.readAudit(first).passportId, state.passportId);

  const assertRefused = async (challenge, proof) => {
    verifyPairedAction(proof, {
      manifest, principalId, principalKeyId: keyId(principal.publicKey),
      audience: f.route.audience, permission: f.route.permission,
      challenge, now: initialTime, requestDigest: mcpToolCallDigest(call),
      revokedKeyIds: [], revokedGrantDigests: [],
    });
    const before = f.forwarded.length;
    await assert.rejects(gateway.invoke(call, proof), /passport authorization refused/i);
    assert.equal(f.forwarded.length, before);
    assert.equal(gateway.readAudit(challenge), null);
  };
  const challenge = gateway.issueChallenge(call);
  const originalProof = f.makeProof(challenge);
  state = store.append(seal({ ...event, operation: 'rotate', previous: state.head, agentPublicKey: pem(next) }, next));
  await assertRefused(challenge, originalProof);
  const replacementProof = f.makeProof(challenge, principal, call, next);
  assert.equal((await gateway.invoke(call, replacementProof)).audit.passportHead, state.head);

  const forOldManifest = gateway.issueChallenge(call);
  state = store.append(seal({
    ...event, operation: 'revise', previous: state.head, agentPublicKey: pem(next),
    manifestDigest: digest({ revision: 'different manifest' }),
  }, next));
  await assertRefused(forOldManifest, f.makeProof(forOldManifest, principal, call, next));

  const afterRevocation = gateway.issueChallenge(call);
  store.append(seal({
    ...event, operation: 'revoke', previous: state.head, manifestDigest: state.current.manifestDigest,
    agentPublicKey: null,
  }, null));
  await assertRefused(afterRevocation, f.makeProof(afterRevocation, principal, call, next));
});

test('passport enforcement refuses omitted policy, missing history, and a substituted passport ID', async t => {
  const { passportId, signPassportEvent } = await import('kya-evidence/passport');
  const f = fixture(t);
  const registry = 'https://registry.example';
  let history = null;
  f.dependencies.passports = { registry, readHistory: () => history };
  const gateway = f.open();
  t.after(() => gateway.close());
  await gateway.enrollIdentity('fixture-login');
  assert.throws(() => gateway.issueChallenge(call), /fields/i);
  f.route.passportId = digest('different passport');
  const challenge = gateway.issueChallenge(call);
  const proof = f.makeProof(challenge);
  await assert.rejects(gateway.invoke(call, proof), /history/i);
  const event = {
    schema: 'kya.passport-event/v1', registry, operation: 'register', previous: null,
    principalId, agentId: manifest.agent.id, manifestDigest: digest(manifest),
    controllerPublicKey: pem(principal), agentPublicKey: pem(agent),
  };
  event.passportId = passportId(event);
  history = [{
    event, controllerSignature: signPassportEvent(event, principal.privateKey),
    agentSignature: signPassportEvent(event, agent.privateKey),
  }];
  await assert.rejects(gateway.invoke(call, proof), /passport identity mismatch/i);
  assert.equal(gateway.readAudit(challenge), null);
  assert.equal(f.forwarded.length, 0);
});
