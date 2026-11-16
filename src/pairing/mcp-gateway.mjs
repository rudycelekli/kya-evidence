import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, identifier, keyId, text, timestamp, validateManifest, validatePublicPem } from '../identity/domain/services/validation.mjs';
import { verifyPairedAction } from './index.mjs';
import { verifyPassport } from '../passport/index.mjs';

function snapshot(value) {
  return JSON.parse(canonical(value));
}

function captureCall(input) {
  const call = snapshot(input);
  exactKeys(call, ['server', 'tool', 'arguments'], 'MCP call');
  identifier(call.server, 'MCP server');
  insist(typeof call.tool === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(call.tool), 'Invalid MCP tool');
  insist(call.arguments && typeof call.arguments === 'object' && !Array.isArray(call.arguments), 'Invalid MCP arguments');
  return call;
}

function callDigest(call) {
  return digest({ schema: 'kya.mcp-tool-call/v1', method: 'tools/call', ...call });
}

export function mcpToolCallDigest(call) {
  return callDigest(captureCall(call));
}

export function openPairingGateway(filename, dependencies) {
  const { authenticateIdentity, resolveRoute, forward, observeDelivery, passports, clock = () => new Date().toISOString() } = dependencies;
  insist(typeof filename === 'string' && filename.length > 0 && filename !== ':memory:'
    && !filename.startsWith('file:'), 'Expected SQLite path');
  const passportRegistry = passports?.registry;
  const readPassportHistory = passports?.readHistory;
  if (passports !== undefined) {
    text(passportRegistry, 'Passport registry');
    insist(typeof readPassportHistory === 'function', 'Passport reader required');
  }
  const db = new DatabaseSync(filename);
  db.exec(`
    PRAGMA busy_timeout=5000;
    PRAGMA foreign_keys=ON;
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=FULL;
    CREATE TABLE IF NOT EXISTS identity (
      principal TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
      key_id TEXT NOT NULL, UNIQUE (issuer, subject)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS retired_key (
      principal TEXT NOT NULL, key_id TEXT NOT NULL, PRIMARY KEY (principal, key_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS enrollment_challenge (
      nonce TEXT PRIMARY KEY, issued INTEGER NOT NULL, expires INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS passport_head (
      passport TEXT PRIMARY KEY, sequence INTEGER NOT NULL, head TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS challenge (
      nonce TEXT PRIMARY KEY, binding TEXT NOT NULL, issued INTEGER NOT NULL, expires INTEGER NOT NULL,
      accepted_at INTEGER, audit TEXT
    ) STRICT;
    CREATE TABLE IF NOT EXISTS mcp_delivery (
      operation_id TEXT PRIMARY KEY, challenge TEXT NOT NULL UNIQUE REFERENCES challenge(nonce),
      state TEXT NOT NULL CHECK (state IN ('accepted', 'dispatching', 'unknown',
        'response-observed', 'confirmed-applied', 'confirmed-not-applied')),
      receipt_digest TEXT
    ) STRICT;
    CREATE INDEX IF NOT EXISTS mcp_delivery_state ON mcp_delivery(state, operation_id);
  `);
  const issueEnrollment = db.prepare('INSERT INTO enrollment_challenge VALUES (?, ?, ?)');
  const consumeEnrollment = db.prepare('DELETE FROM enrollment_challenge WHERE nonce = ? AND issued <= ? AND expires > ?');
  const identity = db.prepare('SELECT * FROM identity WHERE principal = ?');
  const enroll = db.prepare('INSERT INTO identity VALUES (?, ?, ?, ?)');
  const retire = db.prepare('INSERT INTO retired_key VALUES (?, ?)');
  const retired = db.prepare('SELECT 1 FROM retired_key WHERE principal = ? AND key_id = ?');
  const rotate = db.prepare('UPDATE identity SET key_id = ? WHERE principal = ?');
  const issue = db.prepare('INSERT INTO challenge (nonce, binding, issued, expires) VALUES (?, ?, ?, ?)');
  const pending = db.prepare('SELECT * FROM challenge WHERE nonce = ?');
  const consume = db.prepare('UPDATE challenge SET accepted_at = ?, audit = ? WHERE nonce = ? AND accepted_at IS NULL AND issued <= ? AND expires > ?');

  const knownHead = db.prepare('SELECT sequence, head FROM passport_head WHERE passport = ?');
  const pinHead = db.prepare('INSERT INTO passport_head VALUES (?, ?, ?) ON CONFLICT (passport) DO UPDATE SET sequence = excluded.sequence, head = excluded.head WHERE excluded.sequence > passport_head.sequence');
  const recordResponse = db.prepare('UPDATE challenge SET audit = ? WHERE nonce = ? AND audit = ?');

  const addDelivery = db.prepare("INSERT INTO mcp_delivery VALUES (?, ?, 'accepted', NULL)");
  const getDelivery = db.prepare('SELECT * FROM mcp_delivery WHERE operation_id = ?');
  const transitions = db.prepare('UPDATE mcp_delivery SET state = ?, receipt_digest = ? WHERE operation_id = ? AND state = ?');
  const unresolved = db.prepare("SELECT operation_id FROM mcp_delivery WHERE state IN ('accepted', 'dispatching', 'unknown') AND operation_id > ? ORDER BY operation_id LIMIT ?");

  function readDelivery(operationId) {
    hash(operationId, 'Operation ID');
    const row = getDelivery.get(operationId);
    if (!row) return null;
    const audit = JSON.parse(pending.get(row.challenge).audit);
    return {
      operationId, state: row.state, receiptDigest: row.receipt_digest,
      challenge: row.challenge, server: audit.server, tool: audit.tool,
      routeRevision: audit.routeRevision, requestDigest: audit.requestDigest,
    };
  }

  function write(operation) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = operation();
      db.exec('COMMIT');
      return result;
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  async function bindIdentity(session, previousKeyId) {
    // The host verifies its login session and key-possession ceremony before
    // returning this assertion. Callers cannot supply the assertion directly.
    const login = snapshot(await authenticateIdentity(session, previousKeyId ?? null));
    exactKeys(login, ['issuer', 'subject', 'principalId', 'publicKey'], 'Enrollment assertion');
    text(login.issuer, 'Identity issuer');
    text(login.subject, 'Identity subject');
    identifier(login.principalId, 'Principal ID');
    validatePublicPem(login.publicKey);
    const next = keyId(login.publicKey);
    return write(() => {
      if (previousKeyId === undefined) {
        enroll.run(login.principalId, login.issuer, login.subject, next);
      } else {
        const current = identity.get(login.principalId);
        insist(current?.issuer === login.issuer && current.subject === login.subject
          && current.key_id === previousKeyId && next !== previousKeyId
          && !retired.get(login.principalId, next), 'Rotation refused');
        retire.run(login.principalId, previousKeyId);
        rotate.run(next, login.principalId);
      }
      return { principalId: login.principalId, keyId: next };
    });
  }

  function routeFor(call) {
    // A synchronous registry callback returns a single snapshot used for both
    // verification and forwarding. Its revision must change when the route changes.
    const route = snapshot(resolveRoute(call.server, call.tool));
    const fields = ['manifest', 'audience', 'permission', 'revision', 'revokedKeyIds', 'revokedGrantDigests'];
    if (passports !== undefined) {
      fields.push('passportId');
    }
    exactKeys(route, fields, 'MCP route');
    if (passports !== undefined) hash(route.passportId, 'Passport ID');
    route.manifest = validateManifest(route.manifest);
    hash(route.revision, 'Route revision');
    identifier(route.audience, 'Audience');
    identifier(route.permission, 'Permission');
    const tool = route.manifest.system.tools.find(entry => entry.id === call.tool);
    insist(tool?.permissions.includes(route.permission), 'Tool permission absent');
    return route;
  }

  function binding(call, route, principalKeyId) {
    return digest({
      requestDigest: callDigest(call), manifestDigest: digest(route.manifest),
      audience: route.audience, permission: route.permission, revision: route.revision, principalKeyId,
      ...(route.passportId === undefined ? {} : { passportId: route.passportId }),
    });
  }

  return {
    issueEnrollmentChallenge() {
      const challenge = randomBytes(32).toString('hex');
      const now = timestamp(clock());
      issueEnrollment.run(challenge, now, now + 300_000);
      return challenge;
    },
    consumeEnrollmentChallenge(challenge) {
      hash(challenge, 'Enrollment challenge');
      const now = timestamp(clock());
      return consumeEnrollment.run(challenge, now, now).changes === 1;
    },
    enrollIdentity(session) {
      return bindIdentity(session);
    },
    rotateIdentity(session, previousKeyId) {
      hash(previousKeyId, 'Previous key ID');
      return bindIdentity(session, previousKeyId);
    },
    issueChallenge(input) {
      const call = captureCall(input);
      return write(() => {
        const route = routeFor(call);
        const principal = identity.get(route.manifest.principal.id);
        insist(principal, 'Enrollment required');
        const now = timestamp(clock());
        const challenge = randomBytes(32).toString('hex');
        issue.run(challenge, binding(call, route, principal.key_id), now, now + 60_000);
        return challenge;
      });
    },
    async invoke(input, inputProof) {
      const call = captureCall(input);
      const proof = snapshot(inputProof);
      const challenge = proof?.action?.payload?.challenge;
      hash(challenge, 'Challenge');
      const acceptance = write(() => {
        const route = routeFor(call);
        const principalId = route.manifest.principal.id;
        const principal = identity.get(principalId);
        const row = pending.get(challenge);
        const now = clock();
        const time = timestamp(now);
        insist(principal && row && row.accepted_at === null && time >= row.issued && time < row.expires
          && row.binding === binding(call, route, principal.key_id), 'Challenge unavailable');
        const requestDigest = callDigest(call);
        const verified = verifyPairedAction(proof, {
          manifest: route.manifest, principalId, principalKeyId: principal.key_id,
          audience: route.audience, permission: route.permission, challenge, now,
          requestDigest, revokedKeyIds: route.revokedKeyIds,
          revokedGrantDigests: route.revokedGrantDigests,
        });
        let passportBinding;
        if (route.passportId !== undefined) {
          const history = snapshot(readPassportHistory(route.passportId));
          const passport = verifyPassport(history, passportRegistry);
          insist(passport.passportId === route.passportId && passport.agentId === verified.agentId
            && passport.principalId === verified.principalId, 'Passport identity mismatch');
          const pinned = knownHead.get(passport.passportId);
          insist(!pinned || (history.length >= pinned.sequence
            && digest(history[pinned.sequence - 1]) === pinned.head), 'Passport history rolled back or forked');
          pinHead.run(passport.passportId, history.length, passport.head);
          // Keep the authenticated head even when it disables this request.
          if (passport.status !== 'active' || passport.current.fingerprint !== verified.agentKeyId
            || passport.current.manifestDigest !== verified.manifestDigest) return null;
          passportBinding = { passportId: passport.passportId, passportHead: passport.head };
        }
        const operationId = digest({
          schema: 'kya.mcp-delivery/v1', actionDigest: verified.actionDigest, routeRevision: route.revision,
        });
        const audit = {
          ...verified, ...passportBinding, challenge, requestDigest, operationId, routeRevision: route.revision,
          server: call.server, tool: call.tool, acceptedAt: now,
        };
        insist(consume.run(time, canonical(audit), challenge, time, time).changes === 1, 'Challenge unavailable');
        addDelivery.run(operationId, challenge);
        return { route, audit };
      });
      insist(acceptance, 'Passport authorization refused');
      const { route, audit } = acceptance;
      const { operationId } = audit;
      insist(transitions.run('dispatching', null, operationId, 'accepted').changes === 1, 'Delivery claim failed');
      let result;
      try {
        result = await forward(call.server, route.revision, {
          method: 'tools/call', params: { name: call.tool, arguments: call.arguments },
        }, { operationId });
      } catch (error) {
        transitions.run('unknown', null, operationId, 'dispatching');
        throw error;
      }
      const completedAudit = { ...audit, downstreamResponseObserved: true };
      write(() => {
        insist(recordResponse.run(canonical(completedAudit), challenge, canonical(audit)).changes === 1,
          'Audit update failed');
        transitions.run('response-observed', null, operationId, 'dispatching');
      });
      return { audit: completedAudit, result };
    },
    readDelivery,
    listUnresolvedDeliveries({ after = '', limit = 100 } = {}) {
      if (after !== '') hash(after, 'Operation ID');
      insist(Number.isInteger(limit) && limit > 0 && limit <= 100, 'Invalid delivery limit');
      return unresolved.all(after, limit).map(row => readDelivery(row.operation_id));
    },
    async reconcileDelivery(operationId) {
      const delivery = readDelivery(operationId);
      insist(delivery, 'Unknown delivery');
      if (delivery.state !== 'unknown' && delivery.state !== 'dispatching') return delivery;
      insist(typeof observeDelivery === 'function', 'Delivery observer required');
      const observation = snapshot(await observeDelivery(delivery));
      exactKeys(observation, ['operationId', 'outcome', 'receiptDigest'], 'Delivery observation');
      insist(observation.operationId === operationId, 'Delivery observation mismatch');
      if (observation.outcome === 'unknown') {
        insist(observation.receiptDigest === null, 'Unexpected delivery receipt');
        return readDelivery(operationId);
      }
      insist(observation.outcome === 'confirmed-applied' || observation.outcome === 'confirmed-not-applied',
        'Invalid delivery outcome');
      hash(observation.receiptDigest, 'Receipt digest');
      return write(() => {
        const current = readDelivery(operationId);
        if (current.state === 'unknown' || current.state === 'dispatching') {
          transitions.run(observation.outcome, observation.receiptDigest, operationId, current.state);
        }
        return readDelivery(operationId);
      });
    },
    readAudit(challenge) {
      hash(challenge, 'Challenge');
      const row = pending.get(challenge);
      return row?.audit ? JSON.parse(row.audit) : null;
    },
    close() {
      db.close();
    },
  };
}
