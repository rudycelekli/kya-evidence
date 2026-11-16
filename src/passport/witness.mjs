import { DatabaseSync } from 'node:sqlite';
import { digest, insist } from '../shared/canonical.mjs';
import { keyId, text, validatePublicPem } from '../identity/domain/services/validation.mjs';
import { passportPublicKey } from './index.mjs';
import { buildPassportRegistryIndex } from './registry-proof.mjs';
import { registryWitnessBytes, signRegistryStatement, verifyRegistryCheckpoint } from './registry-checkpoint.mjs';

export function openPassportWitness(filename, { registry, originPublicKey, witnessPrivateKey, clock = () => new Date().toISOString() }) {
  insist(typeof filename === 'string' && filename.length > 0 && filename !== ':memory:'
    && !filename.startsWith('file:'), 'Expected SQLite path');
  text(registry, 'Registry');
  validatePublicPem(originPublicKey);
  const witnessPublicKey = passportPublicKey(witnessPrivateKey);
  validatePublicPem(witnessPublicKey);
  const witnessId = keyId(witnessPublicKey);
  const originId = keyId(originPublicKey);
  insist(witnessId !== originId, 'Witness keys must be distinct');
  const identity = digest({ registry, witnessId, originId });
  const db = new DatabaseSync(filename);
  try {
    db.exec(`
      PRAGMA busy_timeout=5000;
      PRAGMA journal_mode=WAL;
      PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS witness_identity (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1), identity TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS witnessed_registry (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1), epoch INTEGER NOT NULL,
        checkpoint TEXT NOT NULL, issued TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS witnessed_passport (
        id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, head TEXT NOT NULL
      ) STRICT;
    `);
    db.prepare('INSERT OR IGNORE INTO witness_identity VALUES (1, ?)').run(identity);
    insist(db.prepare('SELECT identity FROM witness_identity WHERE singleton = 1').get().identity === identity, 'Witness trust mismatch');
  } catch (error) {
    db.close();
    throw error;
  }
  const last = db.prepare('SELECT * FROM witnessed_registry WHERE singleton = 1');
  const passports = db.prepare('SELECT * FROM witnessed_passport');
  const storeHead = db.prepare('INSERT OR REPLACE INTO witnessed_registry VALUES (1, ?, ?, ?)');
  const storePassport = db.prepare('INSERT OR REPLACE INTO witnessed_passport VALUES (?, ?, ?)');

  return {
    witnessId,
    endorse(signed, histories) {
      const { checkpoint, checkpointDigest } = verifyRegistryCheckpoint(signed, { registry, originPublicKey }, clock());
      const index = buildPassportRegistryIndex(histories, registry);
      insist(index.root === checkpoint.root && index.count === checkpoint.count, 'Witness snapshot mismatch');
      db.exec('BEGIN IMMEDIATE');
      try {
        const prior = last.get();
        if (prior?.checkpoint !== checkpointDigest) {
          insist(checkpoint.epoch === (prior?.epoch ?? 0) + 1 && checkpoint.previous === (prior?.checkpoint ?? null)
            && (!prior || checkpoint.issuedAt > prior.issued), 'Witness checkpoint does not extend prior checkpoint');
          for (const old of passports.iterate()) {
            const next = index.passports.get(old.id);
            insist(next && next.sequence >= old.sequence && digest(next.history[old.sequence - 1]) === old.head,
              'Witness history omitted or forked');
          }
          for (const next of index.passports.values()) storePassport.run(next.id, next.sequence, next.head);
          storeHead.run(checkpoint.epoch, checkpointDigest, checkpoint.issuedAt);
        }
        const signature = signRegistryStatement(registryWitnessBytes(checkpoint), witnessPrivateKey);
        db.exec('COMMIT');
        return { witnessId, checkpointDigest, signature };
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
    close() {
      db.close();
    },
  };
}
