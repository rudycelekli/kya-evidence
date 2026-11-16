import { DatabaseSync } from 'node:sqlite';
import { canonical, digest, insist } from '../shared/canonical.mjs';
import { hash, keyId, text, validatePublicPem } from '../identity/domain/services/validation.mjs';
import { verifyPassportCheckpoint } from './checkpoint.mjs';

export function openPassportMirror(filename, { registry, publicKey, clock = () => new Date().toISOString() }) {
  insist(typeof filename === 'string' && filename.length > 0 && filename !== ':memory:'
    && !filename.startsWith('file:'), 'Expected SQLite path');
  text(registry, 'Registry');
  validatePublicPem(publicKey);
  const trust = { registry, publicKey };
  const identity = digest({ registry, checkpointKeyId: keyId(publicKey) });
  const db = new DatabaseSync(filename);
  try {
    db.exec(`
      PRAGMA busy_timeout=5000;
      PRAGMA journal_mode=WAL;
      PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS mirror_trust (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1), identity TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS mirrored_passport (
        id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, head TEXT NOT NULL, issued TEXT NOT NULL, bundle TEXT NOT NULL
      ) STRICT;
    `);
    db.prepare('INSERT OR IGNORE INTO mirror_trust VALUES (1, ?)').run(identity);
    insist(db.prepare('SELECT identity FROM mirror_trust WHERE singleton = 1').get().identity === identity, 'Mirror trust mismatch');
  } catch (error) {
    db.close();
    throw error;
  }
  const read = db.prepare('SELECT * FROM mirrored_passport WHERE id = ?');
  const write = db.prepare('INSERT OR REPLACE INTO mirrored_passport VALUES (?, ?, ?, ?, ?)');

  return {
    importCheckpoint(input) {
      db.exec('BEGIN IMMEDIATE');
      try {
        const { passport, ...bundle } = verifyPassportCheckpoint(input, trust, clock());
        const { checkpoint, history } = bundle;
        const existing = read.get(passport.passportId);
        if (existing) {
          insist(history.length >= existing.sequence && digest(history[existing.sequence - 1]) === existing.head,
            'Mirror history rolled back or forked');
          insist(checkpoint.issuedAt >= existing.issued, 'Mirror checkpoint rolled back');
          if (checkpoint.issuedAt === existing.issued) {
            insist(canonical(bundle) === existing.bundle, 'Conflicting checkpoint issuance');
          }
        }
        write.run(passport.passportId, history.length, passport.head, checkpoint.issuedAt, canonical(bundle));
        db.exec('COMMIT');
        return passport;
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
    read(id) {
      hash(id, 'Passport ID');
      const entry = read.get(id);
      return entry ? verifyPassportCheckpoint(JSON.parse(entry.bundle), trust, clock()) : null;
    },
    close() {
      db.close();
    },
  };
}
