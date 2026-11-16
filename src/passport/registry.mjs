import { DatabaseSync } from 'node:sqlite';
import { canonical, digest, insist } from '../shared/canonical.mjs';
import { hash, keyId } from '../identity/domain/services/validation.mjs';
import { verifyPassport } from './index.mjs';

export function openPassportRegistry(filename, registry) {
  insist(typeof filename === 'string' && filename.length > 0 && filename !== ':memory:'
    && !filename.startsWith('file:'), 'Expected SQLite path');
  const db = new DatabaseSync(filename);
  db.exec(`
    PRAGMA busy_timeout=5000;
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=FULL;
    CREATE TABLE IF NOT EXISTS passport_event (
      passport TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL,
      PRIMARY KEY (passport, sequence)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS passport_fingerprint (
      fingerprint TEXT NOT NULL, passport TEXT NOT NULL,
      PRIMARY KEY (fingerprint, passport)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS passport_registry (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1), registry TEXT NOT NULL
    ) STRICT;
  `);
  db.prepare('INSERT OR IGNORE INTO passport_registry VALUES (1, ?)').run(registry);
  if (db.prepare('SELECT registry FROM passport_registry WHERE singleton = 1').get().registry !== registry) {
    db.close();
    throw new Error('Registry mismatch');
  }
  const events = db.prepare('SELECT record FROM passport_event WHERE passport = ? ORDER BY sequence');
  const append = db.prepare('INSERT INTO passport_event VALUES (?, ?, ?)');
  const index = db.prepare('INSERT OR IGNORE INTO passport_fingerprint VALUES (?, ?)');
  const lookup = db.prepare('SELECT passport FROM passport_fingerprint WHERE fingerprint = ? ORDER BY passport');
  const history = id => events.all(id).map(row => JSON.parse(row.record));

  function read(id) {
    hash(id, 'Passport ID');
    const records = history(id);
    if (records.length === 0) return null;
    return { ...verifyPassport(records, registry), history: records };
  }

  return {
    append(input) {
      const record = JSON.parse(canonical(input));
      const id = record?.event?.passportId;
      hash(id, 'Passport ID');
      db.exec('BEGIN IMMEDIATE');
      try {
        const records = history(id);
        if (records.some(prior => digest(prior) === digest(record))) {
          const passport = { ...verifyPassport(records, registry), history: records };
          db.exec('COMMIT');
          return passport;
        }
        records.push(record);
        const passport = verifyPassport(records, registry);
        append.run(id, records.length, canonical(record));
        index.run(record.event.manifestDigest, id);
        if (record.event.agentPublicKey !== null) index.run(keyId(record.event.agentPublicKey), id);
        db.exec('COMMIT');
        return { ...passport, history: records };
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
    read,
    lookup(fingerprint) {
      hash(fingerprint, 'Fingerprint');
      return lookup.all(fingerprint).map(row => row.passport);
    },
    close() {
      db.close();
    },
  };
}
