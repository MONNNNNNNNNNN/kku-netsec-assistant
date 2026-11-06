'use strict';
/*
 * SQLite store (node:sqlite, built in). The file holds unmasked IPs and account names
 * (PDPA personal data): it is created 0600, kept for `retentionDays`, and every user
 * action on it is recorded in user_actions. Treat it as an ISMS information asset.
 */
// node:sqlite is stable on Node 24; Node 22 prints an ExperimentalWarning. Silence only that one.
const emitWarning = process.emitWarning;
process.emitWarning = function (w, ...a) {
  const type = typeof a[0] === 'string' ? a[0] : a[0] && a[0].type;
  if (type === 'ExperimentalWarning' && /SQLite/i.test(String(w && w.message ? w.message : w))) return;
  return emitWarning.call(this, w, ...a);
};
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL, role TEXT NOT NULL, created TEXT NOT NULL, failed INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, csrf TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS items (
     id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL,
     severity TEXT NOT NULL, det_severity TEXT NOT NULL, title TEXT NOT NULL,
     trusted TEXT NOT NULL, untrusted TEXT NOT NULL, flags TEXT NOT NULL, floor TEXT NOT NULL DEFAULT '[]',
     count INTEGER NOT NULL DEFAULT 1, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
     pinned_by TEXT, pinned_at INTEGER, acked_by TEXT, acked_at INTEGER, snoozed_until INTEGER, snoozed_by TEXT,
     resolved_at INTEGER, link TEXT, llm TEXT, llm_state TEXT NOT NULL DEFAULT 'none', notified_severity TEXT)`,
  `CREATE INDEX IF NOT EXISTS items_last_seen ON items(last_seen)`,
  `CREATE TABLE IF NOT EXISTS source_state (source TEXT PRIMARY KEY, cursor TEXT, last_run INTEGER, last_ok INTEGER, last_error TEXT, next_run INTEGER, fails INTEGER NOT NULL DEFAULT 0, received INTEGER NOT NULL DEFAULT 0, filtered INTEGER NOT NULL DEFAULT 0, dropped INTEGER NOT NULL DEFAULT 0, dropped_senders TEXT NOT NULL DEFAULT '{}', unsupported INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'idle')`,
  `CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, source TEXT NOT NULL, started INTEGER NOT NULL, ms INTEGER, ok INTEGER, n INTEGER, error TEXT)`,
  `CREATE TABLE IF NOT EXISTS llm_audit (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, item_ids TEXT, endpoint TEXT, endpoint_class TEXT, overrides TEXT, model TEXT, prompt_sha256 TEXT, messages TEXT, reply TEXT, ms INTEGER, error TEXT)`,
  `CREATE TABLE IF NOT EXISTS user_actions (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, username TEXT, ip TEXT, action TEXT NOT NULL, item_id INTEGER, detail TEXT)`,
  `CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, channel TEXT NOT NULL, msg TEXT, item_id INTEGER, severity TEXT, ok INTEGER, digest INTEGER NOT NULL DEFAULT 0, error TEXT)`,
  `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)`,
];

function openDb(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const file = path.join(dataDir, 'board.db');
  if (!fs.existsSync(file)) fs.closeSync(fs.openSync(file, 'a', 0o600));
  try { fs.chmodSync(file, 0o600); } catch { /* read-only fs: best effort */ }
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;');
  for (const s of SCHEMA) db.exec(s);
  db.file = file;
  return db;
}

function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
}

const getMeta = (db, k) => { const r = db.prepare('SELECT value FROM meta WHERE key = ?').get(k); return r ? JSON.parse(r.value) : null; };
const setMeta = (db, k, v) => db.prepare('INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, JSON.stringify(v));

function sourceState(db, source) {
  let r = db.prepare('SELECT * FROM source_state WHERE source = ?').get(source);
  if (!r) { db.prepare('INSERT OR IGNORE INTO source_state(source) VALUES(?)').run(source); r = db.prepare('SELECT * FROM source_state WHERE source = ?').get(source); }
  return r;
}
function updateSource(db, source, patch) {
  sourceState(db, source);
  const keys = Object.keys(patch);
  if (!keys.length) return;
  db.prepare(`UPDATE source_state SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE source = ?`).run(...keys.map((k) => patch[k]), source);
}
function bumpSource(db, source, field, n = 1) {
  sourceState(db, source);
  db.prepare(`UPDATE source_state SET ${field} = ${field} + ? WHERE source = ?`).run(n, source);
}

function logAction(db, user, action, itemId = null, detail = null, ip = null) {
  db.prepare('INSERT INTO user_actions(ts, username, ip, action, item_id, detail) VALUES(?, ?, ?, ?, ?, ?)').run(Date.now(), user || null, ip, action, itemId, detail == null ? null : String(detail).slice(0, 500));
}

/** Delete data older than the retention window. Pinned items are kept. */
function retention(db, days, now = Date.now()) {
  const cut = now - days * 86400000;
  const n = db.prepare('DELETE FROM items WHERE last_seen < ? AND pinned_at IS NULL').run(cut).changes;
  for (const [t, c] of [['runs', 'started'], ['llm_audit', 'ts'], ['user_actions', 'ts'], ['notifications', 'ts']]) db.prepare(`DELETE FROM ${t} WHERE ${c} < ?`).run(cut);
  db.prepare('DELETE FROM sessions WHERE expires < ?').run(now);
  return n;
}

module.exports = { openDb, tx, getMeta, setMeta, sourceState, updateSource, bumpSource, logAction, retention };
