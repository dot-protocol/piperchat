// Copyright 2026 The Pied Piper Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const { randomUUID } = require('crypto');

const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'piperchat.db');

let _db = null;

function getDb() {
  if (_db) return _db;
  _db = new Database(DB_PATH);
  _db.pragma('journal_mode = WAL');
  _db.pragma('synchronous = NORMAL');
  _db.pragma('foreign_keys = ON');
  _applySchema(_db);
  return _db;
}

function _applySchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id               TEXT PRIMARY KEY,
      channel          TEXT NOT NULL DEFAULT 'main',
      author_pubkey    TEXT NOT NULL,
      author_name      TEXT NOT NULL,
      content          TEXT NOT NULL,
      created_at       TEXT NOT NULL,
      prev_hash        TEXT,
      signature        TEXT,
      signed_at        INTEGER,
      legacy           INTEGER NOT NULL DEFAULT 0,
      -- v1.1 DOT-native fields (nullable for backwards compat with v1.0 rows)
      from_dot1        TEXT,
      from_ed25519_pub TEXT,
      sig              TEXT,
      signed           INTEGER NOT NULL DEFAULT 0,
      unsigned_legacy  INTEGER NOT NULL DEFAULT 0,
      attachments_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_messages_channel_time
      ON messages(channel, created_at);

    CREATE TABLE IF NOT EXISTS channels (
      name          TEXT PRIMARY KEY,
      created_at    TEXT NOT NULL,
      message_count INTEGER NOT NULL DEFAULT 0,
      last_activity TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_channels_activity
      ON channels(last_activity DESC);

    CREATE TABLE IF NOT EXISTS keys (
      pubkey      TEXT PRIMARY KEY,
      first_seen  TEXT NOT NULL,
      last_seen   TEXT NOT NULL,
      message_count INTEGER NOT NULL DEFAULT 0
    );
  `);

  // Idempotent column additions for existing databases (ALTER TABLE IF NOT EXISTS
  // is not supported by SQLite; wrap each in a try/catch instead).
  const addIfMissing = (sql) => { try { db.exec(sql); } catch (_) {} };
  // v1.1 columns
  addIfMissing(`ALTER TABLE messages ADD COLUMN from_dot1        TEXT`);
  addIfMissing(`ALTER TABLE messages ADD COLUMN from_ed25519_pub TEXT`);
  addIfMissing(`ALTER TABLE messages ADD COLUMN sig              TEXT`);
  addIfMissing(`ALTER TABLE messages ADD COLUMN signed           INTEGER NOT NULL DEFAULT 0`);
  addIfMissing(`ALTER TABLE messages ADD COLUMN unsigned_legacy  INTEGER NOT NULL DEFAULT 0`);
  addIfMissing(`ALTER TABLE messages ADD COLUMN attachments_json TEXT`);
  // v1.2 E2E encryption columns
  addIfMissing(`ALTER TABLE messages ADD COLUMN from_x25519_pub  TEXT`);
  addIfMissing(`ALTER TABLE messages ADD COLUMN cipher_body       TEXT`);
  addIfMissing(`ALTER TABLE messages ADD COLUMN wraps_json        TEXT`);
  addIfMissing(`ALTER TABLE messages ADD COLUMN encrypted         INTEGER NOT NULL DEFAULT 0`);
  // v1.3 username columns
  addIfMissing(`ALTER TABLE messages ADD COLUMN username          TEXT`);

  // v1.3 usernames registry
  db.exec(`
    CREATE TABLE IF NOT EXISTS usernames (
      username     TEXT PRIMARY KEY,
      dot1         TEXT NOT NULL,
      claimed_at   REAL NOT NULL,
      ed25519_pub  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_usernames_dot1 ON usernames(dot1);
  `);
}

// ── channel helpers ──────────────────────────────────────────────────────────

const CHANNEL_RE = /^[a-z0-9-]{1,32}$/;
function validateChannelName(name) {
  return typeof name === 'string' && CHANNEL_RE.test(name);
}

function ensureChannel(db, name) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT OR IGNORE INTO channels (name, created_at, message_count, last_activity)
    VALUES (?, ?, 0, ?)
  `).run(name, now, now);
}

function touchChannel(db, name, now) {
  db.prepare(`
    UPDATE channels SET message_count = message_count + 1, last_activity = ?
    WHERE name = ?
  `).run(now, name);
}

function touchKey(db, pubkey, now) {
  db.prepare(`
    INSERT INTO keys (pubkey, first_seen, last_seen, message_count)
    VALUES (?, ?, ?, 1)
    ON CONFLICT(pubkey) DO UPDATE SET
      last_seen = excluded.last_seen,
      message_count = message_count + 1
  `).run(pubkey, now, now);
}

// ── write ────────────────────────────────────────────────────────────────────

const _insertMsg = (db) => db.prepare(`
  INSERT OR IGNORE INTO messages
    (id, channel, author_pubkey, author_name, content, created_at, prev_hash, signature, signed_at, legacy,
     from_dot1, from_ed25519_pub, sig, signed, unsigned_legacy, attachments_json,
     from_x25519_pub, cipher_body, wraps_json, encrypted, username)
  VALUES
    (@id, @channel, @author_pubkey, @author_name, @content, @created_at, @prev_hash, @signature, @signed_at, @legacy,
     @from_dot1, @from_ed25519_pub, @sig, @signed, @unsigned_legacy, @attachments_json,
     @from_x25519_pub, @cipher_body, @wraps_json, @encrypted, @username)
`);

function insertMessage(msg) {
  const db  = getDb();
  const now = msg.created_at || new Date().toISOString();
  ensureChannel(db, msg.channel);
  _insertMsg(db).run(msg);
  touchChannel(db, msg.channel, now);
  touchKey(db, msg.author_pubkey, now);
}

// ── read ─────────────────────────────────────────────────────────────────────

function getMessages({ channel = 'main', limit = 100, since } = {}) {
  const db = getDb();
  if (since) {
    // since = ISO timestamp; return messages after that time
    return db.prepare(`
      SELECT * FROM messages
      WHERE channel = ? AND created_at > ?
      ORDER BY created_at ASC
      LIMIT ?
    `).all(channel, since, limit);
  }
  return db.prepare(`
    SELECT * FROM messages
    WHERE channel = ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(channel, limit).reverse();
}

function getLastMessage(channel) {
  return getDb().prepare(`
    SELECT * FROM messages WHERE channel = ? ORDER BY created_at DESC LIMIT 1
  `).get(channel);
}

function getMessage(id) {
  return getDb().prepare('SELECT * FROM messages WHERE id = ?').get(id);
}

function countMessages() {
  return getDb().prepare('SELECT COUNT(*) as n FROM messages').get().n;
}

function countKeys() {
  return getDb().prepare('SELECT COUNT(*) as n FROM keys').get().n;
}

function getChannels() {
  return getDb().prepare(`
    SELECT name, created_at, message_count, last_activity
    FROM channels
    ORDER BY last_activity DESC
  `).all();
}

function getChannelCount() {
  return getDb().prepare('SELECT COUNT(*) as n FROM channels').get().n;
}

// ── usernames ────────────────────────────────────────────────────────────────

const USERNAME_RE = /^[a-z0-9_-]{3,32}$/;
function validateUsername(name) {
  return typeof name === 'string' && USERNAME_RE.test(name);
}

/**
 * Claim a username. Returns:
 *   { ok: true,  claimed: true,  row }   — new claim
 *   { ok: true,  claimed: false, row }   — already claimed by same dot1 (idempotent)
 *   { ok: false, conflict: true, row }   — taken by different dot1
 */
function claimUsername(username, dot1, ed25519_pub) {
  const db  = getDb();
  const now = Date.now();
  const existing = db.prepare('SELECT * FROM usernames WHERE username = ?').get(username);
  if (existing) {
    if (existing.dot1 === dot1) {
      return { ok: true, claimed: false, row: existing };
    }
    return { ok: false, conflict: true, row: existing };
  }
  const row = { username, dot1, claimed_at: now, ed25519_pub };
  db.prepare(`
    INSERT INTO usernames (username, dot1, claimed_at, ed25519_pub) VALUES (?,?,?,?)
  `).run(username, dot1, now, ed25519_pub);
  return { ok: true, claimed: true, row };
}

function getUsernameByName(username) {
  return getDb().prepare('SELECT * FROM usernames WHERE username = ?').get(username) || null;
}

function getUsernameByDot1(dot1) {
  return getDb().prepare('SELECT * FROM usernames WHERE dot1 = ?').get(dot1) || null;
}

function getRecentUsernames(limit = 50) {
  return getDb().prepare('SELECT username, dot1, claimed_at FROM usernames ORDER BY claimed_at DESC LIMIT ?').all(limit);
}

// ── legacy JSON migration ────────────────────────────────────────────────────

function migrateFromJson(jsonPath) {
  if (!fs.existsSync(jsonPath)) return 0;
  const db = getDb();
  const existing = db.prepare('SELECT COUNT(*) as n FROM messages').get().n;
  if (existing > 0) return 0; // only migrate into empty db

  let raw;
  try { raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8')); } catch (_) { return 0; }
  if (!Array.isArray(raw) || raw.length === 0) return 0;

  const insertMany = db.transaction((items) => {
    let imported = 0;
    for (const m of items) {
      const channel   = (m.channel && validateChannelName(m.channel)) ? m.channel : 'main';
      const author    = typeof m.author === 'string' ? m.author.slice(0, 64) : 'unknown';
      const content   = typeof m.content === 'string' ? m.content.slice(0, 4096) : '';
      if (!content) continue;
      const legacy_pubkey = 'legacy-' + randomUUID().slice(0, 8);
      const msg = {
        id:           m.id || randomUUID(),
        channel,
        author_pubkey: legacy_pubkey,
        author_name:  author,
        content,
        created_at:   m.createdAt || new Date().toISOString(),
        prev_hash:    m.prev || null,
        signature:    null,
        signed_at:    null,
        legacy:       1,
      };
      try { insertMessage(msg); imported++; } catch (_) {}
    }
    return imported;
  });

  const count = insertMany(raw);
  console.log(`[db] migrated ${count} messages from ${jsonPath}`);
  return count;
}

// ── close ────────────────────────────────────────────────────────────────────
function close() {
  if (_db) { _db.close(); _db = null; }
}

module.exports = {
  getDb,
  validateChannelName,
  insertMessage,
  getMessages,
  getLastMessage,
  getMessage,
  countMessages,
  countKeys,
  getChannels,
  getChannelCount,
  migrateFromJson,
  close,
  // v1.3 username registry
  validateUsername,
  claimUsername,
  getUsernameByName,
  getUsernameByDot1,
  getRecentUsernames,
};
