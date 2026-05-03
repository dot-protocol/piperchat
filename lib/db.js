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
      id           TEXT PRIMARY KEY,
      channel      TEXT NOT NULL DEFAULT 'main',
      author_pubkey TEXT NOT NULL,
      author_name  TEXT NOT NULL,
      content      TEXT NOT NULL,
      created_at   TEXT NOT NULL,
      prev_hash    TEXT,
      signature    TEXT,
      signed_at    INTEGER,
      legacy       INTEGER NOT NULL DEFAULT 0
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
    (id, channel, author_pubkey, author_name, content, created_at, prev_hash, signature, signed_at, legacy)
  VALUES
    (@id, @channel, @author_pubkey, @author_name, @content, @created_at, @prev_hash, @signature, @signed_at, @legacy)
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
};
