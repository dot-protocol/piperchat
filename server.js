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

const http = require('http');
const fs   = require('fs');
const path = require('path');
const { randomUUID, createHash } = require('crypto');

const db         = require('./lib/db');
const {
  verifyMessage, isSigned,
  isV11Signed, verifyMessageV11, validateAttachments,
  isV12Envelope, verifyV12Envelope,
} = require('./lib/crypto');
const nacl = require('tweetnacl');
const { checkFlood, checkPubkey, checkIp } = require('./lib/ratelimit');
const { capture } = require('./lib/telemetry');

// ── iroh (optional) ───────────────────────────────────────────────────────────
let ShareMode, AddrInfoOptions, Iroh, DocTicket;
try {
  ({ ShareMode, AddrInfoOptions, Iroh, DocTicket } = require('@number0/iroh'));
} catch (_) {
  // iroh optional — chat still works via SSE relay when iroh is unavailable
}

// ── config ────────────────────────────────────────────────────────────────────
const PORT     = parseInt(process.env.PORT    || '4100', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());

const MAX_CONTENT_BYTES = 4096;
const MAX_AUTHOR_BYTES  = 64;

// ── migration: json → sqlite ──────────────────────────────────────────────────
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
db.migrateFromJson(MESSAGES_FILE);

// ── SSE clients per channel ───────────────────────────────────────────────────
// Map<channel, Set<{res, id}>>
const sseChannels = new Map();

function getSseSet(channel) {
  if (!sseChannels.has(channel)) sseChannels.set(channel, new Set());
  return sseChannels.get(channel);
}

function broadcastToChannel(channel, msg) {
  const set = sseChannels.get(channel);
  if (!set) return;
  const line = `data: ${JSON.stringify(msg)}\n\n`;
  for (const client of set) {
    try { client.res.write(line); } catch (_) { set.delete(client); }
  }
}

// ── iroh P2P node ─────────────────────────────────────────────────────────────
let irohNode = null;
let irohDoc  = null;
let nodeId   = 'relay-' + randomUUID().slice(0, 8);

async function initIroh() {
  if (!Iroh) return;
  try {
    irohNode = await Iroh.memory({ enableDocs: true });
    nodeId   = (await irohNode.net.nodeId()).toString();
    irohDoc  = await irohNode.docs.create();
    console.log(`[iroh] node  ${nodeId.slice(0, 20)}...`);
    console.log(`[iroh] doc   ${irohDoc.id().toString().slice(0, 20)}...`);
  } catch (err) {
    console.log(`[iroh] unavailable (${err.message}) — running in relay-only mode`);
    irohNode = null;
    nodeId   = 'relay-' + randomUUID().slice(0, 8);
  }
}

async function writeToIroh(msg) {
  if (!irohDoc) return;
  try {
    const author = await irohNode.authors.default();
    await irohDoc.setBytes(author, Buffer.from(msg.id), Buffer.from(JSON.stringify(msg)));
  } catch (_) {}
}

// ── utilities ─────────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(typeof c === 'string' ? Buffer.from(c) : c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sanitize(str, maxLen = MAX_CONTENT_BYTES) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').slice(0, maxLen);
}

const PUBLIC_DIR = path.join(__dirname, 'public');
function serveFile(filePath, res) {
  try {
    const ext  = path.extname(filePath).toLowerCase();
    const mime = {
      '.html': 'text/html; charset=utf-8',
      '.js':   'text/javascript',
      '.css':  'text/css',
      '.ico':  'image/x-icon',
      '.min.js': 'text/javascript',
    };
    res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream' });
    res.end(fs.readFileSync(filePath));
  } catch (_) {
    res.writeHead(404);
    res.end('not found');
  }
}

function clientIp(req) {
  return (
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket.remoteAddress ||
    'unknown'
  );
}

function corsHeaders(req) {
  const origin = req.headers['origin'] || '*';
  const allow  = ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)
    ? origin
    : 'null';
  return {
    'Access-Control-Allow-Origin':  allow,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}

// ── build a public message object from a db row ───────────────────────────────
function toPublic(row) {
  const isV12 = Boolean(row.encrypted);
  const base = {
    id:          row.id,
    channel:     row.channel,
    version:     isV12 ? '1.2' : (row.from_dot1 ? '1.1' : '1.0'),
    // v1.0 backwards-compat fields
    author:      row.author_name,
    author_name: row.author_name,
    pubkey:      row.author_pubkey,
    pubkeyShort: row.author_pubkey ? row.author_pubkey.slice(0, 4) : '',
    content:     row.content,
    createdAt:   row.created_at,
    prev:        row.prev_hash || null,
    legacy:      Boolean(row.legacy),
    signed:      Boolean(row.signature) || Boolean(row.signed),
    unsigned:    Boolean(row.unsigned_legacy),
    encrypted:   isV12,
  };

  // v1.1 DOT-native fields (present on v1.1 and v1.2 messages)
  if (row.from_dot1) {
    base.from_dot1        = row.from_dot1;
    base.from_ed25519_pub = row.from_ed25519_pub;
    // dot1 short form: last 6 hex chars of the 16-char address suffix
    base.dot1Short        = row.from_dot1.replace('dot1:', '').slice(-6);
    base.sig              = row.sig;
  }

  // v1.3 username
  if (row.username) base.username = row.username;

  // v1.2 E2E encryption fields (only on encrypted messages)
  if (isV12) {
    base.from_x25519_pub = row.from_x25519_pub || null;
    base.cipher_body     = row.cipher_body     || null;
    // Decode wraps from stored JSON string back to array
    if (row.wraps_json) {
      try { base.wraps = JSON.parse(row.wraps_json); } catch (_) { base.wraps = []; }
    } else {
      base.wraps = [];
    }
  }

  // Attachments — decode from JSON string, strip content_b64 for SSE/GET responses
  // (content_b64 is stored and available on direct attachment fetch, not in message lists)
  if (row.attachments_json) {
    try {
      const atts = JSON.parse(row.attachments_json);
      if (Array.isArray(atts)) {
        base.attachments = atts.map(a => ({
          filename:   a.filename,
          mime_type:  a.mime_type,
          size_bytes: a.size_bytes,
          sha256:     a.sha256,
          // include content_b64 in full replies only — strip here for list/SSE
        }));
      }
    } catch (_) {}
  }

  return base;
}

// toPublicFull includes content_b64 (for direct POST response only)
function toPublicFull(row) {
  const pub = toPublic(row);
  if (row.attachments_json) {
    try {
      const atts = JSON.parse(row.attachments_json);
      if (Array.isArray(atts)) pub.attachments = atts; // full, with content_b64
    } catch (_) {}
  }
  return pub;
}

// ── HTTP server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const cors = corsHeaders(req);
  for (const [k, v] of Object.entries(cors)) res.setHeader(k, v);
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p   = url.pathname;

  // ── GET / → chat UI
  if (p === '/' && req.method === 'GET') {
    return serveFile(path.join(PUBLIC_DIR, 'index.html'), res);
  }

  // ── GET /vendor/* → static vendor assets
  if (p.startsWith('/vendor/') && req.method === 'GET') {
    const safe = path.join(PUBLIC_DIR, 'vendor', path.basename(p));
    return serveFile(safe, res);
  }

  // ── GET /channels → list channels
  if (p === '/channels' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(db.getChannels()));
    return;
  }

  // ── GET /events → SSE stream (channel-filtered)
  if (p === '/events' && req.method === 'GET') {
    const channel = url.searchParams.get('channel') || 'main';
    res.writeHead(200, {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    // replay history for this channel
    const history = db.getMessages({ channel, limit: 100 });
    for (const row of history) res.write(`data: ${JSON.stringify(toPublic(row))}\n\n`);

    const client = { res, id: randomUUID() };
    getSseSet(channel).add(client);
    req.on('close', () => {
      const set = sseChannels.get(channel);
      if (set) set.delete(client);
    });
    return;
  }

  // ── GET /health → status
  if (p === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const uptime = process.uptime();
    res.end(JSON.stringify({
      status:           'ok',
      nodeId,
      iroh:             irohNode ? 'connected' : 'offline',
      channels:         db.getChannelCount(),
      messages:         db.countMessages(),
      keys:             db.countKeys(),
      uptime_s:         Math.floor(uptime),
      version:          '1.3.0',
      protocol_version: '1.3',
      protocol_versions_supported: ['1.0', '1.1', '1.2', '1.3'],
    }));
    return;
  }

  // ── POST /messages → send a message
  if (p === '/messages' && req.method === 'POST') {
    // global flood guard
    if (!checkFlood()) {
      res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '10' });
      res.end(JSON.stringify({ error: 'server overloaded — try again shortly' }));
      return;
    }

    let body;
    try {
      body = JSON.parse((await readBody(req)).toString('utf8'));
    } catch (_) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid JSON' }));
      return;
    }

    // channel from query-string takes priority, then body, then default 'main'
    const rawChannel = url.searchParams.get('channel') || body.channel || 'main';
    const channel = sanitize(rawChannel.toLowerCase(), 32);

    if (!db.validateChannelName(channel)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'channel name must match [a-z0-9-]{1,32}' }));
      return;
    }

    // v1.3 username binding: if message includes a username, verify it's claimed by this dot1
    // (Checked before we parse version-specific fields; username is independent of version.)
    const claimedUsername = (typeof body.username === 'string' && body.username.length > 0)
      ? body.username.toLowerCase()
      : null;
    if (claimedUsername) {
      if (!db.validateUsername(claimedUsername)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'username must match [a-z0-9_-]{3,32}' }));
        return;
      }
      // We need the sender dot1 — it's in from_dot1 for v1.1/v1.2, or absent for v1.0
      const senderDot1 = (typeof body.from_dot1 === 'string') ? body.from_dot1 : null;
      if (!senderDot1) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'username requires v1.1 or v1.2 identity (from_dot1 missing)' }));
        return;
      }
      const usernameRow = db.getUsernameByName(claimedUsername);
      if (!usernameRow) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'claim_first', detail: `username "${claimedUsername}" has not been claimed — POST /usernames/claim first` }));
        return;
      }
      if (usernameRow.dot1 !== senderDot1) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'username_mismatch', detail: `username "${claimedUsername}" belongs to a different identity` }));
        return;
      }
    }

    const content = sanitize(body.content || '');
    // v1.2 envelopes carry the body inside cipher_body; content field is optional for them.
    const isV12Request = body.version === '1.2' || (body.cipher_body !== undefined && body.wraps !== undefined);
    if (!content && !isV12Request) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'content required' }));
      return;
    }

    let author_pubkey, author_name, signature = null, signed_at = null, legacy = 0;
    // v1.1 DOT-native fields
    let from_dot1 = null, from_ed25519_pub = null, sig_v11 = null, signed_v11 = 0;
    let unsigned_legacy = 0;
    let attachments_json = null;
    // v1.2 E2E encryption fields
    let from_x25519_pub = null, cipher_body = null, wraps_json = null, encrypted = 0;
    // v1.1/v1.2: use client-provided id/createdAt (signed over them); v1.0: server-generated
    let msg_id         = randomUUID();
    let msg_created_at = new Date().toISOString();

    // Pre-check: partial v1.0 signing fields (has some but not all).
    // Handled before the three-way branch to give a precise error message.
    const looksLikeV10 = (body.pubkey || body.signature || body.signed_at !== undefined) &&
                         body.version !== '1.1' && body.version !== '1.2' && !body.from_dot1;
    if (looksLikeV10 && !isSigned(body)) {
      const problems = [];
      if (typeof body.pubkey    !== 'string' || body.pubkey.length    !== 64)  problems.push(`pubkey must be 64 hex chars (got ${typeof body.pubkey === 'string' ? body.pubkey.length : typeof body.pubkey})`);
      if (typeof body.signature !== 'string' || body.signature.length !== 128) problems.push(`signature must be 128 hex chars (got ${typeof body.signature === 'string' ? body.signature.length : typeof body.signature})`);
      if (typeof body.signed_at !== 'number')                                  problems.push(`signed_at must be a number (ms epoch), got ${typeof body.signed_at}`);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `malformed signing fields: ${problems.join('; ')}` }));
      return;
    }

    // ── v1.2 E2E encrypted envelope path ─────────────────────────────────────
    if (body.version === '1.2' || (body.cipher_body !== undefined && body.wraps !== undefined)) {

      // Validate required v1.2 structure
      const v12problems = [];
      if (!body.from_dot1 || !/^dot1:[0-9a-f]{16}$/.test(body.from_dot1))
        v12problems.push('from_dot1 must match dot1:[0-9a-f]{16}');
      if (typeof body.from_ed25519_pub !== 'string' || body.from_ed25519_pub.length !== 64)
        v12problems.push('from_ed25519_pub must be 64 hex chars');
      if (typeof body.from_x25519_pub !== 'string' || body.from_x25519_pub.length !== 64)
        v12problems.push('from_x25519_pub must be 64 hex chars');
      if (typeof body.cipher_body !== 'string' || body.cipher_body.length === 0)
        v12problems.push('cipher_body must be a non-empty base64 string');
      if (!Array.isArray(body.wraps) || body.wraps.length < 1)
        v12problems.push('wraps must be a non-empty array');
      if (typeof body.sig !== 'string' || body.sig.length !== 128)
        v12problems.push('sig must be 128 hex chars');

      if (v12problems.length > 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `malformed v1.2 envelope: ${v12problems.join('; ')}` }));
        return;
      }

      // Validate cipher_body is valid base64 and has min length (12 nonce + 16 tag = 28 bytes)
      let cipherBuf;
      try {
        cipherBuf = Buffer.from(body.cipher_body, 'base64');
      } catch (_) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'v1.2: cipher_body is not valid base64' }));
        return;
      }
      if (cipherBuf.length < 28) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `v1.2: cipher_body too short (${cipherBuf.length} bytes, min 28)` }));
        return;
      }

      // Validate each wrap entry
      for (const wrap of body.wraps) {
        if (!wrap || typeof wrap !== 'object') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'v1.2: each wrap must be an object' }));
          return;
        }
        if (!/^dot1:[0-9a-f]{16}$/.test(wrap.recipient_dot1 || '')) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `v1.2: wrap.recipient_dot1 invalid: ${wrap.recipient_dot1}` }));
          return;
        }
        try {
          const wrapBuf = Buffer.from(wrap.wrapped_body_key || '', 'base64');
          if (wrapBuf.length < 60) throw new Error('too short');
        } catch (_) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `v1.2: wrap.wrapped_body_key invalid for ${wrap.recipient_dot1}` }));
          return;
        }
      }

      // Validate attachments (metadata only — same as v1.1)
      const atts = validateAttachments(body.attachments);

      // Server-side sig verification (server does NOT decrypt — just verifies authenticity)
      const clientId        = (typeof body.id === 'string' && body.id.length > 0) ? body.id : randomUUID();
      const clientCreatedAt = (typeof body.createdAt === 'string' && body.createdAt.length > 0)
        ? body.createdAt : new Date().toISOString();

      const envForVerify = {
        id:               clientId,
        version:          '1.2',
        channel,
        createdAt:        clientCreatedAt,
        prev:             body.prev !== undefined ? body.prev : null,
        from_dot1:        body.from_dot1,
        from_ed25519_pub: body.from_ed25519_pub,
        from_x25519_pub:  body.from_x25519_pub,
        cipher_body:      body.cipher_body,
        wraps:            body.wraps,
        sig:              body.sig,
      };

      const check = verifyV12Envelope(envForVerify, atts);
      if (!check.ok) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `v1.2 signature rejected: ${check.reason}` }));
        return;
      }

      // per-pubkey rate limit
      if (!checkPubkey(body.from_ed25519_pub)) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
        res.end(JSON.stringify({ error: 'rate limit: 30 signed messages per minute' }));
        return;
      }

      // Server stores the envelope as-is. content field is set to
      // '[encrypted v1.2 message — upgrade client]' for legacy clients.
      author_pubkey    = body.from_ed25519_pub;
      author_name      = sanitize(body.author_name || body.author || body.from_dot1, MAX_AUTHOR_BYTES);
      from_dot1        = body.from_dot1;
      from_ed25519_pub = body.from_ed25519_pub;
      from_x25519_pub  = body.from_x25519_pub;
      sig_v11          = body.sig;
      signed_v11       = 1;
      cipher_body      = body.cipher_body;
      wraps_json       = JSON.stringify(body.wraps);
      encrypted        = 1;
      if (atts.length > 0) attachments_json = JSON.stringify(atts);
      msg_id         = clientId;
      msg_created_at = clientCreatedAt;

      // Telemetry + build row + store + broadcast (falls through to common store path below)

    } else if (body.version === '1.1' || isV11Signed(body)) {
    // ── v1.1 DOT-native path ──────────────────────────────────────────────────

      // Detect partial v1.1 (has version="1.1" or from_dot1 but missing sig fields)
      if (!isV11Signed(body)) {
        const problems = [];
        if (!body.from_dot1 || !/^dot1:[0-9a-f]{16}$/.test(body.from_dot1))
          problems.push('from_dot1 must match dot1:[0-9a-f]{16}');
        if (typeof body.from_ed25519_pub !== 'string' || body.from_ed25519_pub.length !== 64)
          problems.push('from_ed25519_pub must be 64 hex chars');
        if (typeof body.sig !== 'string' || body.sig.length !== 128)
          problems.push('sig must be 128 hex chars');
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `malformed v1.1 signing fields: ${problems.join('; ')}` }));
        return;
      }

      // Validate + cap attachments before building the canonical bytes
      const atts = validateAttachments(body.attachments);

      // The signature covers the canonical form that the CLIENT built, which includes
      // the client-supplied id and createdAt. We verify against those exact values.
      // The server does NOT regenerate id/createdAt for the verification step.
      const clientId        = (typeof body.id === 'string' && body.id.length > 0) ? body.id : randomUUID();
      const clientCreatedAt = (typeof body.createdAt === 'string' && body.createdAt.length > 0)
        ? body.createdAt : new Date().toISOString();

      const msgForVerify = {
        id:               clientId,
        version:          '1.1',
        content,
        channel,
        createdAt:        clientCreatedAt,
        prev:             body.prev !== undefined ? body.prev : null,
        from_dot1:        body.from_dot1,
        from_ed25519_pub: body.from_ed25519_pub,
      };

      const check = verifyMessageV11({ ...msgForVerify, sig: body.sig }, atts);
      if (!check.ok) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `v1.1 signature rejected: ${check.reason}` }));
        return;
      }

      // per-pubkey rate limit (keyed on ed25519 pub)
      if (!checkPubkey(body.from_ed25519_pub)) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
        res.end(JSON.stringify({ error: 'rate limit: 30 signed messages per minute' }));
        return;
      }

      author_pubkey    = body.from_ed25519_pub; // use ed25519 pub as the storage key
      author_name      = sanitize(body.author_name || body.author || body.from_dot1, MAX_AUTHOR_BYTES);
      from_dot1        = body.from_dot1;
      from_ed25519_pub = body.from_ed25519_pub;
      sig_v11          = body.sig;
      signed_v11       = 1;
      if (atts.length > 0) attachments_json = JSON.stringify(atts);
      // Preserve client-generated id and createdAt (they were signed over)
      msg_id         = clientId;
      msg_created_at = clientCreatedAt;

    } else if (isSigned(body)) {
      // ── v1.0 signed path ──────────────────────────────────────────────────
      const check = verifyMessage({ ...body, channel, content });
      if (!check.ok) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `signature rejected: ${check.reason}` }));
        return;
      }

      // per-pubkey rate limit
      if (!checkPubkey(body.pubkey)) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
        res.end(JSON.stringify({ error: 'rate limit: 30 signed messages per minute' }));
        return;
      }

      author_pubkey = body.pubkey;
      author_name   = sanitize(body.author_name || body.author || 'anonymous', MAX_AUTHOR_BYTES);
      signature     = body.signature;
      signed_at     = body.signed_at;

    } else {
      // ── unsigned / legacy path ────────────────────────────────────────────
      // (partial v1.0 signing fields are caught above before this branch)
      const ip = clientIp(req);
      if (!checkIp(ip)) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
        res.end(JSON.stringify({ error: 'rate limit: 30 messages per minute per IP' }));
        return;
      }

      author_pubkey   = 'legacy-' + createHash('sha256').update(ip).digest('hex').slice(0, 8);
      author_name     = sanitize(body.author || 'anonymous', MAX_AUTHOR_BYTES);
      legacy          = 1;
      unsigned_legacy = 1;

      // Emit a deprecation warning to telemetry for monitoring
      capture('unsigned_message_posted', { channel, ip_hash: author_pubkey });
    }

    // build prev_hash from last message in this channel
    const last     = db.getLastMessage(channel);
    const prev_hash = last
      ? createHash('sha256').update(last.id + last.content).digest('hex').slice(0, 16)
      : null;

    // For v1.2 encrypted messages, the stored `content` is a placeholder for legacy clients.
    // The real plaintext is inside cipher_body and never touches the server in plaintext.
    const storedContent = encrypted ? '[encrypted v1.2 message — upgrade client]' : content;

    const newRow = {
      id:              msg_id,
      channel,
      author_pubkey,
      author_name,
      content:         storedContent,
      created_at:      msg_created_at,
      prev_hash,
      signature,
      signed_at,
      legacy,
      // v1.1 fields
      from_dot1,
      from_ed25519_pub,
      sig:             sig_v11,
      signed:          signed_v11,
      unsigned_legacy,
      attachments_json,
      // v1.2 fields
      from_x25519_pub,
      cipher_body,
      wraps_json,
      encrypted,
      // v1.3 username (optional)
      username:        claimedUsername || null,
    };

    // dedup: same pubkey + id within 10 seconds in this channel.
    // For v1.2 we key on id (client-generated) rather than content (which is an opaque blob).
    const recent = db.getMessages({ channel, limit: 10 });
    const dup = recent.find(m =>
      encrypted
        ? m.id === msg_id   // v1.2: dedup by id
        : (m.author_pubkey === author_pubkey &&
           m.content       === storedContent &&
           Date.now() - new Date(m.created_at).getTime() < 10_000)
    );
    if (dup) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, message: toPublicFull(dup), deduped: true }));
      return;
    }

    db.insertMessage(newRow);

    const pub     = toPublic(newRow);     // for SSE broadcast (no content_b64)
    const pubFull = toPublicFull(newRow); // for POST response (with content_b64)
    broadcastToChannel(channel, pub);
    writeToIroh(pub);

    // telemetry
    const msgVersion = encrypted ? '1.2' : (from_dot1 ? '1.1' : '1.0');
    capture('message_posted', {
      channel,
      pubkey:    author_pubkey,
      legacy:    Boolean(legacy),
      version:   msgVersion,
      signed:    Boolean(signed_v11 || signature),
      encrypted: Boolean(encrypted),
    });
    if (!legacy && author_pubkey && !recent.some(m => m.author_pubkey === author_pubkey)) {
      capture('key_first_seen', { pubkey: author_pubkey });
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, message: pubFull }));
    return;
  }

  // ── GET /messages → history
  if (p === '/messages' && req.method === 'GET') {
    const channel = url.searchParams.get('channel') || 'main';
    const limit   = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 500);
    const since   = url.searchParams.get('since') || null;  // ISO timestamp

    const rows = db.getMessages({ channel, limit, since });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(rows.map(toPublic)));
    return;
  }

  // ── GET /ticket → iroh doc share ticket (backwards compat)
  if (p === '/ticket' && req.method === 'GET') {
    if (!irohDoc) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'iroh unavailable — running in relay-only mode' }));
      return;
    }
    try {
      const ticket = await irohDoc.share(ShareMode.Read, AddrInfoOptions.Id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ticket: ticket.toString() }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // ── POST /usernames/claim → first-claim-wins username registration ─────────
  if (p === '/usernames/claim' && req.method === 'POST') {
    let body;
    try {
      body = JSON.parse((await readBody(req)).toString('utf8'));
    } catch (_) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid JSON' }));
      return;
    }

    const { username, dot1, ed25519_pub, sig } = body;

    // Validate all fields present
    const problems = [];
    if (!db.validateUsername(username))
      problems.push('username must match [a-z0-9_-]{3,32}');
    if (typeof dot1 !== 'string' || !/^dot1:[0-9a-f]{16}$/.test(dot1))
      problems.push('dot1 must match dot1:[0-9a-f]{16}');
    if (typeof ed25519_pub !== 'string' || ed25519_pub.length !== 64 || !/^[0-9a-f]+$/.test(ed25519_pub))
      problems.push('ed25519_pub must be 64 hex chars');
    if (typeof sig !== 'string' || sig.length !== 128 || !/^[0-9a-f]+$/.test(sig))
      problems.push('sig must be 128 hex chars');
    if (problems.length > 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: problems.join('; ') }));
      return;
    }

    // Verify signature: sig = ed25519_sign(priv, "claim:<username>:<dot1>")
    const claimBytes = Buffer.from(`claim:${username.toLowerCase()}:${dot1}`, 'utf8');
    const pubBytes   = Buffer.from(ed25519_pub, 'hex');
    const sigBytes   = Buffer.from(sig, 'hex');
    let sigValid = false;
    try {
      sigValid = nacl.sign.detached.verify(claimBytes, sigBytes, pubBytes);
    } catch (_) {}
    if (!sigValid) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'signature verification failed' }));
      return;
    }

    const result = db.claimUsername(username.toLowerCase(), dot1, ed25519_pub);
    if (!result.ok) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error:       'username taken',
        claimed_by:  result.row.dot1,
        claimed_at:  result.row.claimed_at,
      }));
      return;
    }

    capture('username_claimed', { username: username.toLowerCase(), dot1 });
    res.writeHead(result.claimed ? 201 : 200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, username: result.row.username, dot1: result.row.dot1, claimed_at: result.row.claimed_at }));
    return;
  }

  // ── GET /usernames/:name → look up by username ───────────────────────────────
  const unameMatch = p.match(/^\/usernames\/([a-z0-9_-]{3,32})$/);
  if (unameMatch && req.method === 'GET') {
    const row = db.getUsernameByName(unameMatch[1]);
    if (!row) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ username: row.username, dot1: row.dot1, claimed_at: row.claimed_at }));
    return;
  }

  // ── GET /usernames?dot1=X  or  GET /usernames?limit=N ────────────────────────
  if (p === '/usernames' && req.method === 'GET') {
    const dot1Param = url.searchParams.get('dot1');
    if (dot1Param) {
      const row = db.getUsernameByDot1(dot1Param);
      if (!row) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ username: row.username, dot1: row.dot1, claimed_at: row.claimed_at }));
      return;
    }
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
    const rows  = db.getRecentUsernames(limit);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(rows));
    return;
  }

  // ── POST /connect → join peer via iroh ticket (backwards compat)
  if (p === '/connect' && req.method === 'POST') {
    let body;
    try { body = JSON.parse((await readBody(req)).toString('utf8')); }
    catch (_) { res.writeHead(400); res.end('{}'); return; }

    if (!irohNode) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'iroh unavailable' }));
      return;
    }
    try {
      const t = DocTicket.fromString(body.ticket);
      await irohNode.docs.import(t);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  res.writeHead(404);
  res.end('not found');
});

// ── start ─────────────────────────────────────────────────────────────────────
async function start() {
  await initIroh();
  server.listen(PORT, () => {
    console.log(`piper-chat listening on http://localhost:${PORT}`);
    console.log(`iroh: ${irohNode ? 'connected' : 'offline (relay-only mode)'}`);
    console.log('open the URL in two browser tabs to test locally.');
  });
}

start().catch(err => { console.error(err); process.exit(1); });
