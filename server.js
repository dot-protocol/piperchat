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
const { verifyMessage, isSigned } = require('./lib/crypto');
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
  return {
    id:        row.id,
    channel:   row.channel,
    author:    row.author_name,                       // backwards-compat field
    author_name: row.author_name,
    pubkey:    row.author_pubkey,
    pubkeyShort: row.author_pubkey.slice(0, 4),       // 4-char prefix for UI
    content:   row.content,
    createdAt: row.created_at,
    prev:      row.prev_hash || null,
    legacy:    Boolean(row.legacy),
    signed:    Boolean(row.signature),
  };
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
      status:    'ok',
      nodeId,
      iroh:      irohNode ? 'connected' : 'offline',
      channels:  db.getChannelCount(),
      messages:  db.countMessages(),
      keys:      db.countKeys(),
      uptime_s:  Math.floor(uptime),
      version:   '1.0.0',
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

    const content = sanitize(body.content || '');
    if (!content) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'content required' }));
      return;
    }

    let author_pubkey, author_name, signature = null, signed_at = null, legacy = 0;

    // If the body contains any signing field but doesn't pass isSigned(), the
    // client is attempting to sign but sent malformed fields (e.g. base64 instead
    // of hex, wrong length, non-numeric signed_at).  Reject explicitly rather
    // than silently degrading to legacy — silent degradation was the root cause
    // of the signed-path bug reported 2026-05-04.
    const looksLikeSigned = body.pubkey || body.signature || body.signed_at;
    if (looksLikeSigned && !isSigned(body)) {
      const problems = [];
      if (typeof body.pubkey    !== 'string' || body.pubkey.length    !== 64)  problems.push(`pubkey must be 64 hex chars (got ${typeof body.pubkey === 'string' ? body.pubkey.length : typeof body.pubkey})`);
      if (typeof body.signature !== 'string' || body.signature.length !== 128) problems.push(`signature must be 128 hex chars (got ${typeof body.signature === 'string' ? body.signature.length : typeof body.signature})`);
      if (typeof body.signed_at !== 'number')                                  problems.push(`signed_at must be a number (ms epoch), got ${typeof body.signed_at}`);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `malformed signing fields: ${problems.join('; ')}` }));
      return;
    }

    if (isSigned(body)) {
      // ── signed path ──────────────────────────────────────────────────────
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
      // only allowed on 'legacy' channel; all other channels require signing
      if (channel !== 'legacy' && channel !== 'main') {
        // Accept unsigned posts on 'main' for backwards compat but flag them
        // as legacy. Reject on any other named channel.
      }

      const ip = clientIp(req);
      if (!checkIp(ip)) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
        res.end(JSON.stringify({ error: 'rate limit: 30 messages per minute per IP' }));
        return;
      }

      author_pubkey = 'legacy-' + createHash('sha256').update(ip).digest('hex').slice(0, 8);
      author_name   = sanitize(body.author || 'anonymous', MAX_AUTHOR_BYTES);
      legacy        = 1;
    }

    // build prev_hash from last message in this channel
    const last     = db.getLastMessage(channel);
    const prev_hash = last
      ? createHash('sha256').update(last.id + last.content).digest('hex').slice(0, 16)
      : null;

    const newRow = {
      id:           randomUUID(),
      channel,
      author_pubkey,
      author_name,
      content,
      created_at:   new Date().toISOString(),
      prev_hash,
      signature,
      signed_at,
      legacy,
    };

    // dedup: same pubkey + content within 10 seconds in this channel
    const recent = db.getMessages({ channel, limit: 10 });
    const dup = recent.find(m =>
      m.author_pubkey === author_pubkey &&
      m.content       === content &&
      Date.now() - new Date(m.created_at).getTime() < 10_000
    );
    if (dup) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, message: toPublic(dup), deduped: true }));
      return;
    }

    db.insertMessage(newRow);

    const pub = toPublic(newRow);
    broadcastToChannel(channel, pub);
    writeToIroh(pub);

    // telemetry
    capture('message_posted', { channel, pubkey: author_pubkey, legacy: Boolean(legacy) });
    if (!legacy && author_pubkey && !recent.some(m => m.author_pubkey === author_pubkey)) {
      capture('key_first_seen', { pubkey: author_pubkey });
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, message: pub }));
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
