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
const fs = require('fs');
const path = require('path');
const { randomUUID, createHash } = require('crypto');

// iroh: P2P document sync (https://github.com/n0-computer/iroh, MIT OR Apache-2.0)
let ShareMode, AddrInfoOptions, Iroh, DocTicket;
try {
  ({ ShareMode, AddrInfoOptions, Iroh, DocTicket } = require('@number0/iroh'));
} catch (_) {
  // iroh optional — chat still works via SSE relay when iroh is unavailable
}

const PORT = parseInt(process.env.PORT || '4100', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

// ── in-memory store ───────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
let messages = [];
try { messages = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8')); } catch (_) {}
function saveMessages() {
  try { fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages)); } catch (_) {}
}

// ── rate limiting (in-memory, per IP) ────────────────────────────────────────
const _rateLimits = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_MSGS = 30;
const MAX_CONTENT_BYTES = 4096;

function checkRateLimit(ip) {
  const now = Date.now();
  let e = _rateLimits.get(ip);
  if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + RATE_WINDOW_MS }; _rateLimits.set(ip, e); }
  return ++e.count <= RATE_MAX_MSGS;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of _rateLimits) { if (now > e.resetAt) _rateLimits.delete(ip); }
}, 300_000);

function sanitize(str, maxLen = MAX_CONTENT_BYTES) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').slice(0, maxLen);
}

// ── SSE clients ───────────────────────────────────────────────────────────────
const sseClients = new Set();

function broadcast(msg) {
  const line = `data: ${JSON.stringify(msg)}\n\n`;
  for (const res of sseClients) { try { res.write(line); } catch (_) {} }
}

// ── iroh P2P node ─────────────────────────────────────────────────────────────
let irohNode = null;
let irohDoc = null;
let nodeId = 'no-iroh-' + randomUUID().slice(0, 8);

async function initIroh() {
  if (!Iroh) return;
  try {
    irohNode = await Iroh.memory({ enableDocs: true });
    nodeId = (await irohNode.net.nodeId()).toString();
    irohDoc = await irohNode.docs.create();
    console.log(`[iroh] node  ${nodeId.slice(0, 20)}...`);
    console.log(`[iroh] doc   ${irohDoc.id().toString().slice(0, 20)}...`);
  } catch (err) {
    console.log(`[iroh] unavailable (${err.message}) — running in relay-only mode`);
    irohNode = null;
    nodeId = 'relay-' + randomUUID().slice(0, 8);
  }
}

async function writeToIroh(msg) {
  if (!irohDoc) return;
  try {
    const author = await irohNode.authors.default();
    await irohDoc.setBytes(author, Buffer.from(msg.id), Buffer.from(JSON.stringify(msg)));
  } catch (_) {}
}

// ── body reader ──────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(typeof c === 'string' ? Buffer.from(c) : c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ── static file helper ────────────────────────────────────────────────────────
const PUBLIC_DIR = path.join(__dirname, 'public');
function serveFile(filePath, res) {
  try {
    const ext = path.extname(filePath).toLowerCase();
    const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.ico': 'image/x-icon' };
    res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream' });
    res.end(fs.readFileSync(filePath));
  } catch (_) {
    res.writeHead(404);
    res.end('Not found');
  }
}

// ── HTTP server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p = url.pathname;

  // ── GET / → chat UI
  if (p === '/' && req.method === 'GET') {
    return serveFile(path.join(PUBLIC_DIR, 'index.html'), res);
  }

  // ── GET /events → SSE stream
  if (p === '/events' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    // replay history to new client
    for (const m of messages) res.write(`data: ${JSON.stringify(m)}\n\n`);
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // ── GET /health → status
  if (p === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      nodeId,
      peers: irohNode ? 1 : 0,
      messages: messages.length,
      iroh: irohNode ? 'connected' : 'offline',
    }));
    return;
  }

  // ── POST /messages → send a message
  if (p === '/messages' && req.method === 'POST') {
    const clientIp = ((req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(clientIp)) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      res.end(JSON.stringify({ error: 'rate limit exceeded: 30 messages per minute per IP' }));
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

    const content = sanitize(body.content || '');
    const author = sanitize(body.author || 'anonymous', 64);
    if (!content) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'content required' }));
      return;
    }

    // simple dedup: same author + content within 10s
    const recent = messages.slice(-20).find(m =>
      m.author === author && m.content === content &&
      Date.now() - new Date(m.createdAt).getTime() < 10_000
    );
    if (recent) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, message: recent, deduped: true }));
      return;
    }

    const prev = messages.length > 0 ? messages[messages.length - 1] : null;
    const msg = {
      id: randomUUID(),
      content,
      author,
      channel: sanitize(body.channel || 'main', 32),
      createdAt: new Date().toISOString(),
      prev: prev ? createHash('sha256').update(JSON.stringify(prev)).digest('hex').slice(0, 16) : null,
    };

    messages.push(msg);
    saveMessages();
    broadcast(msg);
    writeToIroh(msg);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, message: msg }));
    return;
  }

  // ── GET /messages → history
  if (p === '/messages' && req.method === 'GET') {
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 500);
    const since = url.searchParams.get('since');
    let result = messages;
    if (since) {
      const idx = result.findIndex(m => m.id === since);
      if (idx >= 0) result = result.slice(idx + 1);
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result.slice(-limit)));
    return;
  }

  // ── GET /ticket → iroh doc share ticket
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

  // ── POST /connect → join peer via iroh ticket
  if (p === '/connect' && req.method === 'POST') {
    let body;
    try { body = JSON.parse((await readBody(req)).toString('utf8')); } catch (_) {
      res.writeHead(400); res.end('{}'); return;
    }
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
