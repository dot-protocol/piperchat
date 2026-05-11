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

// PiperClient — thin Node.js wrapper around piper-chat's HTTP + SSE API.
// Supports both v1.0 (legacy) and v1.1 (DOT-native, ed25519-signed) message formats.
// Zero external dependencies beyond those already in package.json. Node 20+ built-ins only.

const http        = require('http');
const https       = require('https');
const fs          = require('fs');
const { randomUUID, createHash } = require('crypto');

// v1.1 crypto helpers (require tweetnacl from package.json)
const { signMessageV11, verifyMessageV11, validateAttachments } = require('./lib/crypto');

const DEFAULT_URL     = 'http://localhost:4101';
const DEFAULT_CHANNEL = 'main';
const BACKOFF_INITIAL = 1_000;
const BACKOFF_MAX     = 30_000;

// ── cell file parser ──────────────────────────────────────────────────────────
/**
 * Parse a cell_*.md file and extract the PUBKEYS section values.
 * The PUBKEYS section looks like:
 *   ## PUBKEYS (derived from canonical section — safe to share)
 *   ed25519_pub: <64 hex chars>
 *   x25519_pub:  <64 hex chars>
 *
 * @param {string} cellPath  - absolute path to the cell_*.md file
 * @returns {{ ed25519_pub: string, x25519_pub: string, dot1: string } | null}
 */
function parseCellFile(cellPath) {
  try {
    const text = fs.readFileSync(cellPath, 'utf8');

    // Extract dot1 address from "Personal `dot1:`:" line
    const dot1Match = text.match(/\*\*Personal `dot1:`:\*\*\s*(dot1:[0-9a-f]{16})/);
    const dot1      = dot1Match ? dot1Match[1] : null;

    // Extract PUBKEYS section
    const ed25519Match = text.match(/^ed25519_pub:\s*([0-9a-f]{64})\s*$/m);
    const x25519Match  = text.match(/^x25519_pub:\s*([0-9a-f]{64})\s*$/m);

    if (!ed25519Match) return null;

    return {
      ed25519_pub: ed25519Match[1],
      x25519_pub:  x25519Match ? x25519Match[1] : null,
      dot1:        dot1 || null,
    };
  } catch (_) {
    return null;
  }
}

class PiperClient {
  /**
   * @param {object}  opts
   * @param {string}  [opts.author]           - Display name for this client.
   * @param {string}  [opts.url]              - Base URL of the piper-chat server.
   * @param {string}  [opts.channel]          - Default channel for send().
   * @param {boolean} [opts.includeOwn]       - If true, subscribe() also fires for own messages.
   *
   * v1.1 identity options (DOT-native signing):
   * @param {string}  [opts.dot1]             - dot1: address (e.g. "dot1:6d94e2c24a06486b")
   * @param {string}  [opts.ed25519PubHex]    - 64-hex ed25519 public key
   * @param {string}  [opts.ed25519PrivHex]   - 128-hex ed25519 private key (seed+pub concatenated)
   *                                            If provided, all outgoing messages are v1.1-signed.
   * @param {string}  [opts.cellPath]         - Path to a cell_*.md file. If given, ed25519PubHex
   *                                            and dot1 are read from the file's PUBKEYS section.
   *                                            ed25519PrivHex must still be supplied separately.
   */
  constructor(opts = {}) {
    this.author     = opts.author || 'anonymous';
    this.url        = (opts.url || DEFAULT_URL).replace(/\/$/, '');
    this.channel    = opts.channel || DEFAULT_CHANNEL;
    this.includeOwn = Boolean(opts.includeOwn);

    // v1.1 identity
    this._dot1    = opts.dot1    || null;
    this._ed25519Pub  = opts.ed25519PubHex  || null;
    this._ed25519Priv = opts.ed25519PrivHex || null;

    // Load pub+dot1 from cell file if provided (priv must still be supplied separately)
    if (opts.cellPath) {
      const parsed = parseCellFile(opts.cellPath);
      if (parsed) {
        if (!this._ed25519Pub && parsed.ed25519_pub) this._ed25519Pub = parsed.ed25519_pub;
        if (!this._dot1 && parsed.dot1) this._dot1 = parsed.dot1;
      }
    }

    this._handlers   = new Set();   // subscribe() callbacks
    this._sseReq     = null;        // active http.ClientRequest
    this._closed     = false;
    this._backoff    = BACKOFF_INITIAL;
    this._retryTimer = null;
  }

  /** Returns true if this client has a v1.1 signing identity configured. */
  get canSignV11() {
    return Boolean(this._ed25519Priv && this._ed25519Pub && this._dot1);
  }

  // ── public API ──────────────────────────────────────────────────────────────

  /**
   * Send a message. If the client has a v1.1 identity (dot1 + ed25519PrivHex),
   * the message is signed with v1.1 protocol. Otherwise falls back to v1.0 unsigned.
   *
   * @param {string}  content             - Message text
   * @param {string}  [channel]           - Override default channel
   * @param {Array}   [attachments]       - DOTpost v1.3 attachments (optional)
   *   Each item: { filename, mime_type, size_bytes, sha256, content_b64 }
   * @returns {Promise<object>} - The stored message object from the server
   */
  async send(content, channel, attachments) {
    const ch   = channel || this.channel;
    const atts = validateAttachments(attachments || []);

    if (this.canSignV11) {
      return this._sendV11(content, ch, atts);
    }

    // v1.0 unsigned fallback
    const body = JSON.stringify({ content, author: this.author, channel: ch });
    const res  = await this._fetch('/messages', { method: 'POST', body });
    return res.message;
  }

  /**
   * Subscribe to incoming messages via SSE.
   * Calls handler(msg) for each new message.
   * By default, skips messages from this client's own dot1/author.
   * For v1.1 messages, the handler receives a `verified` field indicating
   * whether the signature was successfully verified client-side.
   * Returns an unsubscribe function.
   */
  subscribe(handler) {
    if (typeof handler !== 'function') throw new TypeError('handler must be a function');
    this._handlers.add(handler);
    if (!this._sseReq) this._connectSSE();
    return () => {
      this._handlers.delete(handler);
      if (this._handlers.size === 0) this._disconnectSSE();
    };
  }

  /** Fetch message history. */
  async history({ limit = 100, since } = {}) {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (since) qs.set('since', since);
    return this._fetch(`/messages?${qs}`);
  }

  /** Check server health. */
  async health() {
    return this._fetch('/health');
  }

  /** Disconnect SSE and prevent reconnects. */
  close() {
    this._closed = true;
    this._disconnectSSE();
  }

  // ── v1.1 signing internals ───────────────────────────────────────────────────

  async _sendV11(content, channel, atts) {
    const id        = randomUUID();
    const createdAt = new Date().toISOString();

    // Build the message to be signed (without sig)
    const msgForSig = {
      id,
      version:          '1.1',
      content,
      channel,
      createdAt,
      prev:             null, // server fills this; canonical bytes include null
      from_dot1:        this._dot1,
      from_ed25519_pub: this._ed25519Pub,
    };

    const sig = signMessageV11(msgForSig, atts, this._ed25519Priv);

    const payload = {
      ...msgForSig,
      sig,
      author:      this.author,
      author_name: this.author,
      attachments: atts,
    };

    const res = await this._fetch('/messages', {
      method: 'POST',
      body:   JSON.stringify(payload),
    });
    return res.message;
  }

  /** Verify a v1.1 message received from the server. Returns the msg with `verified` field added. */
  _verifyIncoming(msg) {
    if (msg.version !== '1.1' || !msg.sig || !msg.from_ed25519_pub) {
      return { ...msg, verified: false, unsigned: true };
    }
    try {
      const atts  = (msg.attachments || []).map(a => ({ ...a, content_b64: a.content_b64 || '' }));
      const check = verifyMessageV11(msg, atts);
      return { ...msg, verified: check.ok };
    } catch (_) {
      return { ...msg, verified: false };
    }
  }

  // ── internals ───────────────────────────────────────────────────────────────

  _fetch(path, opts = {}) {
    return new Promise((resolve, reject) => {
      const fullUrl = this.url + path;
      const parsed  = new URL(fullUrl);
      const lib     = parsed.protocol === 'https:' ? https : http;
      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + (parsed.search || ''),
        method:   opts.method || 'GET',
        headers:  { 'Content-Type': 'application/json' },
      };
      const req = lib.request(options, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch (e) {
            reject(new Error(`PiperClient: bad JSON from server (status ${res.statusCode})`));
          }
        });
      });
      req.on('error', reject);
      if (opts.body) req.write(opts.body);
      req.end();
    });
  }

  _connectSSE() {
    if (this._closed || this._sseReq) return;
    const chParam = encodeURIComponent(this.channel);
    const parsed  = new URL(`${this.url}/events?channel=${chParam}`);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     `/events?channel=${chParam}`,
      method:   'GET',
      headers:  { Accept: 'text/event-stream', 'Cache-Control': 'no-cache' },
    };
    const req = lib.request(options, (res) => {
      // skip history replay — only emit messages that arrive after connect
      let isReplay = true;
      let buf = '';
      const replayIds = new Set();

      // first batch of messages in history() to mark as replay
      this._fetch(`/messages?limit=500&channel=${chParam}`).then(hist => {
        if (Array.isArray(hist)) hist.forEach(m => replayIds.add(m.id));
        isReplay = false;
      }).catch(() => { isReplay = false; });

      res.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        const parts = buf.split('\n\n');
        buf = parts.pop(); // incomplete last chunk
        for (const block of parts) {
          const line = block.trim();
          if (!line.startsWith('data:')) continue;
          try {
            const raw = JSON.parse(line.slice(5).trim());
            if (replayIds.has(raw.id)) continue; // skip history replay
            // own-message filter: skip if author matches by name OR dot1
            if (!this.includeOwn) {
              if (raw.author === this.author) continue;
              if (this._dot1 && raw.from_dot1 === this._dot1) continue;
            }
            // verify v1.1 signatures client-side before delivering to handler
            const msg = this._verifyIncoming(raw);
            for (const h of this._handlers) { try { h(msg); } catch (_) {} }
          } catch (_) {}
        }
      });

      res.on('end', () => {
        this._sseReq = null;
        this._scheduleReconnect();
      });
      res.on('error', () => {
        this._sseReq = null;
        this._scheduleReconnect();
      });

      this._backoff = BACKOFF_INITIAL; // connected — reset backoff
    });

    req.on('error', () => {
      this._sseReq = null;
      this._scheduleReconnect();
    });

    req.end();
    this._sseReq = req;
  }

  _disconnectSSE() {
    if (this._retryTimer) { clearTimeout(this._retryTimer); this._retryTimer = null; }
    if (this._sseReq) {
      try { this._sseReq.destroy(); } catch (_) {}
      this._sseReq = null;
    }
  }

  _scheduleReconnect() {
    if (this._closed || this._handlers.size === 0) return;
    this._retryTimer = setTimeout(() => {
      this._retryTimer = null;
      this._connectSSE();
    }, this._backoff);
    this._backoff = Math.min(this._backoff * 2, BACKOFF_MAX);
  }
}

module.exports = { PiperClient };
