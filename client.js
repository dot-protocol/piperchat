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
// Zero dependencies. Node 18+ built-ins only.

const http  = require('http');
const https = require('https');

const DEFAULT_URL     = 'http://localhost:4101';
const DEFAULT_CHANNEL = 'main';
const BACKOFF_INITIAL = 1_000;
const BACKOFF_MAX     = 30_000;

class PiperClient {
  /**
   * @param {object}  opts
   * @param {string}  opts.author          - Required. Display name for this client.
   * @param {string}  [opts.url]           - Base URL of the piper-chat server.
   * @param {string}  [opts.channel]       - Default channel for send().
   * @param {boolean} [opts.includeOwn]    - If true, subscribe() also fires for own messages.
   */
  constructor(opts = {}) {
    if (!opts.author) throw new Error('PiperClient: opts.author is required');
    this.author     = opts.author;
    this.url        = (opts.url || DEFAULT_URL).replace(/\/$/, '');
    this.channel    = opts.channel || DEFAULT_CHANNEL;
    this.includeOwn = Boolean(opts.includeOwn);

    this._handlers   = new Set();   // subscribe() callbacks
    this._sseReq     = null;        // active http.ClientRequest
    this._closed     = false;
    this._backoff    = BACKOFF_INITIAL;
    this._retryTimer = null;
  }

  // ── public API ──────────────────────────────────────────────────────────────

  /** Send a message. Returns the stored message object from the server. */
  async send(content, channel) {
    const body = JSON.stringify({
      content,
      author:  this.author,
      channel: channel || this.channel,
    });
    const res = await this._fetch('/messages', { method: 'POST', body });
    return res.message;
  }

  /**
   * Subscribe to incoming messages via SSE.
   * Calls handler(msg) for each new message.
   * By default, skips messages from this client's own author name.
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
    const parsed = new URL(this.url + '/events');
    const lib    = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     '/events',
      method:   'GET',
      headers:  { Accept: 'text/event-stream', 'Cache-Control': 'no-cache' },
    };
    const req = lib.request(options, (res) => {
      // skip history replay — only emit messages that arrive after connect
      let isReplay = true;
      let buf = '';
      const replayIds = new Set();

      // first batch of messages in history() to mark as replay
      this._fetch('/messages?limit=500').then(hist => {
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
            const msg = JSON.parse(line.slice(5).trim());
            if (replayIds.has(msg.id)) continue; // skip history replay
            if (!this.includeOwn && msg.author === this.author) continue;
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
