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

// mailbox-bridge.js — HTTP client for the mathpost-mailbox relay at relay.piedpiper.fun.
//
// The mailbox relay exposes:
//   POST /mailbox/{dot1}/push   → push an envelope to dot1's inbox
//   GET  /mailbox/{dot1}/pull   → pull envelopes for dot1 (cursor-based)
//   GET  /health                → relay health check
//
// All HTTP done with Node built-ins (http/https modules). No new npm deps.

const http  = require('http');
const https = require('https');

const DEFAULT_MAILBOX_BASE = 'https://relay.piedpiper.fun';
const REQUEST_TIMEOUT_MS   = 15_000;

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function _httpRequest(method, url, body = null) {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(url);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + (parsed.search || ''),
      method,
      headers: {
        'Content-Type': 'application/json',
        'Accept':       'application/json',
      },
      timeout: REQUEST_TIMEOUT_MS,
    };

    const req = lib.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json;
        try { json = JSON.parse(raw); } catch (_) { json = { raw }; }
        resolve({ status: res.statusCode, body: json });
      });
      res.on('error', reject);
    });

    req.on('timeout', () => { req.destroy(new Error('mailbox-bridge: request timed out')); });
    req.on('error', reject);

    if (body !== null) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── public API ────────────────────────────────────────────────────────────────

/**
 * Push a v1.2 envelope to a recipient's mailbox.
 *
 * POST {mailboxBase}/mailbox/{recipientDot1}/push
 *
 * @param {string} mailboxBase   - e.g. "https://relay.piedpiper.fun"
 * @param {string} recipientDot1 - e.g. "dot1:abcdef0123456789"
 * @param {object} envelope      - v1.2 envelope object
 * @returns {Promise<{status: number, body: object}>}
 */
function pushEnvelope(mailboxBase, recipientDot1, envelope) {
  const base = (mailboxBase || DEFAULT_MAILBOX_BASE).replace(/\/$/, '');
  const url  = `${base}/mailbox/${encodeURIComponent(recipientDot1)}/push`;
  return _httpRequest('POST', url, envelope);
}

/**
 * Pull envelopes from the mailbox for myDot1, starting after sinceSeq.
 *
 * GET {mailboxBase}/mailbox/{myDot1}/pull?since={sinceSeq}
 *
 * @param {string} mailboxBase - e.g. "https://relay.piedpiper.fun"
 * @param {string} myDot1      - own dot1 address
 * @param {number} sinceSeq    - cursor: fetch envelopes with seq > sinceSeq (default 0)
 * @returns {Promise<{status: number, body: {envelopes: Array, next_cursor: number}}>}
 */
function pullEnvelopes(mailboxBase, myDot1, sinceSeq = 0) {
  const base = (mailboxBase || DEFAULT_MAILBOX_BASE).replace(/\/$/, '');
  const url  = `${base}/mailbox/${encodeURIComponent(myDot1)}/pull?since=${sinceSeq}`;
  return _httpRequest('GET', url);
}

/**
 * GET {mailboxBase}/health — relay health check.
 *
 * @param {string} mailboxBase - e.g. "https://relay.piedpiper.fun"
 * @returns {Promise<{status: number, body: object}>}
 */
function mailboxHealth(mailboxBase) {
  const base = (mailboxBase || DEFAULT_MAILBOX_BASE).replace(/\/$/, '');
  return _httpRequest('GET', `${base}/health`);
}

module.exports = {
  pushEnvelope,
  pullEnvelopes,
  mailboxHealth,
  DEFAULT_MAILBOX_BASE,
};
