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

// Ed25519 message signing and verification using tweetnacl.
// Signed message format: client sends
//   { content, channel, author_name, pubkey, signature, signed_at }
// The canonical signing string is:
//   "v1\n<pubkey>\n<channel>\n<signed_at>\n<content>"

const nacl = require('tweetnacl');

// Max clock skew allowed between client and server (ms)
const MAX_SKEW_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Build the canonical bytes that are signed/verified.
 * @param {string} pubkey    - hex-encoded public key
 * @param {string} channel   - channel name
 * @param {number} signed_at - ms epoch timestamp
 * @param {string} content   - message content
 * @returns {Uint8Array}
 */
function canonicalBytes(pubkey, channel, signed_at, content) {
  const str = `v1\n${pubkey}\n${channel}\n${signed_at}\n${content}`;
  return Buffer.from(str, 'utf8');
}

/**
 * Verify an incoming signed message body.
 *
 * @param {object} body - parsed request body
 * @param {string} body.pubkey     - hex Ed25519 public key (64 hex chars = 32 bytes)
 * @param {string} body.signature  - hex Ed25519 signature (128 hex chars = 64 bytes)
 * @param {number} body.signed_at  - ms epoch when the client signed
 * @param {string} body.channel    - channel name
 * @param {string} body.content    - message content
 *
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
function verifyMessage(body) {
  const { pubkey, signature, signed_at, channel, content } = body;

  if (
    typeof pubkey    !== 'string' || pubkey.length    !== 64 ||
    typeof signature !== 'string' || signature.length !== 128 ||
    typeof signed_at !== 'number' ||
    typeof channel   !== 'string' ||
    typeof content   !== 'string'
  ) {
    return { ok: false, reason: 'missing or malformed signing fields' };
  }

  // timestamp freshness check
  const skew = Math.abs(Date.now() - signed_at);
  if (skew > MAX_SKEW_MS) {
    return { ok: false, reason: `signed_at is ${Math.round(skew / 1000)}s off — max allowed ${MAX_SKEW_MS / 1000}s` };
  }

  let pubkeyBytes, sigBytes;
  try {
    pubkeyBytes = Buffer.from(pubkey,    'hex');
    sigBytes    = Buffer.from(signature, 'hex');
  } catch (_) {
    return { ok: false, reason: 'pubkey or signature is not valid hex' };
  }

  if (pubkeyBytes.length !== 32) return { ok: false, reason: 'pubkey must be 32 bytes (64 hex chars)' };
  if (sigBytes.length    !== 64) return { ok: false, reason: 'signature must be 64 bytes (128 hex chars)' };

  const msg = canonicalBytes(pubkey, channel, signed_at, content);

  const valid = nacl.sign.detached.verify(msg, sigBytes, pubkeyBytes);
  if (!valid) return { ok: false, reason: 'signature verification failed' };

  return { ok: true };
}

/**
 * Detect whether a request body looks like a signed post.
 * We treat it as signed if pubkey + signature fields are present.
 * @param {object} body
 */
function isSigned(body) {
  return (
    typeof body === 'object' && body !== null &&
    typeof body.pubkey    === 'string' && body.pubkey.length    === 64 &&
    typeof body.signature === 'string' && body.signature.length === 128 &&
    typeof body.signed_at === 'number'
  );
}

module.exports = { verifyMessage, isSigned, canonicalBytes };
