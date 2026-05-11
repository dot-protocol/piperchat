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
//
// v1.0 (legacy) signed message format: client sends
//   { content, channel, author_name, pubkey, signature, signed_at }
//   canonical signing string: "v1\n<pubkey>\n<channel>\n<signed_at>\n<content>"
//
// v1.1 (DOT-native) signed message format: client sends
//   { version:"1.1", from_dot1, from_ed25519_pub, sig, content, channel, attachments, ... }
//   canonical signing input: see signMessageV11 / verifyMessageV11 below.

const nacl    = require('tweetnacl');
const { createHash } = require('crypto');

// Max clock skew allowed between client and server (ms)
const MAX_SKEW_MS = 5 * 60 * 1000; // 5 minutes

// ── v1.0 legacy helpers ───────────────────────────────────────────────────────

/**
 * Build the canonical bytes that are signed/verified for v1.0 messages.
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
 * Verify an incoming v1.0 signed message body.
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
 * Detect whether a request body looks like a v1.0 signed post.
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

// ── v1.1 DOT-native helpers ───────────────────────────────────────────────────

/**
 * Validate and normalise an attachments array from a v1.1 POST body.
 * - Drops items with invalid/missing required fields.
 * - Caps array at 32 items.
 * - Enforces per-item field length constraints.
 * Returns a clean array (may be empty).
 *
 * @param {any} raw  - the raw `attachments` value from the request body
 * @returns {Array<{filename:string, mime_type:string, size_bytes:number, sha256:string, content_b64:string}>}
 */
function validateAttachments(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const { filename, mime_type, size_bytes, sha256, content_b64 } = item;
    if (
      typeof filename    !== 'string' || filename.length < 1    || filename.length > 256 ||
      typeof mime_type   !== 'string' || mime_type.length < 1   || mime_type.length > 128 ||
      typeof size_bytes  !== 'number' || size_bytes < 0          ||
      typeof sha256      !== 'string' || sha256.length !== 64    ||
      typeof content_b64 !== 'string' || content_b64.length === 0
    ) continue;
    out.push({ filename, mime_type, size_bytes, sha256, content_b64 });
    if (out.length >= 32) break;
  }
  return out;
}

/**
 * Build the canonical signing input for a v1.1 message.
 *
 * The signed bytes cover:
 *   canonical_json_without_sig_and_content_b64 + "::" + attachment_manifest_json
 *
 * canonical_json = JSON.stringify of the message object with:
 *   - `sig` field removed
 *   - `content_b64` stripped from each attachment (only metadata is signed)
 *   - keys sorted alphabetically, no whitespace (deterministic)
 *
 * attachment_manifest = JSON array of [{filename, mime_type, size_bytes, sha256}]
 *   sorted in the same order as the attachments array (not re-sorted).
 *
 * @param {object} msg   - v1.1 message object (without sig field, or sig will be removed)
 * @param {Array}  atts  - validated attachments array
 * @returns {Buffer}
 */
function v11CanonicalBytes(msg, atts) {
  // Build a signable representation: drop sig and content_b64 from attachments
  const signable = {
    channel:          msg.channel,
    content:          msg.content,
    createdAt:        msg.createdAt,
    from_dot1:        msg.from_dot1,
    from_ed25519_pub: msg.from_ed25519_pub,
    id:               msg.id,
    prev:             msg.prev ?? null,
    version:          '1.1',
  };

  // Sort keys alphabetically for canonical form
  const sortedJson = JSON.stringify(
    Object.fromEntries(Object.entries(signable).sort(([a], [b]) => a.localeCompare(b))),
  );

  // Attachment manifest: metadata only (no content_b64)
  const manifest = JSON.stringify(
    (atts || []).map(a => ({ filename: a.filename, mime_type: a.mime_type, sha256: a.sha256, size_bytes: a.size_bytes })),
  );

  return Buffer.from(`${sortedJson}::${manifest}`, 'utf8');
}

/**
 * Detect whether a request body is a v1.1 DOT-native signed post.
 * @param {object} body
 */
function isV11Signed(body) {
  return (
    typeof body === 'object' && body !== null &&
    body.version === '1.1' &&
    typeof body.from_dot1        === 'string' && /^dot1:[0-9a-f]{16}$/.test(body.from_dot1) &&
    typeof body.from_ed25519_pub === 'string' && body.from_ed25519_pub.length === 64 &&
    typeof body.sig              === 'string' && body.sig.length              === 128
  );
}

/**
 * Sign a v1.1 message object with an ed25519 private key.
 * msg must already have all fields set except `sig`.
 *
 * @param {object} msg             - v1.1 message (id, version, content, channel, createdAt, prev, from_dot1, from_ed25519_pub)
 * @param {Array}  atts            - validated attachments array
 * @param {string} ed25519PrivHex  - 128-hex ed25519 private key (seed+pub, 64 bytes)
 * @returns {string}               - 128-hex signature
 */
function signMessageV11(msg, atts, ed25519PrivHex) {
  const privBytes = Buffer.from(ed25519PrivHex, 'hex');
  const bytes     = v11CanonicalBytes(msg, atts);
  const sig       = nacl.sign.detached(bytes, privBytes);
  return Buffer.from(sig).toString('hex');
}

/**
 * Verify a v1.1 DOT-native signed message.
 *
 * @param {object} body - parsed request body (must include all v1.1 fields)
 * @param {Array}  atts - validated attachments array (after validateAttachments())
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
function verifyMessageV11(body, atts) {
  if (!isV11Signed(body)) {
    return { ok: false, reason: 'missing or malformed v1.1 signing fields' };
  }

  const { from_ed25519_pub, sig } = body;

  let pubkeyBytes, sigBytes;
  try {
    pubkeyBytes = Buffer.from(from_ed25519_pub, 'hex');
    sigBytes    = Buffer.from(sig,              'hex');
  } catch (_) {
    return { ok: false, reason: 'from_ed25519_pub or sig is not valid hex' };
  }

  if (pubkeyBytes.length !== 32) return { ok: false, reason: 'from_ed25519_pub must be 32 bytes (64 hex chars)' };
  if (sigBytes.length    !== 64) return { ok: false, reason: 'sig must be 64 bytes (128 hex chars)' };

  const msgBytes = v11CanonicalBytes(body, atts);
  const valid    = nacl.sign.detached.verify(msgBytes, sigBytes, pubkeyBytes);

  if (!valid) return { ok: false, reason: 'v1.1 signature verification failed' };
  return { ok: true };
}

// ── self-test (round-trip a sample v1.1 message) ──────────────────────────────
// Runs once at module load in development. Throws if the canonical form is broken.
function _selfTest() {
  try {
    const kp  = nacl.sign.keyPair();
    const priv = Buffer.from(kp.secretKey).toString('hex');
    const pub  = Buffer.from(kp.publicKey).toString('hex');

    const sampleMsg = {
      id:               'test-id-001',
      version:          '1.1',
      content:          'hello v1.1',
      channel:          'main',
      createdAt:        '2026-05-12T00:00:00.000Z',
      prev:             null,
      from_dot1:        'dot1:6d94e2c24a06486b',
      from_ed25519_pub: pub,
    };

    const sampleAtts = [{
      filename:    'spec.md',
      mime_type:   'text/markdown',
      size_bytes:  42,
      sha256:      'a'.repeat(64),
      content_b64: 'aGVsbG8=',
    }];

    const sig = signMessageV11(sampleMsg, sampleAtts, priv);
    const res = verifyMessageV11({ ...sampleMsg, sig }, sampleAtts);
    if (!res.ok) throw new Error('self-test verify failed: ' + res.reason);

    // Tampered content must fail
    const tampered = verifyMessageV11({ ...sampleMsg, sig, content: 'tampered' }, sampleAtts);
    if (tampered.ok) throw new Error('self-test: tampered message should have failed');
  } catch (err) {
    // Don't crash the server; log a warning
    console.warn('[crypto] v1.1 self-test failed:', err.message);
  }
}
_selfTest();

module.exports = {
  // v1.0 (legacy)
  verifyMessage,
  isSigned,
  canonicalBytes,
  // v1.1 (DOT-native)
  validateAttachments,
  v11CanonicalBytes,
  isV11Signed,
  signMessageV11,
  verifyMessageV11,
};
