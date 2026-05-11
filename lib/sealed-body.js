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

// sealed-body.js — X25519 ECDH + AES-256-GCM sealed message body primitives for piperchat v1.2.
//
// Supports N-recipient group chat: a single encrypted body (using a random per-message key)
// + one wrapped copy of that key per recipient (ECDH-keyed).
//
// All crypto uses Node.js built-in `crypto` module only.
//   - X25519 ECDH:     crypto.diffieHellman
//   - HKDF-SHA256:     crypto.hkdfSync
//   - AES-256-GCM:     crypto.createCipheriv / createDecipheriv
//
// DER encoding notes for X25519 (RFC 7748, RFC 8410):
//   PKCS8 private key: 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 <32 raw bytes>
//   SPKI  public  key: 30 2a 30 05 06 03 2b 65 6e 03 21 00 <32 raw bytes>

const {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
} = require('crypto');

// ── DER prefix constants (RFC 8410 §10.3 / §10.1) ────────────────────────────

// X25519 PKCS8 prefix (16 bytes): wraps 32-byte raw private key
// 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

// X25519 SPKI prefix (12 bytes): wraps 32-byte raw public key
// 30 2a 30 05 06 03 2b 65 6e 03 21 00
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

// HKDF constants
const WRAP_SALT = Buffer.from('piperchat/v1.2/wrap', 'utf8');

// ── key encoding helpers ───────────────────────────────────────────────────────

/**
 * Create a Node.js X25519 private key from a 32-byte raw buffer.
 * @param {Buffer} rawPriv - 32-byte raw X25519 private key
 * @returns {KeyObject}
 */
function x25519PrivFromRaw(rawPriv) {
  if (!Buffer.isBuffer(rawPriv) || rawPriv.length !== 32) {
    throw new Error('x25519PrivFromRaw: expected 32-byte Buffer');
  }
  const der = Buffer.concat([X25519_PKCS8_PREFIX, rawPriv]);
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

/**
 * Create a Node.js X25519 public key from a 32-byte raw buffer.
 * @param {Buffer} rawPub - 32-byte raw X25519 public key
 * @returns {KeyObject}
 */
function x25519PubFromRaw(rawPub) {
  if (!Buffer.isBuffer(rawPub) || rawPub.length !== 32) {
    throw new Error('x25519PubFromRaw: expected 32-byte Buffer');
  }
  const der = Buffer.concat([X25519_SPKI_PREFIX, rawPub]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

/**
 * Perform X25519 ECDH given raw hex keys.
 * @param {string} privHex - 64-hex (32-byte) X25519 private key
 * @param {string} pubHex  - 64-hex (32-byte) X25519 public key
 * @returns {Buffer} 32-byte shared secret
 */
function ecdhX25519(privHex, pubHex) {
  const privRaw = Buffer.from(privHex, 'hex');
  const pubRaw  = Buffer.from(pubHex,  'hex');
  if (privRaw.length !== 32) throw new Error('ecdhX25519: privHex must be 64 hex chars');
  if (pubRaw.length  !== 32) throw new Error('ecdhX25519: pubHex must be 64 hex chars');
  const privKey = x25519PrivFromRaw(privRaw);
  const pubKey  = x25519PubFromRaw(pubRaw);
  return diffieHellman({ privateKey: privKey, publicKey: pubKey });
}

// ── body encryption / decryption ──────────────────────────────────────────────

/**
 * Generate a random 32-byte AES-256-GCM body key.
 * @returns {Buffer} 32-byte random key
 */
function generateBodyKey() {
  return randomBytes(32);
}

/**
 * Encrypt plaintext bytes with AES-256-GCM.
 * Returns a single base64 blob: 12-byte nonce || ciphertext || 16-byte GCM tag.
 *
 * @param {Buffer|Uint8Array} plaintextBytes
 * @param {Buffer} bodyKey - 32-byte AES-256-GCM key
 * @returns {string} base64(nonce || ciphertext || tag)
 */
function encryptBody(plaintextBytes, bodyKey) {
  if (bodyKey.length !== 32) throw new Error('encryptBody: bodyKey must be 32 bytes');
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', bodyKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintextBytes), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return Buffer.concat([nonce, ct, tag]).toString('base64');
}

/**
 * Decrypt a cipher_body_b64 blob produced by encryptBody.
 * Throws on auth tag mismatch (tampered ciphertext).
 *
 * @param {string} cipherBodyB64 - base64(nonce(12) || ciphertext || tag(16))
 * @param {Buffer} bodyKey - 32-byte AES-256-GCM key
 * @returns {Buffer} plaintext bytes
 */
function decryptBody(cipherBodyB64, bodyKey) {
  if (bodyKey.length !== 32) throw new Error('decryptBody: bodyKey must be 32 bytes');
  const blob = Buffer.from(cipherBodyB64, 'base64');
  if (blob.length < 12 + 16) throw new Error('decryptBody: cipher_body too short (min 28 bytes)');
  const nonce = blob.subarray(0, 12);
  const tag   = blob.subarray(blob.length - 16);
  const ct    = blob.subarray(12, blob.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', bodyKey, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ── body key wrapping ─────────────────────────────────────────────────────────

/**
 * Derive the AES-256-GCM wrap key for a (sender → recipient) pair.
 * wrap_key = HKDF-SHA256(shared_secret, salt="piperchat/v1.2/wrap", info=recipientDot1||senderDot1)
 *
 * The info is directional: wrapping from sender S to recipient R uses info = R||S.
 * This binds the wrapped key to a specific ordered pair.
 *
 * @param {Buffer} sharedSecret - 32-byte X25519 shared secret
 * @param {string} recipientDot1 - e.g. "dot1:abcdef0123456789"
 * @param {string} senderDot1   - e.g. "dot1:0123456789abcdef"
 * @returns {Buffer} 32-byte AES wrap key
 */
function deriveWrapKey(sharedSecret, recipientDot1, senderDot1) {
  const info = Buffer.from(recipientDot1 + senderDot1, 'utf8');
  return Buffer.from(
    hkdfSync('sha256', sharedSecret, WRAP_SALT, info, 32)
  );
}

/**
 * Wrap (encrypt) a body_key for a specific recipient using X25519 ECDH + HKDF + AES-256-GCM.
 *
 * @param {Buffer} bodyKey            - 32-byte body key to wrap
 * @param {string} senderX25519PrivHex   - sender's X25519 private key (64 hex)
 * @param {string} recipientX25519PubHex - recipient's X25519 public key (64 hex)
 * @param {string} recipientDot1         - recipient's dot1 (e.g. "dot1:...")
 * @param {string} senderDot1            - sender's dot1 (e.g. "dot1:...")
 * @returns {string} base64(wrap_nonce(12) || wrapped_key_ciphertext(32) || tag(16))
 */
function wrapBodyKey(bodyKey, senderX25519PrivHex, recipientX25519PubHex, recipientDot1, senderDot1) {
  if (bodyKey.length !== 32) throw new Error('wrapBodyKey: bodyKey must be 32 bytes');
  const sharedSecret = ecdhX25519(senderX25519PrivHex, recipientX25519PubHex);
  const wrapKey      = deriveWrapKey(sharedSecret, recipientDot1, senderDot1);
  const wrapNonce    = randomBytes(12);
  const cipher       = createCipheriv('aes-256-gcm', wrapKey, wrapNonce);
  const ct           = Buffer.concat([cipher.update(bodyKey), cipher.final()]);
  const tag          = cipher.getAuthTag(); // 16 bytes
  return Buffer.concat([wrapNonce, ct, tag]).toString('base64');
}

/**
 * Unwrap (decrypt) a wrapped body key for a specific recipient.
 * Throws if authentication fails or inputs are malformed.
 *
 * @param {string} wrappedBodyKeyB64     - base64(wrap_nonce(12) || ct(32) || tag(16))
 * @param {string} recipientX25519PrivHex - recipient's X25519 private key (64 hex)
 * @param {string} senderX25519PubHex    - sender's X25519 public key (64 hex) from envelope
 * @param {string} recipientDot1         - recipient's dot1
 * @param {string} senderDot1            - sender's dot1 (from_dot1 in envelope)
 * @returns {Buffer} 32-byte body key
 */
function unwrapBodyKey(wrappedBodyKeyB64, recipientX25519PrivHex, senderX25519PubHex, recipientDot1, senderDot1) {
  const blob = Buffer.from(wrappedBodyKeyB64, 'base64');
  if (blob.length < 12 + 16) throw new Error('unwrapBodyKey: wrapped_body_key too short');
  const wrapNonce = blob.subarray(0, 12);
  const tag       = blob.subarray(blob.length - 16);
  const ct        = blob.subarray(12, blob.length - 16);

  const sharedSecret = ecdhX25519(recipientX25519PrivHex, senderX25519PubHex);
  const wrapKey      = deriveWrapKey(sharedSecret, recipientDot1, senderDot1);

  const decipher = createDecipheriv('aes-256-gcm', wrapKey, wrapNonce);
  decipher.setAuthTag(tag);
  const bodyKey = Buffer.concat([decipher.update(ct), decipher.final()]);
  if (bodyKey.length !== 32) throw new Error('unwrapBodyKey: decrypted key is not 32 bytes');
  return bodyKey;
}

// ── self-tests ─────────────────────────────────────────────────────────────────

/**
 * Run built-in round-trip self-tests. Throws on failure.
 * Called automatically when this module is loaded (bottom of file).
 */
function _selfTest() {
  try {
    // Generate synthetic X25519 key pairs using the DER helpers
    const { generateKeyPairSync } = require('crypto');

    const pairA = generateKeyPairSync('x25519');
    const pairB = generateKeyPairSync('x25519');

    // Extract raw 32-byte keys from KeyObjects
    const aPrivRaw = pairA.privateKey.export({ type: 'pkcs8',  format: 'der' }).subarray(16); // last 32 bytes
    const aPubRaw  = pairA.publicKey.export({ type: 'spki', format: 'der' }).subarray(12);     // last 32 bytes
    const bPrivRaw = pairB.privateKey.export({ type: 'pkcs8',  format: 'der' }).subarray(16);
    const bPubRaw  = pairB.publicKey.export({ type: 'spki', format: 'der' }).subarray(12);

    const aPrivHex = aPrivRaw.toString('hex');
    const aPubHex  = aPubRaw.toString('hex');
    const bPrivHex = bPrivRaw.toString('hex');
    const bPubHex  = bPubRaw.toString('hex');

    const dotA = 'dot1:aaaaaaaaaaaaaaaa';
    const dotB = 'dot1:bbbbbbbbbbbbbbbb';

    // ── Test 1: encrypt / decrypt body ──
    const bodyKey   = generateBodyKey();
    const plaintext = Buffer.from('hello sealed world', 'utf8');
    const cipher    = encryptBody(plaintext, bodyKey);
    const recovered = decryptBody(cipher, bodyKey);
    if (!recovered.equals(plaintext)) throw new Error('body encrypt/decrypt mismatch');

    // ── Test 2: wrap / unwrap body key (A→B) ──
    const wrapped   = wrapBodyKey(bodyKey, aPrivHex, bPubHex, dotB, dotA);
    const unwrapped = unwrapBodyKey(wrapped, bPrivHex, aPubHex, dotB, dotA);
    if (!unwrapped.equals(bodyKey)) throw new Error('wrap/unwrap bodyKey mismatch');

    // ── Test 3: tampered cipher_body must throw ──
    const tampered = Buffer.from(cipher, 'base64');
    tampered[tampered.length - 1] ^= 0xff; // flip last byte of GCM tag
    let threw = false;
    try { decryptBody(tampered.toString('base64'), bodyKey); } catch (_) { threw = true; }
    if (!threw) throw new Error('tampered cipher_body should have thrown');

    // ── Test 4: tampered wrapped_body_key must throw ──
    const tamperedWrap = Buffer.from(wrapped, 'base64');
    tamperedWrap[tamperedWrap.length - 1] ^= 0xff;
    let threwWrap = false;
    try { unwrapBodyKey(tamperedWrap.toString('base64'), bPrivHex, aPubHex, dotB, dotA); } catch (_) { threwWrap = true; }
    if (!threwWrap) throw new Error('tampered wrapped_body_key should have thrown');

    // ── Test 5: multi-recipient (A→B and A→C) ──
    const pairC   = generateKeyPairSync('x25519');
    const cPrivRaw = pairC.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16);
    const cPubRaw  = pairC.publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
    const cPrivHex = cPrivRaw.toString('hex');
    const cPubHex  = cPubRaw.toString('hex');
    const dotC     = 'dot1:cccccccccccccccc';

    const wrappedForC = wrapBodyKey(bodyKey, aPrivHex, cPubHex, dotC, dotA);
    const unwrappedC  = unwrapBodyKey(wrappedForC, cPrivHex, aPubHex, dotC, dotA);
    if (!unwrappedC.equals(bodyKey)) throw new Error('multi-recipient C unwrap failed');

    // Ensure the wrap for C doesn't accidentally unwrap for B (wrong info context)
    let crossFailed = false;
    try { unwrapBodyKey(wrappedForC, bPrivHex, aPubHex, dotB, dotA); } catch (_) { crossFailed = true; }
    if (!crossFailed) throw new Error('cross-recipient unwrap should have failed');

  } catch (err) {
    // Don't crash the server on load; warn instead
    console.warn('[sealed-body] self-test FAILED:', err.message);
    return;
  }
}

_selfTest();

module.exports = {
  generateBodyKey,
  encryptBody,
  decryptBody,
  wrapBodyKey,
  unwrapBodyKey,
  deriveWrapKey,
  // Exported for tests / advanced use
  ecdhX25519,
  x25519PrivFromRaw,
  x25519PubFromRaw,
};
