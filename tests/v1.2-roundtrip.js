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

// v1.2-roundtrip.js — End-to-end v1.2 sealed-body round-trip test.
//
// Tests both Phase 1 (sealed body crypto) and Phase 2 (mailbox bridge logic).
// Run with: node tests/v1.2-roundtrip.js

const { randomUUID, generateKeyPairSync } = require('crypto');
const nacl = require('tweetnacl');
const {
  generateBodyKey, encryptBody, decryptBody,
  wrapBodyKey, unwrapBodyKey,
} = require('../lib/sealed-body');
const {
  isV12Envelope, signV12Envelope, verifyV12Envelope,
  validateAttachments,
} = require('../lib/crypto');

let passed = 0;
let failed = 0;

function pass(label) {
  console.log(`  PASS  ${label}`);
  passed++;
}

function fail(label, reason) {
  console.error(`  FAIL  ${label}: ${reason}`);
  failed++;
}

function assert(condition, label) {
  if (condition) pass(label);
  else { fail(label, 'assertion failed'); }
}

function assertThrows(fn, label) {
  try {
    fn();
    fail(label, 'expected throw but did not throw');
  } catch (_) {
    pass(label);
  }
}

// ── helpers: generate synthetic X25519 + Ed25519 identity ─────────────────────

function makeX25519Pair() {
  const kp = generateKeyPairSync('x25519');
  // Extract raw 32-byte keys from DER-encoded KeyObjects
  const privRaw = kp.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16);
  const pubRaw  = kp.publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
  return {
    privHex: privRaw.toString('hex'),
    pubHex:  pubRaw.toString('hex'),
  };
}

function makeEd25519Pair() {
  const kp = nacl.sign.keyPair();
  return {
    privHex: Buffer.from(kp.secretKey).toString('hex'), // 128-hex (seed+pub)
    pubHex:  Buffer.from(kp.publicKey).toString('hex'), // 64-hex
  };
}

function makeDot1(seed) {
  // Deterministic dot1 for tests using a simple approach
  const h = require('crypto').createHash('sha256').update(seed).digest('hex');
  return 'dot1:' + h.slice(0, 16);
}

// ── compose a v1.2 envelope (sender → one or more recipients) ────────────────

function composeV12Envelope(sender, recipients, content, channel = 'test-channel') {
  const bodyKey    = generateBodyKey();
  const bodyBytes  = Buffer.from(content, 'utf8');
  const cipherBody = encryptBody(bodyBytes, bodyKey);

  // Wrap body key for each recipient
  const wraps = recipients.map(r => ({
    recipient_dot1:    r.dot1,
    wrapped_body_key:  wrapBodyKey(bodyKey, sender.x25519.privHex, r.x25519.pubHex, r.dot1, sender.dot1),
  }));

  const envelope = {
    id:               randomUUID(),
    version:          '1.2',
    channel,
    createdAt:        new Date().toISOString(),
    prev:             null,
    from_dot1:        sender.dot1,
    from_ed25519_pub: sender.ed25519.pubHex,
    from_x25519_pub:  sender.x25519.pubHex,
    cipher_body:      cipherBody,
    wraps,
  };

  const atts = [];
  envelope.sig = signV12Envelope(envelope, atts, sender.ed25519.privHex);
  return envelope;
}

// ── decrypt a v1.2 envelope as a specific recipient ───────────────────────────

function openV12Envelope(envelope, recipient) {
  const myWrap = envelope.wraps.find(w => w.recipient_dot1 === recipient.dot1);
  if (!myWrap) return null; // not addressed to me

  const bodyKey   = unwrapBodyKey(
    myWrap.wrapped_body_key,
    recipient.x25519.privHex,
    envelope.from_x25519_pub,
    recipient.dot1,
    envelope.from_dot1,
  );
  const plaintext = decryptBody(envelope.cipher_body, bodyKey);
  return plaintext.toString('utf8');
}

// ── build test identities ─────────────────────────────────────────────────────

const A = {
  dot1:    makeDot1('alice'),
  ed25519: makeEd25519Pair(),
  x25519:  makeX25519Pair(),
};

const B = {
  dot1:    makeDot1('bob'),
  ed25519: makeEd25519Pair(),
  x25519:  makeX25519Pair(),
};

const C = {
  dot1:    makeDot1('carol'),
  ed25519: makeEd25519Pair(),
  x25519:  makeX25519Pair(),
};

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 1 — sealed body crypto
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n── Phase 1: sealed body crypto ──');

// 1. Basic body encrypt/decrypt
{
  const key  = generateBodyKey();
  const pt   = Buffer.from('hello v1.2 sealed world', 'utf8');
  const ct   = encryptBody(pt, key);
  const out  = decryptBody(ct, key);
  assert(out.equals(pt), 'body encrypt/decrypt round-trip');
}

// 2. Wrap/unwrap body key (A → B)
{
  const key     = generateBodyKey();
  const wrapped  = wrapBodyKey(key, A.x25519.privHex, B.x25519.pubHex, B.dot1, A.dot1);
  const recovered = unwrapBodyKey(wrapped, B.x25519.privHex, A.x25519.pubHex, B.dot1, A.dot1);
  assert(recovered.equals(key), 'wrap/unwrap A→B');
}

// 3. Compose full v1.2 envelope (A → B) and verify sig
{
  const env = composeV12Envelope(A, [B], 'secret message from A to B');
  const check = verifyV12Envelope(env, []);
  assert(check.ok, 'v1.2 envelope sig verifies');
  assert(isV12Envelope(env), 'isV12Envelope detects format');
}

// 4. A composes message, B decrypts and gets plaintext
{
  const content = 'the steaks are in the fridge';
  const env     = composeV12Envelope(A, [B], content);
  const check   = verifyV12Envelope(env, []);
  assert(check.ok, 'sig ok before decrypt');
  const recovered = openV12Envelope(env, B);
  assert(recovered === content, 'B decrypts A→B envelope correctly');
}

// 5. Corrupt cipher_body — decrypt must throw (not return garbage)
{
  const env  = composeV12Envelope(A, [B], 'tamper me');
  const myWrap = env.wraps.find(w => w.recipient_dot1 === B.dot1);
  const bodyKey = unwrapBodyKey(myWrap.wrapped_body_key, B.x25519.privHex, env.from_x25519_pub, B.dot1, A.dot1);
  const corrupt = Buffer.from(env.cipher_body, 'base64');
  corrupt[corrupt.length - 1] ^= 0xff; // flip last byte of GCM tag
  assertThrows(
    () => decryptBody(corrupt.toString('base64'), bodyKey),
    'tampered cipher_body throws on decrypt',
  );
}

// 6. Corrupt wrapped_body_key for B — unwrap must throw
{
  const env  = composeV12Envelope(A, [B], 'tamper wrap');
  const wrap = env.wraps.find(w => w.recipient_dot1 === B.dot1);
  const corruptWrap = Buffer.from(wrap.wrapped_body_key, 'base64');
  corruptWrap[corruptWrap.length - 1] ^= 0x01;
  assertThrows(
    () => unwrapBodyKey(corruptWrap.toString('base64'), B.x25519.privHex, env.from_x25519_pub, B.dot1, A.dot1),
    'tampered wrapped_body_key throws on unwrap',
  );
}

// 7. Multi-recipient: A → [B, C]. Both B and C can decrypt; A cannot (no own wrap)
{
  const content = 'group secret';
  const env     = composeV12Envelope(A, [B, C], content);
  assert(env.wraps.length === 2, 'envelope has 2 wraps for B+C');
  const bGot = openV12Envelope(env, B);
  const cGot = openV12Envelope(env, C);
  assert(bGot === content, 'B decrypts group envelope');
  assert(cGot === content, 'C decrypts group envelope');
  assert(openV12Envelope(env, A) === null, 'A finds no wrap for herself (no own wrap)');
}

// 8. B's wrap cannot be used by C (wrong info context)
{
  const env   = composeV12Envelope(A, [B, C], 'cross-recipient test');
  const bWrap = env.wraps.find(w => w.recipient_dot1 === B.dot1);
  // C tries to use B's wrap with C's own key pair — should throw
  assertThrows(
    () => unwrapBodyKey(bWrap.wrapped_body_key, C.x25519.privHex, env.from_x25519_pub, B.dot1, A.dot1),
    'B wrap + C priv key = auth failure',
  );
}

// 9. Sig tampered — verifyV12Envelope must return ok:false
{
  const env     = composeV12Envelope(A, [B], 'sig tamper test');
  const tampered = { ...env, sig: 'aa'.repeat(64) };
  const check   = verifyV12Envelope(tampered, []);
  assert(!check.ok, 'tampered sig returns ok:false');
}

// 10. Missing fields — isV12Envelope returns false
{
  assert(!isV12Envelope({}), 'empty object not v1.2');
  assert(!isV12Envelope({ version: '1.2', from_dot1: 'dot1:abcdef0123456789' }), 'partial envelope not v1.2');
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 2 — mailbox bridge logic (unit-level, without live HTTP)
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n── Phase 2: mailbox bridge logic ──');

const { pushEnvelope, pullEnvelopes, mailboxHealth } = require('../lib/mailbox-bridge');

// 11. mailboxHealth returns an object with status for a reachable endpoint.
//     Since relay.piedpiper.fun may be unreachable in test, we test the function
//     signature and that it returns a promise.
{
  const result = mailboxHealth('https://relay.piedpiper.fun');
  assert(result && typeof result.then === 'function', 'mailboxHealth returns a Promise');
}

// 12. pushEnvelope returns a Promise
{
  const env = composeV12Envelope(A, [B], 'test push');
  const result = pushEnvelope('https://relay.piedpiper.fun', B.dot1, env);
  assert(result && typeof result.then === 'function', 'pushEnvelope returns a Promise');
}

// 13. pullEnvelopes returns a Promise
{
  const result = pullEnvelopes('https://relay.piedpiper.fun', A.dot1, 0);
  assert(result && typeof result.then === 'function', 'pullEnvelopes returns a Promise');
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

console.log(`\n── Result: ${passed} PASS  ${failed} FAIL ──\n`);
if (failed > 0) process.exit(1);
