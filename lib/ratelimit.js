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

// Token-bucket rate limiter.
// Per pubkey: 30 msgs/min, burst 10.
// Fallback IP bucket: 30 msgs/min (same shape, larger window).
// Global flood guard: if total throughput exceeds 100 msgs/sec, reject with 503.

const BUCKET_CAPACITY  = 10;   // burst
const BUCKET_RATE      = 30;   // tokens added per minute
const BUCKET_REFILL_MS = 60_000 / BUCKET_RATE; // ms per token (~2000ms)

const IP_CAPACITY  = 10;
const IP_RATE      = 30;
const IP_REFILL_MS = 60_000 / IP_RATE;

const FLOOD_MAX_PER_SEC  = 100;
const FLOOD_LOCKOUT_MS   = 10_000;

// ── in-memory state ──────────────────────────────────────────────────────────
const _buckets  = new Map(); // key → { tokens, lastRefillAt }
const _ipBuckets = new Map();

let _globalCount = 0;
let _globalWindowStart = Date.now();
let _floodLockedUntil = 0;

// prune stale buckets every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of _buckets)   { if (now - b.lastRefillAt > 120_000) _buckets.delete(k); }
  for (const [k, b] of _ipBuckets) { if (now - b.lastRefillAt > 120_000) _ipBuckets.delete(k); }
}, 300_000).unref();

// ── helpers ───────────────────────────────────────────────────────────────────

function _consumeToken(map, key, capacity, refillMs) {
  const now = Date.now();
  let b = map.get(key);
  if (!b) {
    b = { tokens: capacity, lastRefillAt: now };
    map.set(key, b);
  }
  // refill
  const elapsed = now - b.lastRefillAt;
  const toAdd   = Math.floor(elapsed / refillMs);
  if (toAdd > 0) {
    b.tokens = Math.min(capacity, b.tokens + toAdd);
    b.lastRefillAt = now;
  }
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}

// ── public API ────────────────────────────────────────────────────────────────

/**
 * Check global flood guard. Returns false (reject) if system is flooded.
 */
function checkFlood() {
  const now = Date.now();
  if (now < _floodLockedUntil) return false;
  // reset window every second
  if (now - _globalWindowStart > 1000) {
    _globalCount = 0;
    _globalWindowStart = now;
  }
  _globalCount++;
  if (_globalCount > FLOOD_MAX_PER_SEC) {
    _floodLockedUntil = now + FLOOD_LOCKOUT_MS;
    return false;
  }
  return true;
}

/**
 * Check per-pubkey rate limit.
 * @param {string} pubkey hex pubkey (or any unique string key)
 * @returns {boolean} true = allowed
 */
function checkPubkey(pubkey) {
  return _consumeToken(_buckets, pubkey, BUCKET_CAPACITY, BUCKET_REFILL_MS);
}

/**
 * Check per-IP rate limit (fallback for legacy unsigned posts).
 * @param {string} ip
 * @returns {boolean} true = allowed
 */
function checkIp(ip) {
  return _consumeToken(_ipBuckets, ip, IP_CAPACITY, IP_REFILL_MS);
}

module.exports = { checkFlood, checkPubkey, checkIp };
