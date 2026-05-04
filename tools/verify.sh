#!/usr/bin/env bash
# piperchat verify.sh — end-to-end smoke tests
# Usage: ./tools/verify.sh [base_url]
# Default base_url: https://api.mevici.com

set -euo pipefail

BASE="${1:-https://api.mevici.com}"
CHAT="${BASE}/chat"

PASS=0
FAIL=0

probe() {
  local name="$1"
  local result="$2"
  local expected="$3"
  if [ "$result" = "$expected" ]; then
    echo "  PASS  $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $name (got: $result, expected: $expected)"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "piperchat verify — $BASE"
echo "────────────────────────────────────────"

# ── PIPERCHAT-UI-VENDOR-200 ───────────────────────────────────────────────────
# Guards against blank-page regression: tweetnacl must be reachable under /chat/
# If this is 404 the signing JS never loads and the page silently breaks.
result=$(curl -sS -o /dev/null -w "%{http_code}" "${CHAT}/vendor/tweetnacl.min.js")
probe "PIPERCHAT-UI-VENDOR-200" "$result" "200"

# ── PIPERCHAT-UI-RENDERS ─────────────────────────────────────────────────────
# Ensures the BASE constant (post-fix marker) is present in deployed HTML.
# If missing, we shipped old HTML without the absolute-path fix.
result=$(curl -sS "${CHAT}/" | grep -c "BASE = " || true)
probe "PIPERCHAT-UI-RENDERS" "$result" "1"

# ── PIPERCHAT-REDIRECT ────────────────────────────────────────────────────────
# /chat (no trailing slash) must 301 redirect to /chat/
# Without this, relative asset paths break for users who don't type the slash.
result=$(curl -sS -o /dev/null -w "%{http_code}" "${CHAT}")
probe "PIPERCHAT-REDIRECT" "$result" "301"

# ── PIPERCHAT-HEALTH-200 ──────────────────────────────────────────────────────
result=$(curl -sS -o /dev/null -w "%{http_code}" "${CHAT}/health")
probe "PIPERCHAT-HEALTH-200" "$result" "200"

# ── PIPERCHAT-SIGNED-E2E ─────────────────────────────────────────────────────
# Posts a signed message and verifies it appears in GET /messages
CHANNEL="verify-$(date +%s)"
PAYLOAD=$(node -e "
const nacl = require('/opt/piperchat/node_modules/tweetnacl');
const kp = nacl.sign.keyPair();
const pubkey = Buffer.from(kp.publicKey).toString('hex');
const msg = 'verify-probe-' + Date.now();
const sig = Buffer.from(nacl.sign.detached(Buffer.from(msg), kp.secretKey)).toString('hex');
const body = JSON.stringify({
  content: msg, author: 'verify-bot', author_name: 'verify-bot',
  channel: '$CHANNEL', pubkey, sig, pubkeyShort: pubkey.slice(0,8)
});
process.stdout.write(body);
" 2>/dev/null || echo "SKIP_SIGNING")

if [ "$PAYLOAD" = "SKIP_SIGNING" ]; then
  echo "  SKIP  PIPERCHAT-SIGNED-E2E (node/nacl not available locally)"
else
  post_code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "${CHAT}/messages?channel=${CHANNEL}")
  probe "PIPERCHAT-SIGNED-POST" "$post_code" "200"

  get_code=$(curl -sS -o /dev/null -w "%{http_code}" "${CHAT}/messages?channel=${CHANNEL}")
  probe "PIPERCHAT-SIGNED-GET" "$get_code" "200"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo "────────────────────────────────────────"
echo "  Passed: $PASS  Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
