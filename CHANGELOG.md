<!-- Copyright 2026 The Pied Piper Authors. Apache-2.0 license. -->

# Changelog

All notable changes to piper-chat are documented here.
Format: Keep a Changelog (https://keepachangelog.com/en/1.1.0/).
Versioning: Semantic Versioning (https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] — 2026-05-12

### Added — sealed body (X25519 + AES-256-GCM)

- **`lib/sealed-body.js`** — core sealed-body crypto for Node.js:
  - `generateBodyKey()` — random 32-byte body key
  - `encryptBody(plaintext, bodyKey)` — AES-256-GCM, returns `nonce(12)||ct||tag(16)` as base64
  - `decryptBody(cipherB64, bodyKey)` — AES-256-GCM decrypt; throws on tag mismatch
  - `wrapBodyKey(bodyKey, senderX25519Priv, recipientX25519Pub, recipientDot1, senderDot1)` — X25519 ECDH + HKDF-SHA256 + AES-256-GCM
  - `unwrapBodyKey(wrappedB64, recipientX25519Priv, senderX25519Pub, recipientDot1, senderDot1)` — reverse; throws on auth failure
  - HKDF constants: salt `"piperchat/v1.2/wrap"`, info `recipientDot1 + senderDot1`
  - DER prefix constants for X25519 raw key extraction (PKCS8 16-byte prefix, SPKI 12-byte prefix)

- **`lib/crypto.js`** — v1.2 additions:
  - `isV12Envelope(env)` — structural check for v1.2 shape
  - `signV12Envelope(env, atts, ed25519PrivHex)` — ed25519 sign covering all v1.2 fields including `cipher_body` and `wraps`
  - `verifyV12Envelope(env, atts)` — returns `{ok, reason}`
  - `validateAttachments(atts)` — validation helper

- **`lib/mailbox-bridge.js`** — HTTP client for the mathpost-mailbox relay:
  - `pushEnvelope(mailboxBase, recipientDot1, envelope)` — POST to recipient inbox
  - `pullEnvelopes(mailboxBase, myDot1, sinceSeq)` — cursor-based GET
  - `mailboxHealth(mailboxBase)` — relay health check
  - Default relay: `https://relay.piedpiper.fun`
  - Node built-ins only (no new npm deps)

- **`db.js`** — v1.2 schema additions via `ALTER TABLE IF NOT EXISTS`:
  - `encrypted INTEGER DEFAULT 0`
  - `from_x25519_pub TEXT`
  - `cipher_body TEXT`
  - `wraps_json TEXT`

- **`server.js`** — v1.2 receive path:
  - Accepts v1.2 envelopes at `POST /messages`: validates shape, verifies ed25519 sig via `verifyV12Envelope`, stores ciphertext opaquely (server never decrypts)
  - `toPublic()` returns full v1.2 shape: `from_x25519_pub`, `cipher_body`, `wraps[]`
  - `/health` now returns `version: "1.2.0"`, `protocol_version: "1.2"`, `protocol_versions_supported: ["1.0","1.1","1.2"]`

- **`client.js`** — v1.2 additions:
  - `canEncryptV12` getter
  - `addRoomRecipient(channel, {dot1, x25519PubHex})` / `removeRoomRecipient(channel, dot1)`
  - `sendEncrypted(content, channel, atts)` — compose + sign + POST v1.2 envelope; always adds self-wrap
  - `sendViaMailbox(content, channel, mailboxBase)` — push to each recipient's mailbox inbox
  - `pullFromMailbox(mailboxBase)` — pull, decrypt, emit; advances cursor per dot1
  - `_decryptIncomingV12(envelope)` — verify sig, find own wrap, unwrap body key, decrypt

- **`public/index.html`** — browser UI:
  - x25519 private key input in key banner; public key derived via `nacl.scalarMult.base()`
  - Full browser v1.2 crypto suite: `generateBodyKey`, `aesGcmEncrypt/Decrypt`, `hkdfSha256`, `x25519SharedSecret`, `wrapBodyKeyBrowser`, `unwrapBodyKeyBrowser`, `buildV12SigningInput`, `signV12EnvelopeBrowser`, `verifyV12EnvelopeBrowser`, `composeV12Envelope`
  - Transport toggle — SSE relay (default) or mathpost-mailbox (10s poll, cursor in sessionStorage)
  - Room recipients panel per channel: add/remove `{dot1, x25519PubHex}` entries; persisted to sessionStorage
  - Encrypt toggle button 🔓/🔒; when enabled, `sendMsg` uses `composeV12Envelope`
  - `renderMsg`: v1.2 messages show `[sealed 🔒]` placeholder; async in-place decryption updates content and badge from 🔒 to 🔓 on success

- **`tests/v1.2-roundtrip.js`** — 19-assertion end-to-end test:
  - Phase 1 (16 assertions): sealed body crypto — encrypt/decrypt, wrap/unwrap, multi-recipient, tamper detection
  - Phase 2 (3 assertions): mailbox bridge API surface — Promise returns for push/pull/health

### Changed

- `package.json`: version bumped `1.1.0 → 1.2.0`
- `docs/PROTOCOL.md`: full v1.2 spec — sealed body shape, HKDF constants, signing canonical form, backward-compat table, sealed-sender note, no-forward-secrecy note, mailbox transport, storage schema additions

### Backwards compatible

- v1.0 and v1.1 receive paths fully preserved
- v1.0/v1.1 clients receiving v1.2 messages render cipher_body as unknown field (ignored)

---

## [1.1.0] — 2026-05-06

### Added — DOT-native identity

- Ed25519 signing on all outgoing messages (`from_dot1`, `from_ed25519_pub`, `sig`)
- Browser-side ed25519 keypair stored in sessionStorage (never in localStorage or sent to server)
- DOTpost v1.3 attachment support: up to 32 attachments per message, SHA-256 authenticated
- `lib/crypto.js`: v1.1 canonical bytes, `signV11Message`, `verifyV11Message`
- `client.js`: cell file parsing, `canSign` getter, `send()` signs v1.1 envelopes when cell key is set
- Rate limiting: 30 signed msgs/min per pubkey, 30/min per IP, 100/sec global flood guard
- Per-message dedup: same pubkey + content within 10s in same channel returns existing message

### Changed

- `GET /health` returns `protocol_version: "1.1"`

---

## [1.0.0] — 2026-04-20

### Added — initial release

- SQLite-backed message storage with SSE real-time broadcast
- Multi-channel support with hash-based URL routing (`#/r/<channel>`)
- iroh P2P document sync (optional; relay-only fallback)
- Browser keypair (Ed25519 via TweetNaCl, IndexedDB-persisted)
- Peer connect modal with iroh ticket exchange
- Docker + docker-compose deployment
