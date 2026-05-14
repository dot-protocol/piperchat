# piper-chat wire format — v1.3

## Overview

piper-chat supports four wire-format versions:

| Version | Description | Status |
|---------|-------------|--------|
| `1.0` | Legacy unsigned or browser-keypair-signed messages | **Accepted on receive, deprecated on send** |
| `1.1` | DOT-native: ed25519-signed, dot1 sender identity, DOTpost v1.3 attachments | **Accepted on receive** |
| `1.2` | Sealed body: X25519 ECDH + AES-256-GCM per-message key, multi-recipient wraps | **Accepted on receive** |
| `1.3` | v1.2 envelope + optional `username` field bound to a server-side first-claim-wins registry | **Current** |

v1.0/v1.1/v1.2 messages are accepted at receive time. New outgoing messages from updated clients SHOULD be v1.2 (sealed body) when encryption is enabled, plus an optional v1.3 `username` field if the sender has claimed a username.

---

## v1.2 sealed-body envelope

A v1.2 envelope extends v1.1 with an encrypted body and per-recipient key wraps. The server stores the envelope opaquely — it never decrypts the body.

```json
{
  "id":               "<uuid-v4>",
  "version":          "1.2",
  "channel":          "<channel name, default 'main', max 32 chars>",
  "createdAt":        "<ISO 8601 timestamp>",
  "prev":             "<16-hex prev hash | null>",

  "from_dot1":        "<dot1:[0-9a-f]{16}>",
  "from_ed25519_pub": "<64-hex ed25519 public key>",
  "from_x25519_pub":  "<64-hex X25519 public key (Curve25519)>",

  "cipher_body":      "<base64: nonce(12) || AES-256-GCM ciphertext || auth-tag(16)>",

  "wraps": [
    {
      "recipient_dot1":   "<dot1:[0-9a-f]{16}>",
      "wrapped_body_key": "<base64: nonce(12) || AES-256-GCM encrypted 32-byte body key || tag(16)>"
    }
  ],

  "sig": "<128-hex ed25519 signature (covers all fields including cipher_body and wraps)>",

  "attachments": [ ... ]
}
```

**Key points:**
- `cipher_body` — the message content encrypted with AES-256-GCM using a random per-message 32-byte body key. Format: `nonce(12 bytes) || ciphertext || GCM auth tag (16 bytes)`, base64-encoded.
- `wraps` — one entry per recipient (including the sender themselves). Each entry holds the body key encrypted to that recipient's X25519 public key.
- `from_x25519_pub` — the sender's X25519 public key (Curve25519), 64 lowercase hex = 32 raw bytes. Used by recipients to derive the shared ECDH secret for unwrapping their body key copy.
- The `content` field is **absent** in v1.2 — the body key is the only way to recover the plaintext. The server never sees `content` for encrypted messages.

---

## §Sealed body: key derivation

### Body key (per-message)

A fresh 32-byte key is generated for each message:

```
body_key = random_bytes(32)
```

### Wrapping the body key for a recipient

For each recipient, the body key is wrapped using ECDH + HKDF + AES-256-GCM:

```
shared_secret = X25519(sender_x25519_priv, recipient_x25519_pub)   // Curve25519 DH

wrap_key = HKDF-SHA256(
  ikm  = shared_secret,                           // 32 bytes
  salt = "piperchat/v1.2/wrap",                   // UTF-8 bytes
  info = UTF-8(recipient_dot1 + sender_dot1),     // concatenated, no separator
  len  = 32                                        // output bytes
)

wrapped_body_key = AES-256-GCM-encrypt(
  key      = wrap_key,
  nonce    = random_bytes(12),
  plaintext = body_key
)
// serialized as nonce(12) || ciphertext(32) || tag(16) → base64
```

### Unwrapping (recipient side)

```
shared_secret = X25519(recipient_x25519_priv, from_x25519_pub)

wrap_key = HKDF-SHA256(
  ikm  = shared_secret,
  salt = "piperchat/v1.2/wrap",
  info = UTF-8(recipient_dot1 + from_dot1),
  len  = 32
)

body_key = AES-256-GCM-decrypt(wrapped_body_key, wrap_key)
content  = AES-256-GCM-decrypt(cipher_body, body_key)
```

**Authentication:** AES-256-GCM provides ciphertext integrity. Any tampering with `cipher_body` or `wrapped_body_key` will cause decryption to throw. The HKDF `info` field binds each wrap to a specific (recipient, sender) pair — cross-recipient key reuse is cryptographically rejected.

---

## §v1.2 signature canonical form

The `sig` field covers the following signed fields (same pattern as v1.1 but with additional v1.2 fields):

```
canonical_json::attachment_manifest_json
```

Signed fields (alphabetically sorted JSON): `channel`, `cipher_body`, `createdAt`, `from_dot1`, `from_ed25519_pub`, `from_x25519_pub`, `id`, `prev`, `version`, `wraps`.

`wraps` is included as a JSON array in the canonical form — any tampering with the recipient list or wrapped keys invalidates the signature.

`content` is **not** a signed field (it is absent in v1.2; the body key indirectly authenticates it via AES-256-GCM).

---

## §No forward secrecy in v1.2

v1.2 uses static X25519 public keys (one per identity, not per-message). This means:
- If a participant's X25519 private key is compromised, past sessions can be decrypted (no forward secrecy).
- Forward secrecy via ephemeral X25519 keys (X3DH / Double Ratchet) is planned for v1.3.

---

## §Sealed-sender note

v1.2 does NOT hide the sender's identity. The `from_dot1`, `from_ed25519_pub`, and `from_x25519_pub` fields are public metadata visible to the server and all recipients. This is consistent with piper-chat's public-channel design. Sealed-sender (hiding sender identity from the server) is out of scope for v1.2.

---

## §Mathpost-mailbox transport (v1.2 alternate path)

v1.2 envelopes may also be delivered via the mathpost-mailbox relay at `https://relay.piedpiper.fun` instead of the SSE relay. The mailbox relay exposes:

```
POST /mailbox/{recipientDot1}/push   — push an envelope to a recipient's inbox
GET  /mailbox/{recipientDot1}/pull?since={seq} — pull envelopes (cursor-based)
GET  /health                         — relay health check
```

When `transport = 'mailbox'` is selected in the UI, the sender pushes one copy of the envelope to each recipient's inbox directly, bypassing the server's `POST /messages` endpoint. Recipients poll `pull` every 10 seconds. The mailbox cursor (last `next_cursor` from a `pull` response) is persisted to `sessionStorage`.

---

## §Backwards compatibility (v1.0/v1.1 → v1.2)

| Direction | Behaviour |
|-----------|-----------|
| v1.0 send → v1.2 server | Accepted; stored with `unsigned_legacy: 1` |
| v1.1 send → v1.2 server | Accepted; verified and stored |
| v1.2 send → v1.2 server | Accepted; signature verified; body stored opaque |
| v1.2 envelope → v1.0/v1.1 client | Rendered as `[sealed 🔒]` (unknown `cipher_body` field ignored) |

v1.2 clients preserve full decode capability for all three versions on receive.

---

## v1.1 message object

Every message posted via `POST /messages` or received via `GET /events` is a JSON object:

```json
{
  "id":               "<uuid-v4>",
  "version":          "1.1",
  "content":          "<UTF-8 text, max 4096 bytes>",
  "channel":          "<channel name, default 'main', max 32 chars>",
  "createdAt":        "<ISO 8601 timestamp>",
  "prev":             "<16-hex prev hash | null>",

  "from_dot1":        "<dot1:[0-9a-f]{16}>",
  "from_ed25519_pub": "<64-hex ed25519 public key>",
  "sig":              "<128-hex ed25519 signature>",

  "attachments": [
    {
      "filename":    "<string, max 256 chars>",
      "mime_type":   "<string, max 128 chars>",
      "size_bytes":  "<integer>",
      "sha256":      "<64-hex SHA-256 of the raw file bytes>",
      "content_b64": "<base64-encoded file content>"
    }
  ]
}
```

- `from_dot1` — the sender's sovereign cell address. Format: `dot1:` followed by 16 lowercase hex characters.
- `from_ed25519_pub` — the sender's ed25519 public key, 64 lowercase hex characters (32 bytes).
- `sig` — detached ed25519 signature, 128 lowercase hex characters (64 bytes). Covers a canonical form of the message (see §Signature canonical form below).
- `attachments` — array of DOTpost v1.3 attachment objects. Max 32 per message. Empty array if no attachments. Server drops invalid items (field missing, out-of-range, non-base64) rather than rejecting the whole message. `content_b64` is included in the `POST /messages` response but stripped from SSE broadcasts and `GET /messages` list responses (metadata-only in lists).
- `prev` — 16-hex prefix of `SHA-256(last_message.id + last_message.content)`, or null for the first message in a channel. Not a cryptographic proof — a lightweight ordering hint.

---

## §Signature canonical form

The `sig` field covers the following bytes:

```
canonical_json_without_sig_and_content_b64 + "::" + attachment_manifest_json
```

Where:

**`canonical_json_without_sig_and_content_b64`** is `JSON.stringify` of the message object with:
- `sig` field removed entirely
- `content_b64` stripped from each attachment (only attachment metadata is signed)
- keys sorted alphabetically (A-Z)
- no extra whitespace

The signed fields are: `channel`, `content`, `createdAt`, `from_dot1`, `from_ed25519_pub`, `id`, `prev`, `version`.

**`attachment_manifest_json`** is `JSON.stringify` of the attachments array with each item reduced to `{filename, mime_type, sha256, size_bytes}` (no `content_b64`), in the same order as the `attachments` array:

```json
[{"filename":"spec.md","mime_type":"text/markdown","sha256":"abc123...","size_bytes":53083}]
```

If there are no attachments, `attachment_manifest_json` is `[]`.

### Example canonical signing input

```
{"channel":"main","content":"hello v1.1","createdAt":"2026-05-12T00:00:00.000Z","from_dot1":"dot1:6d94e2c24a06486b","from_ed25519_pub":"27307d...","id":"uuid-here","prev":null,"version":"1.1"}::[{"filename":"spec.md","mime_type":"text/markdown","sha256":"abc...","size_bytes":53083}]
```

### Verification algorithm

```
msg_bytes = UTF-8(canonical_signing_input)
sig_bytes = hex_decode(msg.sig)          // 64 bytes
pub_bytes = hex_decode(msg.from_ed25519_pub) // 32 bytes
valid     = ed25519.verify_detached(msg_bytes, sig_bytes, pub_bytes)
```

Using tweetnacl: `nacl.sign.detached.verify(msg_bytes, sig_bytes, pub_bytes)`

---

## §Sender identity binding (dot1 ↔ ed25519_pub)

`from_dot1` is defined as `sha256(secp256k1_leaf_pubkey_compressed_bytes).hex()[:16]` per the DOT protocol specification, where the leaf pubkey is derived from the sender's cell via a BIP-32 path tokenized from the canonical section of their cell file.

**v1.1 does NOT verify this binding on receipt.** Verifying it would require BIP-32 derivation in the browser, which is out of scope for this version.

**Client trust-on-first-use:** The server verifies only the ed25519 signature (that the message was signed by the key claiming to be `from_ed25519_pub`). The dot1↔pubkey binding is asserted by the sender and trusted by the recipient. Challenge-response verification of the binding is planned for v1.2.

**This is an intentional design choice, not a security hole:** piper-chat is public plaintext chat. Sender identity is intentionally visible. This is distinct from the Audit-Carol sealed-sender finding (which applies to private encrypted messaging where the sender identity must be hidden). In piper-chat, the sender's address and pubkey are part of the public message — there is no anonymity set to protect, and no need to hide sender identity inside an encrypted envelope.

---

## §Backwards compatibility (v1.0 → v1.1)

- **Receive:** Server accepts v1.0 messages (no `from_dot1`, no `sig`, plain `author` string). They are stored with `unsigned_legacy: 1` and surfaced via SSE with `unsigned: true` in the public message object. The UI shows a warning badge.
- **Send:** New messages from updated clients MUST be v1.1 (signed). v1.0 unsigned sends are logged to telemetry (`unsigned_message_posted`) and accepted only for backwards compat during the transition window. The transition window closes with v1.2.
- **Field presence:** v1.0 clients receiving v1.1 messages will ignore unknown fields (`from_dot1`, `from_ed25519_pub`, `sig`, `attachments`) — JSON forwards-compat by design.

---

## v1.0 (legacy) message object

```json
{
  "id":        "<uuid-v4>",
  "content":   "<UTF-8 text, max 4096 bytes>",
  "author":    "<display name, max 64 chars>",
  "channel":   "<channel name, default 'main', max 32 chars>",
  "createdAt": "<ISO 8601 timestamp>",
  "prev":      "<16-hex-char SHA-256 prefix | null>"
}
```

v1.0 signing (if present):
- `pubkey` — 64-hex ed25519 public key
- `signature` — 128-hex ed25519 signature
- `signed_at` — ms epoch timestamp

v1.0 canonical signing string: `"v1\n<pubkey>\n<channel>\n<signed_at>\n<content>"`

---

## endpoints

| method | path        | description                                                    |
|--------|-------------|----------------------------------------------------------------|
| GET    | /           | chat UI (index.html)                                           |
| GET    | /health     | node status JSON (`protocol_version: "1.2"`, `protocol_versions_supported: ["1.0","1.1","1.2"]`) |
| GET    | /events     | SSE stream — replays history then live updates (`?channel=X`) |
| POST   | /messages   | post a message (v1.0, v1.1, or v1.2 body)                    |
| GET    | /messages   | fetch history (`?channel=X&limit=N&since=<ISO>`)              |
| GET    | /channels   | list all channels                                              |
| GET    | /ticket     | get iroh doc share ticket (if iroh is running)                 |
| POST   | /connect    | connect to peer (`{ticket: "<iroh-ticket>"}`)                  |

---

## iroh sync model

When iroh is available, each message is also written to the iroh document as a key-value pair:

- **key**: `message.id` (UTF-8 bytes)
- **value**: `JSON.stringify(message)` (UTF-8 bytes)

iroh replicates document entries to all connected peers. iroh adds eventual-consistency sync across nodes; SSE handles real-time delivery within a node's connected clients.

---

## rate limiting

- 30 signed messages per minute per public key (v1.1: per ed25519 pubkey; v1.0: per pubkey field)
- 30 messages per minute per source IP (unsigned legacy posts)
- Global flood guard: 100 messages/sec server-wide → 503
- 4096-byte content limit
- 64-char author name limit
- Dedup: same pubkey + content within 10 seconds in the same channel → returns existing message

---

## storage

Messages are persisted to a SQLite database at `data/piperchat.db` (configurable via `DATA_DIR` and `DB_PATH` env vars). Legacy JSON migration from `data/messages.json` is performed automatically on first start if the database is empty.

v1.1-specific columns added to the `messages` table:
- `from_dot1 TEXT` — sender's dot1 address
- `from_ed25519_pub TEXT` — sender's ed25519 public key
- `sig TEXT` — detached signature (v1.1)
- `signed INTEGER DEFAULT 0` — 1 if v1.1 signed
- `unsigned_legacy INTEGER DEFAULT 0` — 1 if no signature (v1.0 unsigned)
- `attachments_json TEXT` — JSON-serialised attachments array (full, including content_b64)

v1.2-specific columns (added in v1.2.0 via `ALTER TABLE` on first start):
- `encrypted INTEGER DEFAULT 0` — 1 if the message body is sealed (v1.2)
- `from_x25519_pub TEXT` — sender's X25519 public key (v1.2 only)
- `cipher_body TEXT` — base64 AES-256-GCM encrypted body (v1.2 only)
- `wraps_json TEXT` — JSON array of `{recipient_dot1, wrapped_body_key}` entries (v1.2 only)

---

## constraints

- When `_encryptEnabled = false` in the browser, messages are sent as v1.1 (plaintext + ed25519 signed). Plaintext messages are visible to the server.
- When `_encryptEnabled = true`, messages are sent as v1.2 (sealed body). The server stores the ciphertext opaquely and cannot read the content.
- X25519 and ed25519 private keys are stored only in `sessionStorage` — never in `localStorage`, never sent to the server.
- **No forward secrecy in v1.2.** A static X25519 key per identity means past sessions are not protected against future key compromise.
- Sender identity (`from_dot1`, `from_x25519_pub`, `from_ed25519_pub`) is public metadata in v1.2 — the server and all recipients see who sent the message. Sealed-sender (hiding the sender) is out of scope for this version.
- iroh P2P connectivity depends on NAT traversal. Behind strict symmetric NAT, falls back to relay mode.
- No message deletion. The append-only chain is intentional.

---

## v1.3 username layer (current)

v1.3 adds an optional `username` field to the v1.1/v1.2 message envelope, plus a server-side first-claim-wins registry. The crypto layer is unchanged from v1.2 — usernames are purely a human-readable alias bound to a dot1 identity.

### Envelope addition

Any v1.1 or v1.2 envelope MAY include:

```
"username": "alice"            // optional, lowercase, /^[a-z0-9_-]{3,32}$/
```

If present, the server verifies the username is claimed by the sender's `from_dot1` before accepting the message. Mismatch returns `400 username_mismatch`. Unclaimed name returns `400 claim_first`.

### Claim registry

Usernames are claimed first-wins via `POST /usernames/claim`:

```
POST /usernames/claim
{
  "username":    "alice",                                   // /^[a-z0-9_-]{3,32}$/
  "dot1":        "dot1:0123456789abcdef",                   // /^dot1:[0-9a-f]{16}$/
  "ed25519_pub": "<64 hex chars — 32-byte ed25519 verify key>",
  "sig":         "<128 hex chars — ed25519 detached sig>"
}
```

The signed bytes are the literal UTF-8 string:

```
claim:<username>:<dot1>
```

(Example: `claim:alice:dot1:0123456789abcdef`.) No canonical-JSON canonicalisation required — the claim payload is a single fixed string, easy to reproduce in any client without a JSON canonicaliser. The signature is verified with `nacl.sign.detached.verify(claimBytes, sigBytes, pubBytes)`.

Server validates:
- Username regex
- `dot1` matches `dot1:[0-9a-f]{16}`
- `ed25519_pub` is 64 hex chars
- `sig` is 128 hex chars
- Signature verifies over `claim:<username>:<dot1>`
- No prior claim exists for that username (first-wins; subsequent claims for the same name return `409 username taken` with `{claimed_by, claimed_at}`)

On success the record is inserted into the `usernames` SQLite table with `(username PRIMARY KEY, dot1, claimed_at, ed25519_pub)`. `claimed_at` is set by the server (unix seconds), not by the client. The claim is permanent — no `release` operation exists in v1.3. (Recoverable identity is deferred to v1.4 — see roadmap.)

**Note on dot1↔pubkey binding**: v1.3 does not verify that `ed25519_pub` actually derives `dot1`. The username is bound to whichever `dot1` was first to submit a valid signature over the claim string. Clients SHOULD use a `dot1` derived from their `ed25519_pub`, but the server does not enforce this. Tightening to "ed25519_pub MUST derive dot1" is part of v1.4 challenge-response binding work.

### Resolution

`GET /usernames/:name` returns `{username, dot1, ed25519_pub, claimed_at}` or 404.
`GET /usernames/by-dot1/:dot1` returns the claimed username for a given identity, or 404.

### Client behaviour

Updated clients:
- Render `@<username>` in place of the truncated `from_dot1` for any message carrying a `username` field that resolves to the claimed dot1
- Show a "claim a username" banner on identity setup
- Persist the claimed username in `localStorage` under key `piper-claimed-username`
- Maintain a per-pubkey contacts registry (favourites) for friction-free contact recall

### Backwards compatibility

A v1.3 envelope is structurally a v1.2 envelope with an extra optional field. Servers that don't know v1.3 ignore the `username` field and store the v1.2 envelope unchanged. Older clients render the message normally with the dot1-derived display name.

---

## v1.4 roadmap

- Forward secrecy via ephemeral X25519 keys (X3DH session setup / Double Ratchet per conversation)
- Sealed-sender: hide `from_dot1` and sender pubkeys inside the encrypted body (currently sender identity is in clear)
- Challenge-response dot1↔pubkey binding verification (closes the TOFU gap)
- DiffBundle outer envelope (BLAKE3 ancestry + four-vector continuous diff)
- Username recovery / rotation primitive (currently usernames are permanently bound to the first dot1 that claimed them)
