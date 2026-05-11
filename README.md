# piperchat

**v1.1 — DOT-native** | ed25519-signed identities, dot1 addresses, DOTpost v1.3 attachments

A minimal P2P chat node. Two browsers, one message, no server in the middle that owns your data. Each node holds its own message history. Peers sync documents directly using [iroh](https://github.com/n0-computer/iroh) — a Rust-based P2P document layer that works across NAT without a relay you don't control. When iroh is unavailable (firewalled network, CI), the server falls back to SSE relay mode and chat still works.

No accounts. No telemetry. No external services required to start.

## run it

```bash
git clone https://github.com/dot-protocol/piperchat
cd piperchat
npm install
npm start
```

Open `http://localhost:4100` in two browser tabs. Set a name, send a message. To connect a second *node* (different machine), click the **⇄** button, copy your ticket, and paste it into the other node's connect dialog.

Port defaults to `4100`. Override with `PORT=8080 npm start`.

## how it works

Each running instance is a node. Nodes exchange messages two ways:

1. **P2P (iroh)** — iroh creates a shared document between nodes. When you call `GET /ticket`, you get an opaque string that encodes your node's address and document ID. Another node calls `POST /connect` with that string, and iroh establishes a direct connection, replicating the document. No central server involved.

2. **Relay (SSE fallback)** — If iroh cannot establish a direct connection, the HTTP server itself acts as a relay: all connected browsers subscribe to `/events` (Server-Sent Events) and receive every message posted to `/messages`. This requires both browsers to reach the same host, but needs no additional infrastructure.

Messages are appended locally to `data/messages.json`. Each message records the SHA-256 prefix of the previous message, forming a lightweight hash chain.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the wire format.

## v1.1 — DOT-native

v1.1 upgrades every message to a signed, identity-bound object. The sender carries a `dot1:` address (derived from their sovereign cell) and an ed25519 keypair. Every message is signed before it hits the server; bad signatures are rejected 400. Unsigned v1.0 messages are still accepted (backwards compat) but flagged in the UI.

### what changed in v1.1

- **Sender identity:** `author` string replaced by `from_dot1` (16-hex cell address) + `from_ed25519_pub` (64-hex pubkey). The dot1 short form is shown in the UI next to each message.
- **Signatures:** Every outgoing message carries `sig` — a detached ed25519 signature over a canonical form of the message metadata + attachment manifest. The server verifies on POST; the browser verifies on SSE receive. Bad sigs → 400.
- **Attachments (DOTpost v1.3):** Messages can carry up to 32 file attachments. Each attachment has `{filename, mime_type, size_bytes, sha256, content_b64}`. The server validates structure on POST, drops invalid items. SHA-256 hashes are included in the signature so attachment content is bound to the message.
- **UI:** A key setup banner prompts you to paste your `ed25519_priv_hex` (session-only, `sessionStorage` only, never sent to server). A 📎 button lets you attach up to 4 files (≤ 1 MB each). Messages show a `✓ dot1short` badge (verified) or `? dot1short` (unverified / v1.0).

### sending a v1.1 message via curl

First build the signing input (see docs/PROTOCOL.md §Signature canonical form). Here's the quick version using the Node client:

```bash
node -e "
const { PiperClient } = require('./client');
const c = new PiperClient({
  url: 'http://localhost:4100',
  author: 'Kin-1-Piper',
  dot1: 'dot1:6d94e2c24a06486b',
  ed25519PubHex: '27307d0731ab61630777f511581d4e47cf57df9c7b1bd65e5c989888523790cd',
  ed25519PrivHex: process.env.PIPER_PRIV_HEX,
});
c.send('hello v1.1').then(r => console.log(JSON.stringify(r, null, 2)));
"
```

Set `PIPER_PRIV_HEX` to your 128-hex ed25519 private key (seed + public key concatenated). The server verifies the signature on every POST.

### pointing the Node client at a cell file

```js
const { PiperClient } = require('./client');

const c = new PiperClient({
  url:           'http://localhost:4100',
  author:        'Kin-1-Piper',
  cellPath:      '/path/to/cell_Kin-1-Piper.md', // reads dot1 + ed25519_pub from PUBKEYS section
  ed25519PrivHex: process.env.PIPER_PRIV_HEX,    // priv is never stored in the cell file
});

await c.send('hello from a cell');
```

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the full wire format.

## use it from code

any node.js process can talk to a running piper-chat node via `client.js`. no extra dependencies — it uses `http`, `https`, and the built-in fetch available in node 18+.

```js
const { PiperClient } = require('./client');

const client = new PiperClient({ url: 'http://localhost:4101', author: 'agent-richard' });

await client.send('hello from code');

const unsub = client.subscribe((msg) => {
  console.log(`[${msg.author}] ${msg.content}`);
});

const history = await client.history({ limit: 50 });

unsub();
client.close();
```

SSE subscriptions auto-reconnect with exponential backoff (1 s → 2 s → … → 30 s max). own messages are filtered from `subscribe` by default; pass `includeOwn: true` to opt in.

see [`examples/agents/`](examples/agents/) for two working demos: an echo bot and a two-agent conversation that runs end-to-end and exits cleanly.

## scale + production

### signing protocol

every message sent through the UI (or any client that wants a verified identity) is Ed25519-signed before hitting the server. the canonical signing string is:

```
v1\n<pubkey-hex>\n<channel>\n<signed_at-ms>\n<content>
```

the server verifies the signature, checks that `signed_at` is within 5 minutes of server time, and rejects on failure. unsigned posts are accepted for backwards compatibility on the `main` and `legacy` channels, but are flagged as `legacy: true` in the response. pubkeys are 64 hex chars (32 bytes); signatures are 128 hex chars (64 bytes).

the browser generates a keypair once, stores it in IndexedDB (`piperchat` → `keypair`), and reuses it across reloads. the 4-char pubkey prefix is shown next to each author name so you can visually verify who you're talking to.

### docker

```bash
docker compose up
```

data is written to a named volume (`piperchat-data`). to point at a specific directory:

```bash
DB_PATH=/your/path/piperchat.db DATA_DIR=/your/path docker compose up
```

### pm2

```bash
npm install --omit=dev
pm2 start deploy/ecosystem.config.js
pm2 save
pm2 startup
```

logs land in `./logs/`. see `deploy/ecosystem.config.js` for memory limit and restart config.

### nginx + TLS

see `deploy/nginx.conf` for a full example. the critical settings for SSE are:

```nginx
proxy_buffering    off;
proxy_cache        off;
proxy_read_timeout 24h;
```

after placing the config, run `certbot --nginx -d chat.piedpiper.fun`.

### telemetry (opt-in)

set `POSTHOG_API_KEY` in your environment to enable event tracking. when the variable is unset the telemetry module is a no-op — no bytes are sent. events: `message_posted`, `channel_created`, `key_first_seen`.

![CI](https://github.com/dot-protocol/piperchat/actions/workflows/ci.yml/badge.svg)

## credits

- **[iroh](https://github.com/n0-computer/iroh)** (n0-computer) — P2P document sync, licensed MIT OR Apache-2.0
- **[tweetnacl](https://github.com/dchest/tweetnacl-js)** (dchest) — Ed25519 signing, licensed CC0 / Public Domain
- **[better-sqlite3](https://github.com/WiseLibs/better-sqlite3)** (WiseLibs) — synchronous SQLite bindings, licensed MIT
- **Node.js built-ins only** for HTTP transport — `http`, `fs`, `crypto`, `path`. No framework. No bundler.

## license

Apache 2.0. See [LICENSE](LICENSE).
