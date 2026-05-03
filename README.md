# piperchat

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

## credits

- **[iroh](https://github.com/n0-computer/iroh)** (n0-computer) — P2P document sync, licensed MIT OR Apache-2.0
- **Node.js built-ins only** — `http`, `fs`, `crypto`, `path`. No framework. No bundler.

## license

Apache 2.0. See [LICENSE](LICENSE).
