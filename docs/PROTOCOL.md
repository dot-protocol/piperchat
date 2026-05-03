# piper-chat wire format

## message object

Every message posted via `POST /messages` or received via `GET /events` is a JSON object:

```json
{
  "id":        "<uuid-v4>",
  "content":   "<UTF-8 text, max 4096 bytes>",
  "author":    "<display name, max 64 chars>",
  "channel":   "<channel name, default 'main', max 32 chars>",
  "createdAt": "<ISO 8601 timestamp>",
  "prev":      "<16-hex-char prefix of SHA-256(JSON.stringify(previous_message)) | null>"
}
```

`prev` is null for the first message. It is not a cryptographic proof of integrity — it is a lightweight ordering hint that makes accidental reordering visible.

## endpoints

| method | path        | description                                     |
|--------|-------------|-------------------------------------------------|
| GET    | /           | chat UI (index.html)                            |
| GET    | /health     | node status JSON                                |
| GET    | /events     | SSE stream — replays history then live updates  |
| POST   | /messages   | post a message (`{content, author, channel}`)   |
| GET    | /messages   | fetch history (`?limit=N&since=<id>`)           |
| GET    | /ticket     | get iroh doc share ticket (if iroh is running)  |
| POST   | /connect    | connect to peer (`{ticket: "<iroh-ticket>"}`)   |

## iroh sync model

When iroh is available, each message is also written to the iroh document as a key-value pair:

- **key**: `message.id` (UTF-8 bytes)
- **value**: `JSON.stringify(message)` (UTF-8 bytes)
- **author**: the iroh node's default author key

iroh replicates document entries to all connected peers. The iroh document is not authoritative — the in-memory `messages` array is. iroh adds eventual-consistency sync across nodes; the SSE stream handles real-time delivery within a single node's connected browsers.

## rate limiting

- 30 messages per minute per source IP
- 4096-byte content limit
- 64-char author name limit
- Simple dedup: same author + content within 10 seconds → returns existing message, no duplicate stored

## storage

Messages are persisted to `data/messages.json` on disk (configurable via `DATA_DIR` env var). The file is written synchronously after each accepted message. On server restart, history is loaded and replayed to new SSE subscribers.

## constraints

- No authentication. Any client that can reach the HTTP server can post messages.
- No end-to-end encryption. Messages are plain text in transit and at rest.
- No message deletion. The append-only chain is intentional.
- iroh P2P connectivity depends on NAT traversal. Connections behind strict symmetric NAT may fall back to relay mode automatically via iroh's built-in relay nodes.
