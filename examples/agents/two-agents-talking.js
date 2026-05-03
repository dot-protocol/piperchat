// Copyright 2026 The Pied Piper Authors — Apache 2.0
// two-agents-talking: demo of two PiperClient instances in one process.
// agent-richard and agent-jared exchange facts about HTTP caching,
// then exit cleanly and print the full transcript.
'use strict';

const { PiperClient } = require('../../client');

const BASE = process.env.PORT
  ? `http://localhost:${process.env.PORT}`
  : 'http://localhost:4101';

const DELAY_MS = 600; // pause between turns so SSE has time to deliver

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── scripts ──────────────────────────────────────────────────────────────────

const RICHARD_LINES = [
  'HTTP caching starts with the Cache-Control header — max-age tells the client how many seconds to keep a response fresh.',
  'A 304 Not Modified response means the server confirmed the cached copy is still valid without resending the body.',
  'ETags are opaque tokens — the server picks the format, the client just echoes it back in If-None-Match.',
];

const JARED_LINES = [
  'Right. And stale-while-revalidate lets a client serve the stale copy immediately while fetching a fresh one in the background.',
  'Vary: Accept-Encoding is why a gzip response and a plain response can coexist in the same cache under the same URL.',
  'Cache-Control: no-store skips writing to cache entirely — useful for sensitive responses you never want persisted.',
];

// ── main ─────────────────────────────────────────────────────────────────────

async function main() {
  const transcript = [];

  const richard = new PiperClient({ url: BASE, author: 'agent-richard', channel: 'agents', includeOwn: true });
  const jared   = new PiperClient({ url: BASE, author: 'agent-jared',   channel: 'agents', includeOwn: true });

  // collect every broadcast message for the final transcript
  const collect = (msg) => {
    if (msg.channel === 'agents') {
      transcript.push({ author: msg.author, content: msg.content, time: msg.createdAt });
    }
  };
  const unsubR = richard.subscribe(collect);
  const unsubJ = jared.subscribe(collect);

  // give SSE connections a moment to establish
  await sleep(400);

  for (let i = 0; i < RICHARD_LINES.length; i++) {
    await richard.send(RICHARD_LINES[i], 'agents');
    await sleep(DELAY_MS);
    await jared.send(JARED_LINES[i], 'agents');
    await sleep(DELAY_MS);
  }

  // wait for the last SSE events to arrive
  await sleep(800);

  unsubR();
  unsubJ();
  richard.close();
  jared.close();

  // ── print transcript ─────────────────────────────────────────────────────
  console.log('\n── transcript ──────────────────────────────────────────────────\n');
  // deduplicate (subscribe fires for each client, may see same msg twice)
  const seen = new Set();
  const deduped = transcript.filter(m => {
    const key = `${m.author}|${m.content}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  for (const m of deduped) {
    const ts = new Date(m.time).toISOString().slice(11, 19);
    console.log(`[${ts}] ${m.author}: ${m.content}`);
  }
  console.log('\n── end of transcript ───────────────────────────────────────────\n');
}

main().catch(err => { console.error(err); process.exit(1); });
