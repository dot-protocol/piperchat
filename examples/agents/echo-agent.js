// Copyright 2026 The Pied Piper Authors — Apache 2.0
// echo-agent: listens on the channel and echoes back any message it receives.
'use strict';

const { PiperClient } = require('../../client');

const client = new PiperClient({
  url:    process.env.PORT ? `http://localhost:${process.env.PORT}` : 'http://localhost:4101',
  author: 'agent-echo',
  channel: 'main',
});

console.log('[echo-agent] connected — listening for messages');

client.subscribe(async (msg) => {
  console.log(`[echo-agent] received from ${msg.author}: ${msg.content}`);
  try {
    await client.send(`you said: ${msg.content}`);
  } catch (err) {
    console.error('[echo-agent] send failed:', err.message);
  }
});

// Keep alive until SIGINT
process.on('SIGINT', () => {
  console.log('\n[echo-agent] shutting down');
  client.close();
  process.exit(0);
});
