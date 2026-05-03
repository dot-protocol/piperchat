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

// Optional PostHog telemetry.
// Set POSTHOG_API_KEY env to enable. No-op when unset.
// Events fired: message_posted, channel_created, key_first_seen.

const https = require('https');

const API_KEY  = process.env.POSTHOG_API_KEY || '';
const ENDPOINT = 'app.posthog.com';
const PATH     = '/capture/';

function _post(payload) {
  const body = JSON.stringify(payload);
  const req  = https.request({
    hostname: ENDPOINT,
    port: 443,
    path: PATH,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  });
  req.on('error', () => {}); // fire-and-forget
  req.write(body);
  req.end();
}

function capture(event, properties = {}) {
  if (!API_KEY) return; // no-op
  _post({
    api_key:        API_KEY,
    event,
    distinct_id:    properties.pubkey || properties.channel || 'server',
    properties:     { ...properties, $lib: 'piperchat-server' },
    timestamp:      new Date().toISOString(),
  });
}

module.exports = { capture };
