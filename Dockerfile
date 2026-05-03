# Copyright 2026 The Pied Piper Authors — Apache 2.0
# Multi-stage build: installs native deps (better-sqlite3) in builder stage
# then copies only what's needed into a slim runtime image.

# ── builder ───────────────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

# ── runtime ───────────────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime

# create a non-root user
RUN addgroup -S pipergroup && adduser -S piperuser -G pipergroup

WORKDIR /app

# copy app code
COPY --from=builder /app/node_modules ./node_modules
COPY server.js client.js ./
COPY lib/ ./lib/
COPY public/ ./public/

# data volume will be mounted here
RUN mkdir -p /data && chown piperuser:pipergroup /data

USER piperuser

ENV PORT=4100
ENV DATA_DIR=/data

EXPOSE 4100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4100/health', r => { if (r.statusCode !== 200) process.exit(1); }).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
