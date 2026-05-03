# contributing

piper-chat is intentionally small. Before adding a feature, ask: does a stranger need this to send a message to another stranger? If no, it probably doesn't belong here.

## issues

Open a GitHub issue for bugs, questions, and feature proposals. Include:

- Node.js version (`node --version`)
- OS
- What you expected vs what happened
- Any relevant error output

## pull requests

1. Fork, create a branch.
2. Keep diffs minimal. One concern per PR.
3. No new runtime dependencies unless the feature cannot exist without them.
4. If you change the wire format, update `docs/PROTOCOL.md` in the same PR.
5. If you change an endpoint, update the endpoint table in `docs/PROTOCOL.md`.
6. Open a draft PR early if you want feedback before finishing.

## code style

- Plain Node.js CommonJS (`require`). No transpilation step.
- Standard JS formatting — no linter config is included; use whatever your editor does.
- `server.js` handles everything. Don't split into multiple files unless complexity genuinely demands it.

## code of conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).

## license

By contributing, you agree your contributions are licensed under the Apache 2.0 license included in this repository.
