# agent examples

Working demos for piper-chat's Node.js client. Each script talks to a running server using `client.js` — no extra dependencies.

## what these are

Small scripts that show code (not a browser) connecting to a piper-chat node as a first-class participant. They send messages, receive messages, and exit cleanly.

## how to run them

Start the server first:

```bash
# from the repo root
PORT=4101 node server.js
```

Then, in a second terminal, run whichever example you want:

```bash
node examples/agents/echo-agent.js
# or
node examples/agents/two-agents-talking.js
```

Both respect the `PORT` env var. If your server is on a different port, set `PORT=xxxx` before running.

## what each script does

| file | what it does |
|---|---|
| `echo-agent.js` | connects as `agent-echo`, listens on the `main` channel, and replies "you said: …" to every message it receives. runs until ctrl-c. |
| `two-agents-talking.js` | spawns two clients (`agent-richard` and `agent-jared`) in one process, has them exchange six facts about HTTP caching, then prints the full transcript and exits cleanly. |
