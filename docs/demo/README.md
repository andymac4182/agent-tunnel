# Demo runbook (presenter)

Status: written for task rows M6-C127 to M6-C130 on 2026-09-26. Every command
on this page was run on a Mac (Apple silicon, macOS, Docker Desktop) against
`origin/main` at `6830ba7` plus this branch. The whole sequence (`up`, `show`
for every ready feature, `down`) passed three rounds from clean with
`scripts/demo/selftest.sh 3` at `f6eef6f`. Later changes (bounded Docker
calls, identity-checked process stops, a cleanup trap in `up.sh`) must be
re-run the same way before the demo; task rows M6-C127, M6-C128 and M6-C130
stay open until then.

One command brings up a complete **local** demo on this Mac: a real
`tunnel-relay`, a real `tunnel-client` device and a throwaway Redis, wired
with synthetic credentials. Every call in the demo goes consumer → relay →
device → backend and back. Nothing bypasses the relay.

| Script | What it does |
| --- | --- |
| `scripts/demo/up.sh` | Builds the binaries if needed, generates a synthetic CA, device certificate and token issuer, starts a dedicated Redis container, provisions the catalog with the shipped `tunnel-relay` commands, starts the relay, the backends and the device. Idempotent. |
| `scripts/demo/status.sh` | Health of every part: container, processes, `/livez`, `/readyz`, device phase, service IDs. Exit 0 only when all are healthy. |
| `scripts/demo/show.sh <feature>` | The narrated demo steps for one feature (`list`, `all`, or a name). |
| `scripts/demo/down.sh` | Stops everything, removes the container, deletes the state. Idempotent. |
| `scripts/demo/token.sh <scope>` | Mints a short-lived consumer token for a demo written in another language. It refuses to print to a terminal. |
| `scripts/demo/selftest.sh [N]` | The acceptance check: the full sequence N times from clean (default 3). |

## Features

`scripts/demo/show.sh list` prints the current set. On `origin/main` today:

| Feature | Ready | What the audience sees |
| --- | --- | --- |
| `echo` | yes (also `--remote`) | An authenticated echo from the device, five timed repeats, then the relay refusing no token (`401`) and the wrong scope (`403`). |
| `http` | yes (also `--remote`) | A web app that listens only on the device's `127.0.0.1`, fetched through the relay, then the relay refusing the wrong scope (`403`) and an unlisted header (`400 HTTP_INVALID_HEAD`) before the device sees it. |
| `mcp` | yes | An MCP server on the device (the repository's synthetic fixture, over stdio), used as a remote MCP server: `initialize`, `tools/list`, `tools/call` with a marker that comes back, no token refused, session `DELETE`. |
| `fs` | TODO | Filled by the filesystem feature PR: [filesystem.md](filesystem.md). |
| `acp` | TODO | Filled by the ACP feature PR: [acp.md](acp.md). |
| `cua` | TODO | Filled by the computer-use feature PR: [cua.md](cua.md). |
| `adapters` | TODO | Filled by the adapters feature PR: [adapters.md](adapters.md). |

**About `http`.** The relay's HTTP forwarding speaks MCP and ACP profiles
only; `origin/main` has no generic-HTTP profile. So the "tiny web app"
(`scripts/demo/backends/demo-web-app.py`) speaks MCP Streamable HTTP
(`mcp-2026-07-28`, stateless) and serves its page as a tool result. Say so
if asked: the point shown is that a loopback-only app on the device is
reachable through the relay and nowhere else.

## Prerequisites (do these the day before)

1. **macOS with Docker Desktop running.** `docker info` must work. Pull the
   Redis image while the network is good: `docker pull redis:8.4.0-alpine`.
2. **Commands on `PATH`:** `docker`, `openssl`, `python3`, `curl`, `nc`,
   `uuidgen` (all standard on a Mac with the Xcode command-line tools), and
   the Rust toolchain via `rustup` (the repository pins 1.95.0).
3. **Build once.** The first `up.sh` builds `tunnel-relay`, `tunnel-client`,
   `tunnel-deadman` and `tunnel-mcp-fixture` with `cargo build --locked`. That
   took 11 minutes on a loaded machine; later runs reuse the binaries (pass
   `--rebuild` after pulling new code). To use other binaries, for example an
   unpacked release's `bin/`, set `DEMO_BIN_DIR=/path/to/bin` (it must also
   hold `tunnel-mcp-fixture` for the `mcp` feature, which releases do not ship).
4. **Free ports** `18443` (consumer HTTPS), `19443` (device WSS), `16380`
   (Redis) and `18931` (web app), all on `127.0.0.1`. Override with
   `DEMO_CONSUMER_PORT`, `DEMO_DEVICE_PORT`, `DEMO_REDIS_PORT` and
   `DEMO_WEB_PORT` if one is taken.
5. **Rehearse:** `scripts/demo/selftest.sh 1`. It must end with
   `demo-selftest ok rounds=1`.

Run everything from the repository root. The local demo writes only to
`scripts/demo/.state/` (gitignored; the location cannot be overridden) and
its own container `agentuplink-demo-redis`, which carries the label
`agentuplink.demo=1`. `down.sh` removes only a container with that label,
deletes the state directory only while it holds the marker file `up.sh`
writes, and signals a process only while its recorded start time and command
line still match. It never touches the shared test Redis: the scripts refuse
the container name `agent-tunnel-m7-isolated-20260911` and the port `63790`.
It never touches the Fly deployment. It reads `~/agentuplink-fly` only in
`--remote` mode, and never writes there.

Every Docker call is bounded: queries (`docker info`, `ps`, `inspect`) at
10 s (`DEMO_DOCKER_TIMEOUT`), `docker run` at 120 s and `docker rm` at 60 s.
A call that does not answer ends with "Docker not answering" instead of
hanging. If `up.sh` fails or is interrupted (Ctrl-C) part-way, it runs
`down.sh --keep-logs` itself.

## One-minute pre-flight (the morning of)

```text
scripts/demo/down.sh          # clean slate, safe if nothing is up
scripts/demo/up.sh            # 20 to 70 s; ends with the status table
scripts/demo/show.sh echo     # must end "echo: all steps as expected"
```

`up.sh` ends with `local demo is up in N s` and a status table in which every
line is `OK`. Measured: 22 to 67 s with binaries already built, on a machine
running several other builds; most of it is starting the Redis container and
the six catalog writes (activation, provisioning, and `add-service` plus `set-grant` for each further feature). Leave it up; `show.sh` can be run as often as you
like.

If a step is not `OK`, run `scripts/demo/down.sh --keep-logs`, look in
`scripts/demo/.state/logs/`, then `scripts/demo/up.sh` again (it tears down a
partial demo by itself).

## Order of the demo

Use a terminal with a large font; every line is short. Colours are on in a
terminal and off in a pipe (`NO_COLOR=1` turns them off).

1. **What is running** -- `scripts/demo/status.sh`. One Redis (TLS), one
   relay, one device with an active session, one backend, and the service
   IDs. Point out that the device dialled *out* to the relay; nothing listens
   on the device except the loopback web app.
2. **Echo** -- `scripts/demo/show.sh echo`. The reply is the device's canary
   (`demo-mac:`) followed by the payload, so it visibly came from the device.
   Then five timed calls (the debug build measured 228 to 412 ms each under
   load, with a new TLS handshake per call) and the two refusals.
3. **HTTP forward** -- `scripts/demo/show.sh http`. Step 0 fetches the app
   directly on loopback, as the device sees it; steps 1 and 2 reach the same
   app through the relay. The page carries a request counter, so the audience
   can see each fetch reached the app. Steps 3 and 4 are refused by the relay
   before the device is involved.
4. **MCP** -- `scripts/demo/show.sh mcp`. A stdio MCP server on the device is
   now a remote MCP server: session issued, ten tools listed, a marker sent in
   `tools/call` comes back from the device-side server, a caller without a
   token gets `401`, and `DELETE` ends the session (the device stops the
   server process).
5. **Filesystem, ACP, computer use, adapters** -- as each feature PR lands,
   `scripts/demo/show.sh <name>`; its own page in this directory has the
   talking points. Until then `show.sh list` marks them TODO and `show.sh
   <name>` exits 2 without calling anything.
6. **Optional: the live relay** -- see [Remote mode](#remote-mode-opt-in).

`scripts/demo/show.sh all` runs every ready feature in order. Each run ends
with `<feature>: all steps as expected (N ms)`; a step that did not match
prints `FAIL`, the status and at most 300 bytes of the (synthetic) body, and
`show.sh` exits 1.

Afterwards: `scripts/demo/down.sh`.

## What is and is not printed

Printed: HTTP status codes, timings, error codes, identifiers (the
device and service UUIDs), counts and synthetic markers. Never printed: a
token, a private key, a certificate, an MCP session ID, or a payload that is
not synthetic demo text. Tokens are minted in memory, handed to `curl` on
stdin so they do not appear in `ps`, and never written to disk. Bodies shown
are passed through a filter that replaces anything shaped like a JWT or a PEM
block. `selftest.sh` fails if any output contains either shape.

For a demo in another language:

```text
TOKEN=$(scripts/demo/token.sh echo:invoke)        # 300 s; add a TTL up to 3600
```

It prints to a pipe or variable only; run straight in a terminal it refuses.
The consumer URL is `https://localhost:18443` and the CA to trust is
`scripts/demo/.state/pki/server-ca.pem`; `status.sh` prints the device and
service UUIDs.

## Remote mode (opt-in)

`--remote` points `status.sh`, `show.sh` and `token.sh` at the live relay,
`https://agentuplink-relay.fly.dev`, using the issuer key and relay CA in
`~/agentuplink-fly` **read-only**. It never writes there or to Fly, and it
mints the same claims as the smoke helpers (`sub` `fly-smoke-user`, 300 s).
Identifiers default to the live smoke identity and can be overridden with
`DEMO_REMOTE_DEVICE`, `DEMO_REMOTE_ECHO_SERVICE` and
`DEMO_REMOTE_HTTP_SERVICE`, or a gitignored `scripts/demo/remote.env`.

```text
scripts/demo/up.sh --remote          # checks the material and /livez, /readyz
scripts/demo/show.sh --remote echo
scripts/demo/show.sh --remote http
```

The live relay only answers if its device is connected. Start it in another
terminal first and leave it running:

```text
tunnel-client connect --config ~/agentuplink-fly/device/client.toml --json
```

**State of the live relay when this was written (2026-09-26 00:00+10:00):**
`/livez` and `/readyz` answered `200`; the echo answered `503 DEVICE_OFFLINE`
because no device was connected, and the `http` service answered `404
NOT_FOUND` because the live relay has no `[http_forward]` profile deployed.
`show.sh` recognises both, says what to do, and skips the rest of that
feature. The live relay also answers a wrong scope with `401`, not `403`,
because its image predates M6-C53; the echo step accepts either there.
Remote mode is therefore not proven green end to end (task row M6-C129).

## Failure recovery

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Docker is not running or not answering` | Docker Desktop is stopped, or did not answer `docker info` in 10 s | Start it; wait until `docker info` answers promptly |
| `port N is in use` | Another process holds a demo port | Stop it, or set the matching `DEMO_*_PORT` |
| `cargo build failed` | Toolchain or network | Read `scripts/demo/.build.log`; `cargo build --locked` needs crates.io once |
| `up.sh` stops with 'no marker file' | A `.state` directory from a pre-fix version | Run `rm -rf scripts/demo/.state` once |
| `Docker not answering: docker run did not start agentuplink-demo-redis (status 124 ...)` | Docker Desktop did not answer in 120 s. Seen while the machine ran several other agents' container builds (load average about 150): `docker run -d` hung for over 20 minutes | Wait until `docker run --rm alpine:3 true` answers in seconds, then `up.sh`. On the presenter's own Mac, restarting Docker Desktop also works; on a shared machine it restarts everyone's containers |
| `a container named agentuplink-demo-redis exists without the agentuplink.demo=1 label` | Something else took the demo's name | `down.sh` will not remove it; rename or remove it yourself, or set `DEMO_REDIS_CONTAINER` |
| `Redis did not answer PING over TLS` | Image missing and no network, or Docker slow | `docker pull redis:8.4.0-alpine`, then `up.sh` again |
| `down.sh`: `container ... is still present after 60 s`, exit 1 | Docker Desktop is stuck removing it | Everything else is already stopped and deleted; run `down.sh` again once Docker answers |
| `relay exited during startup` | Configuration or Redis | `down.sh --keep-logs`; read `scripts/demo/.state/logs/relay.log` |
| `device exited during startup` | Credential or relay | `down.sh --keep-logs`; read `.state/logs/device.log` and `credentials.log` |
| `show.sh`: `the local demo is not healthy` | A process died | `status.sh` names it; `up.sh` rebuilds the demo |
| An echo `503 RESOURCE_EXHAUSTED` or a delayed MCP call once every 300 s | A scheduled data-socket rotation | Run the step again; `status.sh` shows the rotation count |
| `503 DEVICE_OFFLINE` (remote) | The live device is not connected | Start it (above) |
| `404 NOT_FOUND` on `http` (remote) | The live relay does not serve http-forward | Use the local demo for `http` |

## Adding a feature (for the feature PRs)

A feature is one file, `scripts/demo/features/NN-<name>.sh`. Copy
`scripts/demo/features/_template.sh`, which documents the contract, fill it
in and set `FEATURE_READY=1`. Nothing else changes: `up.sh` builds the
feature's cargo packages, adds its service and grant to the catalog
(`add-service` and `set-grant`), its export to the device profile and its
profile to the relay's `[http_forward]` table, and starts its backend;
`show.sh` runs its steps; `down.sh` stops what it started. A feature whose
`feature_service` prints nothing (the adapters demo, which only calls the
others) gets no catalog records and no export; `feature_relay_toml` adds
relay configuration tables. The stubs
`40-fs.sh`, `50-acp.sh`, `60-cua.sh` and `70-adapters.sh` are marked
`TODO(<feature> feature PR)`, and each feature branch adds its own recipe
page here: [filesystem.md](filesystem.md), [acp.md](acp.md), [cua.md](cua.md)
and [adapters.md](adapters.md). After filling one in, run
`scripts/demo/selftest.sh 3`; it runs every ready feature.
