# Demo: a connection over the listener limit gets a 503, not a reset

Task row M6-C153 (fix for M6-C143). Every request goes
consumer -> relay -> device over the real local relay.

## What it shows

Each public listener serves at most `listener_max_connections` connections
(default 64). Before the fix, a connection over that limit was dropped before
TLS and the client saw a connection reset, the same as for a crashed relay. In
a 128-worker flood, 64 workers were reset on every attempt (about 120,000
`CONN_ConnectionResetError` per 60 s run). After the fix, the relay answers
such a connection and then closes it cleanly:

```
HTTP/1.1 503 Service Unavailable
retry-after: 1
connection: close
{"code":"CONNECTION_LIMIT","execution":"not_dispatched",
 "message":"relay listener connection limit reached",
 "retryable":true,"retry_after_ms":1000}
```

For the design and the reasons for choosing it, see
[runtime.md](../runtime.md#connections-over-the-limit-m6-c153).

## Run it

You need a Redis at `127.0.0.1:63790` (the harness uses a unique namespace
and deletes its keys), Python 3 and release binaries.

```sh
cargo build --release --locked --workspace --bins
python3 scripts/m6-soak.py flood --bin-dir target/release --logs /tmp/cap-demo \
  --workers 128 --seconds 60 --bin-head "$(git rev-parse HEAD)"
```

The harness sets up a relay, one device and one user with the shipped
commands. It then runs 128 closed-loop keep-alive echo workers for 60 s,
followed by 10 probe echoes. The workers retry at once and ignore
`Retry-After`, so this is a worst case.

Deterministic check with no relay (real TCP and TLS, limit + 1 connections):

```sh
cargo test --locked -p tunnel-transport --test m6_listener_capacity
```

## Expected output

In `/tmp/cap-demo/flood-*/summary.json`:

* `flood.errors_by_code` has only `CONNECTION_LIMIT/not_dispatched` and
  `RESOURCE_EXHAUSTED/not_dispatched`, with no `CONN_*` entry. Before the fix
  it had about 120,000 `CONN_ConnectionResetError`.
* `device_session_ends` is `[]` and `after` shows 10 of 10 answered 200.

In `requests.csv`, 64 workers hold the 64 served keep-alive connections and
get 200 or `RESOURCE_EXHAUSTED`. The other 64 get `CONNECTION_LIMIT` on each
attempt. That is the documented outcome while the served connections stay
open: the limit is per connection, not per request.

The harness runs the relay with `RUST_LOG=warn`. At the default level, the
relay also logs `refusing connection over the listener connection limit`
(`phase=listener_capacity`), rate limited per listener.

## If it fails

* `CONN_ConnectionResetError` entries: check that `--bin-dir` points at
  binaries built from this branch (`tunnel-relay --version`). If so, the
  kernel listen backlog may have overflowed (`sysctl kern.ipc.somaxconn` or
  `net.core.somaxconn`). Record the run directory on row M6-C153 and do not
  re-run for a green result.
* `DEVICE_OFFLINE` from the start: the device never came up. Read
  `device-a-1.stderr.log` and `relay-1.log` in the run directory.
* To tune the limits, set `listener_max_connections` (`1..=4096`) or
  `listener_refusal_margin` (`0..=256`) at the top level of the relay
  config. A margin of `0` does no TLS work over the limit. Excess connections
  then wait in the backlog with no answer.
