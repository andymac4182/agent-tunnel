# Demo: the unary echo and the connector's OPEN journal through a local relay

This recipe shows the finite (unary) echo running through a real local relay
and a real `connect`. The relay is `tunnel-relay serve` and the device is
`tunnel-client connect`, and every request goes device → relay → consumer.
It covers the task rows this branch changed:

- the connector's OPEN journal is reclaimed, so one device session serves
  far more requests than its 128 retained entries (M7-C82, M7-C92);
- an echo in flight at a data rotation neither kills the session nor passes
  the frozen fence (M7-C93);
- an echo that ends without completing is still reclaimed and never fails
  the session (M7-C94);
- a connector whose retention is exhausted ends the session with a typed,
  retryable cause instead of refusing every request (M7-C95).

Everything uses synthetic identities, a throwaway namespace and loopback
ports. Nothing reaches a deployed relay.

## Prerequisites

- The Rust toolchain pinned in `rust-toolchain.toml`.
- A disposable Redis. This repository's local setup uses Docker on
  `127.0.0.1:63790`; each run creates and deletes its own namespace.

```sh
export TEST_REDIS_URL=redis://127.0.0.1:63790/
export TUNNEL_CATALOG_REDIS_URL=$TEST_REDIS_URL
export CARGO_TARGET_DIR="$PWD/target"
cargo build --locked --workspace --bins
export TUNNEL_CLIENT_BIN="$CARGO_TARGET_DIR/debug/tunnel-client"
```

## 1. More than twice the retention through one session, across rotations

This gate provisions a fresh namespace with the shipped commands
(`activate-first-incarnation`, `provision-catalog`) and starts `serve` with a
3-second rotation interval. It starts `connect --json` with a synthetic device
credential. It then sends one warm-up echo and 300 more, with bodies of 0,
17, 4 KiB and 64 KiB bytes, through the relay's public
`POST /v1/devices/<device>/services/<service>/echo`. It keeps going until two
data rotations have completed.

```sh
cargo test --locked -p tunnel-relay --test m6_provisioning_process -- \
  --ignored --exact m7c92_sequential_unary_echoes_outlive_the_connector_open_retention \
  --nocapture
```

Expected output, one line (the counts vary by run):

```
m7c92-echo ok nonce=<nonce> namespace=<ns> echoes=3xx required=300 sessions=1 rotations=2 freeze_refusals=<n> retention=128 elapsed_ms=<ms>
```

`sessions=1` is the point. Before M7-C92 request 129 of every session failed
with `503 DEVICE_REJECTED` because the connector's journal was full.

## 2. Echoes in flight across rotations

```sh
cargo test --locked -p tunnel-relay --test m6_provisioning_process -- \
  --ignored --exact m7c93_unary_echoes_in_flight_cross_data_rotations --nocapture
```

Expected output: `m7c93-rotation ok ... sessions=1 rotations=2 ...`.

## 3. The whole shipped-binary suite

`scripts/m6-provisioning-verify.sh` runs both gates above with the rest of
the provisioning suite. It builds both binaries into `$CARGO_TARGET_DIR`
first. It exits 1 unless every gate printed its own `ok` line.

```sh
sh scripts/m6-provisioning-verify.sh
```

## 4. The exits that are not completion (M7-C94) and exhaustion (M7-C95)

A consumer that goes away, a connector RESET, an authorization that fails
before dispatch, and each of those inside a rotation freeze are driven
through the relay actor. Every one must be acknowledged and forgotten with
the session still up:

```sh
cargo test --locked -p tunnel-relay --lib -- unary_echo
```

A connector whose owner never forgets fills its journal and must then give
the session up with `OpenRetentionFull`. This test runs on the real session
loop, over WebSockets:

```sh
cargo test --locked -p tunnel-client --lib -- \
  an_owner_that_never_forgets_makes_the_session_give_up_with_a_typed_cause
```

When this happens to a real `connect --json`, it prints the typed end
`"code":"RESOURCE_EXHAUSTED"` with `"retryable":true`. With reconnect
enabled, which is the default, it then starts a fresh session with an empty
journal.

## Failure recovery

- `step warm-up: device not serving`: the relay or `connect` did not come
  up. The panic message includes the `connect --json` events and the tail of
  both logs. Check that Redis answers `PING` on the URL above.
- `HTTP 503 ... RESOURCE_EXHAUSTED ... not_dispatched` more than a few times
  in a row: the relay refuses a request during a rotation freeze, and the
  gates retry that up to a bound. If it repeats past the bound, the rotation
  did not finish. Keep the logs by setting `M6C21_KEEP_WORKDIR=1` and read
  the relay's stderr.
- A gate that fails while `uptime` shows a load average far above the core
  count is not evidence. Re-run it on a quiet machine.
- Every run uses a fresh namespace and deletes its work directory. To start
  over, run the same command again.
