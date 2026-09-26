# Demo: a peer stream survives membership re-signs

This recipe shows the M7 cluster behaviour changed on branch `m7-membership`
(task rows M7-C80 and M7-C83; M7-C86, M7-C90 and M7-C91 are held on a draft branch). Three real relay
processes run against a local Redis. One device is owned by `relay-a` and one
public consumer WebSocket enters at `relay-c`, so every exchange goes
consumer → relay-c → peer HTTP/3 hop → relay-a → device and back. Nothing
bypasses the relay.

While that one consumer stream stays open, the control plane re-signs every
relay's membership record at a higher version for the same node and key:
twice with a gap, then three versions published back to back. Before this
branch, each re-sign cancelled the peer admission and killed the stream
(`HTTP_STREAM_INTERRUPTED`). Now the admission is re-bound to the new record,
so the same stream keeps answering.

## Prerequisites

- Rust 1.95.0 (pinned in `rust-toolchain.toml`).
- A disposable local Redis. The shared development instance is
  `redis://127.0.0.1:63790/`. The gate writes only under its own random
  namespace and deletes it afterwards.

## Run it

```sh
export TEST_REDIS_URL=redis://127.0.0.1:63790/
export TUNNEL_CATALOG_REDIS_URL=$TEST_REDIS_URL
cargo build --locked --workspace --bins
cargo run --locked -p tunnel-test-harness -- verify-m7-resign-stream
```

On a shared machine, run the last command through
`/private/tmp/claude-501/throttle/gate.sh`. The gate is timing-sensitive, and
a failure while the load average is above 20 is not evidence.

## Expected output

The last line looks like this. Counters vary, but the booleans and zeros
must not:

```text
M7 re-sign stream survival passed: relays=3 resigns=3 burst_versions=3 last_record_version=6 exchanges_after_resign=3 same_stream_survived=true membership_changed_invalidations=0 other_invalidations=0 pin_samples=… pins_ever_empty=false readiness_recovered_ms=… elapsed_ms=…
```

- `same_stream_survived=true`: the consumer stream opened before the first
  re-sign answered with the device's canary after every re-sign.
- `membership_changed_invalidations=0`: no relay cancelled any peer admission
  because of a record change. This count comes from the membership runtime's
  own invalidation dispatcher.
- `pins_ever_empty=false`: no relay's transport pin set was empty at any 5 ms
  sample in the window.
- `readiness_recovered_ms`: how long every relay took to report peer
  readiness after the back-to-back burst settled. The gate fails above 5 s.

The component tests behind the same behaviour need no Redis:

```sh
cargo test -p tunnel-relay --test m7_membership_resign --locked
```

## If it fails

- `harness startup timed out` or `cleaning production Redis catalog exceeded
  its shared deadline`: the environment, not the product. Check `uptime`,
  Redis reachability (`redis-cli -p 63790 ping`) and free disk space, then
  re-run.
- `same_stream_survived` or `membership_changed_invalidations`: a re-sign
  invalidated the admission. Look for `membership reconcile failed` warnings
  in the output. A record that changes the key, endpoint or server name, or
  shrinks the signed trust window, is still meant to invalidate.
- `pins_ever_empty`: a relay withdrew its pins during a same-key re-sign. On this branch every unready state still withdraws them (the narrowing is held as M7-C86), so this means a re-sign raced a reconcile and left a relay briefly unready. Look for `membership reconcile failed` warnings.
- A readiness timeout after the burst: rerun with `RUST_LOG=warn` and look for
  `authenticated peer readiness probe failed`.
