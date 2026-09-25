# Demo: relay metrics, including the rotation-freeze hold

What this shows: a real `tunnel-relay serve` with a private `metrics_bind`
listener, a real `tunnel-client connect` device session through it, one echo
served device → relay → consumer, one refused consumer request, and a
`GET /metrics` scrape of that relay. The scrape carries the rotation-freeze
hold series (task row M6-C106) next to the M6-C24 series, with no identifier
in any label.

Everything runs locally against a disposable Redis. Nothing here touches a
deployed relay.

## 1. Prerequisites

- A disposable plaintext Redis. The examples use `redis://127.0.0.1:63790/`;
  the test gives itself a unique namespace, so a shared instance is fine.
- The repository at the branch under test, Rust 1.95.0 (pinned).

```sh
export TEST_REDIS_URL=redis://127.0.0.1:63790/
export TUNNEL_CATALOG_REDIS_URL=$TEST_REDIS_URL
cargo build --locked -p tunnel-relay -p tunnel-client --bins
export TUNNEL_CLIENT_BIN=$PWD/target/debug/tunnel-client
```

(With a custom `CARGO_TARGET_DIR`, point `TUNNEL_CLIENT_BIN` there instead.)

## 2. Run the demo

The M6-C24 process test provisions a relay configuration with
`metrics_bind` on loopback, starts `tunnel-relay serve` and
`tunnel-client connect` as separate processes, serves an echo through the
relay, sends one request for a subject that has no catalog user, and then
scrapes `/metrics`:

```sh
cargo test --locked -p tunnel-relay --test m6_provisioning_process -- \
  --ignored --nocapture --test-threads=1 m6c24_private_metrics
```

Expected: the test passes (`1 passed; ... 9 filtered out`) and prints one
line of this form. Measured at `0e592686` (log nonce
`opsfu-demo2-20260925T155735Z-12526`):

```text
m6c24-metrics ok nonce=8f82edaecd114c739a05c9bc1fa76ac2 series=27 bytes=5273 sessions=1 refusal_identity>=1 freeze_hold_series=12
```

The nonce differs per run; `series` and `bytes` change only when the metrics
set does.

`freeze_hold_series=12` is the number of rotation-freeze hold series the
scrape was required to contain (every one present; all zero here because no
data rotation froze during this short session). The test also fails if the
scrape contains the echo payload, the refused subject, either token, the
tenant, device or service ID, the Redis namespace or URL, or `127.0.0.1`,
and if the public consumer listener answers `/metrics` with anything but
`404`.

`scripts/m6-provisioning-verify.sh` runs the same test among the other M6
gates and requires that line.

## 3. What the freeze-hold series mean

On a relay you run yourself (operator guide section 3.1), set
`metrics_bind = "127.0.0.1:9464"` at the top level of the relay
configuration and scrape it:

```sh shape-only
curl -s http://127.0.0.1:9464/metrics | grep -E 'rotation_freeze|rotation_freeze_hold'
```

The series, all prefixed `tunnel_relay_`
([operator.md](../operator.md) section 5):

| Series | Meaning |
| --- | --- |
| `rotation_freeze_hold_held_total` | New consumer OPENs held at the owner during a data-rotation freeze |
| `rotation_freeze_hold_current` (gauge) | OPENs in the hold now |
| `rotation_freeze_hold_admitted_total` | Held OPENs admitted once the hold ended |
| `rotation_freeze_hold_released_total{outcome}` | Held OPENs released, by `commit`, `abort`, `recovery` or `session_loss` |
| `rotation_freeze_hold_released_with_deferred_writes_total` | Releases that found deferred writes still queued |
| `rotation_freeze_hold_refused_total{reason}` | Refused `ROTATION_FREEZE`: `after_bound` (held past the bound) or `hold_full` |
| `rotation_freeze_hold_cancelled_total` | Held OPENs whose consumer went away |
| `rotation_freeze_hold_max_wait_ms` (gauge) | Longest time any OPEN spent in the hold |
| `consumer_refusals_total{route,stage="rotation_freeze"}` | Requests this relay, as owner, answered `ROTATION_FREEZE`, by route (`echo`, `stream`, `http-forward`, `fs`) |

Check: `held_total` equals `current` plus every `released_total`,
`refused_total{reason="after_bound"}` and `cancelled_total`. A scrape where
it does not is a relay defect.

## 4. Failure recovery

| Symptom | Cause and fix |
| --- | --- |
| `requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN` or the test is skipped with `0 passed` | The test is `#[ignore]`d; pass `--ignored` and export both variables |
| `echo not served: HTTP 503` until the deadline | The device did not connect; the panic message includes its `connect` log. Check that Redis is reachable and that `TUNNEL_CLIENT_BIN` is the client built from the same tree |
| `no tunnel_relay_rotation_freeze_hold_...` | The relay binary predates M6-C106; rebuild `tunnel-relay` from this branch |
| `the scrape leaked ...` | A label or value rendered an identifier: a real defect, report it |
| A relay refuses to start with `unknown field metrics_bind` | That binary predates M6-C24; remove the key or use a newer relay |
