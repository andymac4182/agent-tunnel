# Demo recipe: soak, load, chaos and fairness (M6-03)

What it shows: a local relay and synthetic devices under steady load, a
concurrency sweep, device/relay/Redis faults and a two-user flood, with every
request going consumer -> relay -> device. Measurements and limits:
[../soak-2026-09-26.md](../soak-2026-09-26.md).

## Prerequisites

* Release binaries in one directory: `tunnel-relay`, `tunnel-client`,
  `tunnel-deadman`, `tunnel-mcp-fixture`
  (`cargo build --release --locked -p tunnel-relay -p tunnel-client -p tunnel-deadman -p tunnel-mcp-fixture --bins`).
* A plaintext Redis the harness may write a unique namespace into (default
  `127.0.0.1:63790`). The harness puts its own TLS forwarder in front of it and
  deletes its namespace on exit.
* `python3` (standard library only), `openssl`, and Docker for
  `chaos --dedicated-redis` only.

## Run

```sh
BIN=target/release LOGS=/tmp/m6-soak-logs
# A 60-second flood: shows M6-C120 (device session ends under a consumer flood).
scripts/m6-soak.py flood --bin-dir $BIN --logs $LOGS --workers 128 --seconds 60
# Chaos with the shared Redis (no Redis pause):
scripts/m6-soak.py chaos --bin-dir $BIN --logs $LOGS
# Everything, waiting for the host 1-minute load to fall below 20 first:
scripts/m6-soak-all.sh $BIN $(git rev-parse HEAD) $LOGS
```

Each run prints one line per event (`provisioned`, `device-start`, `fault`,
`progress`, ...) and ends with its `summary.json`. On a hosted runner, use
Actions -> `m6-soak` -> Run workflow.

## Expected output

* `soak`: `errors: 0`, `rotations_completed` about `duration / 300`, and one
  device session.
* `chaos`: a `faults` list with recovery times. `integrity_mismatches: 0`, and
  `mcp_backend_tool_invocations` equal to `mcp_tool_calls_ok_seen_by_consumer + 1`.
* `flood`: on `6830ba79`, the build these measurements used, `device_session_ends` is non-empty
  (`RESOURCE_EXHAUSTED`). That is defect M6-C120, not a harness fault. With the
  fix tracked in M6-C140/C141 (PR #182), expect an empty list and capacity
  refusals (`ADMISSION_LIMIT`/`STREAM_LIMIT`) instead. Compare
  `device_session_ends` with `device_exit_code: null`.

## Recovery

* The run stops early with `step failed`: read the named command's stderr
  tail. A `stage=connection_establishment` failure means Redis or the
  forwarder is not reachable.
* Interrupted runs: SIGTERM or SIGHUP to the driver stops its children and
  deletes its namespace. Each child runs in its own process group, which is
  killed as a group. On Linux, the children also get SIGTERM when the driver dies.
  After a SIGKILL of the driver on macOS, remove the strays by hand. These are
  three kinds of process, all with a path under the run directory on their
  command line:
  * `tunnel-relay serve --config <run>/work/relay.toml`
  * `tunnel-client connect --config <run>/work/device-*/client.toml`, and its
    `tunnel-mcp-fixture` children
  * the Redis TLS forwarders: `m6-soak.py forwarder --cert <run>/work/server-cert.pem ...`

  For example, `pkill -f '<run>/work/'`. Then delete the namespace's keys
  (`tunnel-catalog:<namespace>:*`) by hand, and for `chaos --dedicated-redis`
  the container labelled `m6-03-soak=<nonce>`
  (`docker rm -f $(docker ps -aq --filter label=m6-03-soak=<nonce>)`).
