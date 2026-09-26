# Request latency with TCP_NODELAY (M6-C124)

Status: written 2026-09-26 for task row M6-C124. Shows serial request
latency through a real local relay and device, before and after the relay
set `TCP_NODELAY`. Every request goes consumer → relay → device → relay →
consumer over real TLS sockets.

**Where the difference shows.** On Linux the unfixed build answers one
serial echo in about 42 ms (Nagle's algorithm waiting for Linux's 40 ms
delayed ACK); the fixed build answers in under 2 ms. On macOS the unfixed
build does not show the 40 ms step, so a Mac demo shows the same numbers for
both builds. Use a Linux host or the hosted workflow for the comparison.

## Local (any host)

```sh
# Build the product binaries once per build to compare.
cargo build --release --locked -p tunnel-relay -p tunnel-client -p tunnel-mcp-fixture
mkdir -p /tmp/nodelay-bins && cp target/release/tunnel-relay target/release/tunnel-client \
  target/release/tunnel-mcp-fixture /tmp/nodelay-bins/

# Serial echo latency: one worker, 25 s (about 500 -- 10,000 requests).
# Needs a disposable plaintext Redis; the harness uses and deletes its own namespace.
python3 scripts/m6-soak.py load --bin-dir /tmp/nodelay-bins --logs /tmp/nodelay-logs \
  --redis 127.0.0.1:63790 --steps 1 --step-seconds 25 --kinds echo

# Bulk: 64 KiB echo payloads, 1 and 8 workers.
python3 scripts/m6-soak.py load --bin-dir /tmp/nodelay-bins --logs /tmp/nodelay-logs \
  --redis 127.0.0.1:63790 --steps 1,8 --step-seconds 20 --kinds echo --payload 65536
```

Expected output: one `load-step-done` line per step with `ok_per_s` and
`p99`, then the run's `summary.json` (p50, p95, p99 under
`steps[].latency_ms_ok`). On a Linux host with the fix, step 1 p50 is a few
milliseconds; without it, about 42 ms.

On the shared maintainer Mac, run the commands through
`/private/tmp/claude-501/throttle/gate.sh` and discard any run whose
`host_load1` in `summary.json` exceeds 20.

## Hosted (Linux, the evidence of record)

Actions → `m6-soak` → Run workflow, on the branch to measure:

* `experiments`: `load`
* `load_args`: empty for the standard 1 -- 128 worker steps, or
  `--payload 65536 --steps 1,2,4,8 --step-seconds 30 --kinds echo` for bulk.

The artifact `m6-soak-metrics-0` holds `summary.json` and `requests.csv`.
The runs of record are 36217619255 (main) and 36217617027 (fix) for latency,
and 36218643621 and 36218641914 for bulk; see
[soak-2026-09-26.md](../soak-2026-09-26.md#update-tcp_nodelay-m6-c124).

## Failure recovery

* `activate-first-incarnation` fails at `connection_establishment`: the
  `--redis` address is wrong or Redis is down. Check it with `redis-cli -p
  PORT ping`.
* Refusals `RESOURCE_EXHAUSTED`/not_dispatched from 2 workers upward on the
  fixed build are the per-device echo ceiling of task row M6-C149, not a
  failure of this change.
* An interrupted run leaves its namespace in Redis; the next run uses a new
  one. The harness removes its processes by process group on exit.
