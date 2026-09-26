# Attributing flood interference and the over-limit throughput drop (M6-C182, M6-C183)

Status: written 2026-09-27 for task rows M6-C182 and M6-C183. The recipe
reproduces two effects. The first is a flood on one device raising another
user's latency on a different device. The second is served throughput falling
once the public listener's 64-connection limit refuses connections. For each,
it shows which process the cost lands on. Every request goes consumer → relay
→ device → relay → consumer over real TLS sockets. Nothing bypasses the relay.

The attribution the harness records, all payload-free, per load step or
fairness phase:

* `cpu_percent`: CPU of the relay, TLS forwarder, devices and driver in
  percent of one CPU. It also has the Redis server's CPU from `INFO`,
  `redis_script_calls_per_s`, `redis_script_usec_per_call`, and
  `relay_actor`, the single relay actor's timed busy wall time in percent (from
  `tunnel_relay_actor_busy_microseconds_total`; a lower bound, since only the
  actor's command branch is timed).
* `driver_loop_lag_ms`: how late a 10 ms sleep wakes on the driver's own
  asyncio loop. Any request timed on that loop waits about this long as well.
* Fairness only: `quiet_user_b_off_loop` is the same quiet user B workload,
  timed from a separate `client` process with its own event loop. It sits
  beside the in-loop `quiet_user_b`. Both of B's clients connect before the
  flood starts.
* `off_loop_clients` / `flood_processes`: each client process's own loop lag
  and CPU seconds.

## Local

```sh
cargo build --release --locked -p tunnel-relay -p tunnel-client -p tunnel-deadman -p tunnel-mcp-fixture
mkdir -p /tmp/fair-bins && cp target/release/tunnel-relay target/release/tunnel-client \
  target/release/tunnel-deadman target/release/tunnel-mcp-fixture /tmp/fair-bins/

# M6-C183: B timed on the driver loop and from its own process, same flood.
python3 scripts/m6-soak.py fairness --bin-dir /tmp/fair-bins --logs /tmp/fair-logs \
  --redis 127.0.0.1:63790 --phase-seconds 20

# The same with A's flood in two processes, honouring retry_after_ms.
python3 scripts/m6-soak.py fairness --bin-dir /tmp/fair-bins --logs /tmp/fair-logs \
  --redis 127.0.0.1:63790 --phase-seconds 20 --flood-processes 2 --honor-retry-after

# M6-C182: echo load in four generator processes, with and without back-off.
python3 scripts/m6-soak.py load --bin-dir /tmp/fair-bins --logs /tmp/fair-logs \
  --redis 127.0.0.1:63790 --kinds echo --steps 1,16,32,64,96,128 --generator-processes 4
python3 scripts/m6-soak.py load --bin-dir /tmp/fair-bins --logs /tmp/fair-logs \
  --redis 127.0.0.1:63790 --kinds echo --steps 1,16,32,64,96,128 --generator-processes 4 \
  --honor-retry-after

# M6-C182 for MCP (on the driver loop; --generator-processes applies to echo only).
python3 scripts/m6-soak.py load --bin-dir /tmp/fair-bins --logs /tmp/fair-logs \
  --redis 127.0.0.1:63790 --kinds mcp --steps 1,16,32,64,96,128 --honor-retry-after
```

Expected output: `summary.json` in each run directory. For fairness, compare
`phases["flood-quiet-on-b"].quiet_user_b.latency_ms_ok.p50` with
`quiet_user_b_off_loop` and `driver_loop_lag_ms` in the same phase. For load,
compare `steps[].throughput_ok_per_s` at 64, 96 and 128 workers with and
without `--honor-retry-after`, beside `cpu_percent`.

On a 4-vCPU hosted runner, you should see the results below (runs
36266358041, 36267864622, 36267862335, 36267311313 and 36269590574;
[soak-2026-09-27.md](../soak-2026-09-27.md) section 6):

* **Flood on the driver loop (the old setup).** In-loop B has a p50 of
  about 80 ms, off-loop B about 19 ms, and the driver loop's lag p50 is about
  38 ms. The old harness inflated B about 4×. The in-loop flood also
  throttled itself, at about 440 refusals a second.
* **`--flood-processes 2`, no back-off.** Off-loop B has a p50 of about
  90 ms against a baseline of about 5 ms. The full interference reproduces
  with B timed correctly. How it splits between the relay's refusal cost and
  host contention is not attributed.
* **`--flood-processes 2 --honor-retry-after`.** B's p50 is about 29 ms.
* **Echo load honouring `retry_after_ms`.** It holds about 1,360 -- 1,430
  OK/s from 64 to 128 workers. Without back-off it falls to about 670 --
  860 OK/s.
* **MCP load honouring `retry_after_ms`.** It holds about 1,180 -- 1,240
  OK/s. The drop needs clients that do not back off.
* **Relay actor.** Its timed busy fraction, a lower bound, is at most about
  21% in every step.

**Shared maintainer Mac.** Run each command through
`/private/tmp/claude-501/throttle/gate.sh` and discard timings from any run
whose `run.txt` load average, or whose `host_load1` in `summary.json`, exceeds
20. The shared Redis on 127.0.0.1:63790 also carries other agents' traffic,
visible as `redis_commands_per_s` in a baseline phase with no flood. While
it does, local latencies are not comparable with hosted ones.

## Hosted

```sh
gh workflow run m6-soak.yml --ref BRANCH -f experiments="load fairness" \
  -f load_args="--kinds echo --steps 1,16,32,64,96,128"
gh workflow run m6-soak.yml --ref BRANCH -f experiments="load" \
  -f load_args="--kinds echo --steps 1,16,32,64,96,128 --generator-processes 4 --honor-retry-after"
gh workflow run m6-soak.yml --ref BRANCH -f experiments="fairness" \
  -f fairness_args="--flood-processes 2 --honor-retry-after"
gh run download RUN_ID    # m6-soak-metrics-0: summary.json per experiment
```

## Failure recovery

* **`client exited N without a summary`** in `off_loop_clients` or
  `flood_processes`: the client subprocess failed before printing its summary.
  The `client-*.csv` next to `requests.csv` in the run directory holds the
  rows it recorded. Rerun the experiment.
* **Off-loop B has 0 successes, all `CONNECTION_LIMIT`**: B's clients did not
  get listener permits before the flood took all 64. The harness pre-connects
  B, so this means a pre-connection failed (30 s bound) or the relay closed
  B's idle connection. That starvation is itself the M6-C193 finding. Rerun
  to measure latency.
* **A stale namespace after an interrupted run**: every experiment deletes
  its own `tunnel-catalog:m6-03-*-<nonce>:` keys on exit, including on
  SIGTERM. After a SIGKILL, delete that prefix from the shared Redis by hand.
