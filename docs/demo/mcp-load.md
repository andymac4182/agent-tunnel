# Demo: MCP refusals under load and while the device is offline

This recipe shows the two answers that task rows M6-C144 and M6-C145 fix. It
builds on the MCP demo in [mcp.md](mcp.md) and on the M6-03 soak harness.

| State | Before | Now |
| --- | --- | --- |
| Authorized MCP request, device offline | `404 NOT_FOUND` (reads as "no such service") | `503 DEVICE_OFFLINE`, `execution: not_dispatched`, as echo answers |
| Export at `max_children` (default 8) | `503` + JSON-RPC `-32603` (internal error) | `503` + JSON-RPC `-32050`, `data: {retryable: true, retryAfterMs: 1000, execution: not_dispatched}` |

Every request below goes consumer → relay → device. Nothing bypasses the relay.
The data is synthetic.

## 1. The deterministic checks (no Redis, about a minute)

```sh
export CARGO_TARGET_DIR=/private/tmp/$USER-mcp-load-target
cargo test --locked -p tunnel-relay --lib offline_refusal_tests
cargo test --locked -p tunnel-mcp-fixture --test capacity_refusal
```

Expected: `2 passed` for each. The relay test sends an echo and an MCP
`initialize` through the real consumer router to a device that has no session,
and requires both to be `503 DEVICE_OFFLINE`/`not_dispatched`. It also checks
that a caller without a grant gets the same answer for the real service as for
an invented one. The export test opens eight sessions at once, which are all
admitted. It then requires the ninth to get the `-32050` refusal, and requires
a retry after one `DELETE` to be admitted.

## 2. The capacity refusal through a real relay (shared Redis, about 3 minutes)

This uses the soak harness (`scripts/m6-soak.py`) and binaries built from this
checkout. It uses its own Redis namespace on 127.0.0.1:63790 and deletes it on
exit.

Since M6-C146, the harness shares at most `--mcp-sessions` (default 8, the
stdio export's default `max_children`) MCP sessions among a step's workers.
It `DELETE`s every session it opened when the step or the warm-up ends. So the
default run fits the export. To see the refusal, ask for one session more than
the export allows:

```sh
cargo build --release --locked -p tunnel-relay -p tunnel-client -p tunnel-deadman -p tunnel-mcp-fixture
mkdir -p /private/tmp/$USER-bins && cp $CARGO_TARGET_DIR/release/{tunnel-relay,tunnel-client,tunnel-deadman,tunnel-mcp-fixture} /private/tmp/$USER-bins/
python3 scripts/m6-soak.py load --bin-dir /private/tmp/$USER-bins \
  --logs /private/tmp/$USER-soak-logs --kinds mcp --steps 16 --mcp-sessions 9 --step-seconds 15
```

Expected (measured 2026-09-26 on branch `fix-soak-mcp`, debug binaries, nonce
`663FBF12-B807-4D5C-9CEB-85ADEBD8BA2B`): one line like

```
load-step-done {"kind": "mcp", "concurrency": 16, "ok_per_s": 386.8, ..., "errors": {"-32050": 451}}
```

Eight sessions fill the eight slots. The ninth `initialize` is refused with
`-32050` on every attempt, never `-32603`, so the one worker bound to it is
refused and the other fifteen succeed. The step's `mcp_sessions` summary shows
`opened: 8, deleted: 8`. Without `--mcp-sessions 9`, `--steps 8,16` has no
errors (nonce `3277A374-D6C4-4D96-9A7B-95B4F61D2DED`). The harness before
M6-C146 leaked its sessions: on the same binaries its step 8 had 571 and its
step 16 had 6,756 `-32050` refusals, and step 16 had no successes at all
(nonce `412EE926-B8C8-4485-ADFD-297418513F93`).

## 3. The offline answer through a real relay

Use [mcp.md](mcp.md)'s stack. After `scripts/demo-mcp.sh` has shown a call,
stop the device (`tunnel-client connect`) and repeat any MCP POST with the
same token. Expected: `503` with
`{"code":"DEVICE_OFFLINE","execution":"not_dispatched",...}`. An invented
service ID still gets `404`. This step is a recipe only. It was not run for
this change, because the demo script needs a Redis container and Docker was
unavailable on 2026-09-26. Step 1's relay test covers the same route over a
real socket.

## Recovery

- `-32050` means the export is full. Wait `retryAfterMs` and retry, `DELETE`
  sessions you no longer need, or raise the export's `max_children` (at most
  64) in the device runtime file.
- `DEVICE_OFFLINE` means the device has no live session at the relay. Retry
  after the device reconnects. `tunnel-client doctor` on the device shows why
  it is not connected.
- A soak run stopped part-way deletes its namespace in `finally`. If it was
  killed with SIGKILL, delete `tunnel-catalog:<namespace>:*` keys from the
  shared Redis yourself. The namespace is in the run's `events.jsonl`.
