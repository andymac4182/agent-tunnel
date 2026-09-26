# Demo: a consumer flood is refused per request, the device stays up

Task rows M6-C140 (fix for M6-C120), M6-C141 (fix for M6-C121) and M6-C142.
Every request goes consumer -> relay -> device over the real local relay.

## What it shows

Before the fix, 32 or more concurrent echoes against one device ended the
device's session with `RESOURCE_EXHAUSTED` "bounded connector queue limit
reached", and every user of that device then saw `DEVICE_OFFLINE` until it
reconnected. After the fix the excess requests are refused one by one with a
retryable, not-dispatched answer, and the device session survives:

```
HTTP/1.1 503 Service Unavailable
retry-after: 1
{"code":"RESOURCE_EXHAUSTED","execution":"not_dispatched",
 "message":"reverse channel operation did not complete",
 "retryable":true,"retry_after_ms":250}
```

## Run it

Prerequisites: a Redis reachable at `127.0.0.1:63790` (the harness uses a
unique namespace and deletes its keys), Python 3, and release binaries.

```sh
cargo build --release --locked --workspace --bins
BIN=target/release
# scripts/m6-soak.py comes from the M6-03 soak branch (PR #180); it reads
# examples/ from the checkout it sits in, so place it under scripts/:
git show origin/m6-03-soak:scripts/m6-soak.py > scripts/m6-soak.py
python3 scripts/m6-soak.py flood --bin-dir "$BIN" --logs /tmp/flood-demo \
  --workers 128 --seconds 60 --bin-head "$(git rev-parse HEAD)"
```

The harness provisions a relay, one device and one user with the shipped
commands, starts `tunnel-client connect --json`, runs 128 closed-loop echo
workers for 60 s, then sends 10 probe echoes.

## Expected output

In `/tmp/flood-demo/flood-*/summary.json`:

* `device_session_ends` is `[]` (before the fix: 4 or 5 entries, each
  `RESOURCE_EXHAUSTED` "bounded connector queue limit reached");
* `device_terminal_errors` is `[]` and `device_exit_code` is `null`
  (`connect` still running);
* `after` shows 10 of 10 probe echoes answered 200;
* the flood's non-200 answers are `RESOURCE_EXHAUSTED`/`not_dispatched`
  (capacity refusals), not `DEVICE_OFFLINE`.

`device-a-1.jsonl` has a single `ready` line and no `disconnected` line.

## If it fails

* `DEVICE_OFFLINE` for every request from the start: the device never came
  up; read `device-a-1.stderr.log` and `relay-1.log` in the run directory.
* `activate-first-incarnation` failed at `connection_establishment`: Redis is
  not reachable at the `--redis` address.
* Session ends still appear: record the `code` and `message` of each
  `disconnected` line in `device-a-1.jsonl` and attach the run directory to
  task row M6-C140; do not retry the run to get a green result.
