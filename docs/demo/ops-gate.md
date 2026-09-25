# Demo: runtime operations gate (M6-06)

What this shows, end to end through a real local relay:

1. `tunnel-client connect` is a supervisor with a local, owner-only status
   socket. `tunnel-client status` and `doctor` read it; nothing else can.
2. Every `tunnel-client` subcommand exits with the status
   [runtime.md](../runtime.md#client-exit-codes) publishes, including the new
   `8` (`SUPERVISOR_ABSENT`) and `9` (`SUPERVISOR_RUNNING`).
3. Neither `status` nor `doctor` prints a path, an endpoint, a key, a token,
   a canary or payload bytes.
4. The client and the relay each stop in order on SIGTERM in every data
   rotation phase -- active, preparing, quiescing, draining, committing,
   aborting -- with the device's owner slot released and an explicit outcome
   for the request in flight.

Everything is synthetic. Run from a checkout of this branch, macOS or Linux.

## Part A: the supervisor socket, without a relay (2 minutes)

A profile whose relay is a refused port keeps `connect` alive in its
reconnect loop, which is all the supervisor socket needs.

```sh
cargo build --locked -p tunnel-client
export PATH="$PWD/target/debug:$PATH"      # or ${CARGO_TARGET_DIR}/debug
demo=$(mktemp -d) && chmod 700 "$demo" && cd "$demo"
cat > client.toml <<'EOF'
device_id = "33333333-3333-4333-8333-333333333333"
relay_url = "wss://127.0.0.1:1/v1/tunnel/control"
[credentials]
client_certificate = "credentials/device-cert-chain.pem"
client_key = "credentials/device-key.pem"
server_ca = "credentials/relay-ca.pem"
[reconnect]
initial_delay_ms = 500
max_delay_ms = 2000
EOF
tunnel-client credentials create --config client.toml --csr-out device.csr
# Self-sign a synthetic device certificate for the pending key (demo only):
# the device role SAN names the profile's device_id.
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:33333333-3333-4333-8333-333333333333\n' > device-ext.cnf
openssl x509 -req -in device.csr -signkey credentials/device-key.pem -days 1 \
  -extfile device-ext.cnf -out cert.pem 2>/dev/null
tunnel-client credentials import --config client.toml --certificate cert.pem --server-ca cert.pem
```

No supervisor yet:

```console
$ tunnel-client status --config client.toml; echo "exit=$?"
tunnel-client: no supervisor is running for this profile (start `tunnel-client connect`)
exit=8
```

Start one in another terminal (`tunnel-client connect --config client.toml`)
or in the background, then read it:

```console
$ tunnel-client connect --config client.toml --json > connect.log 2>&1 &
$ tunnel-client status --config client.toml
Supervisor: pid=51234 state=backoff sessions=0
Session: none
Last session end: TRANSPORT_ERROR
$ ls -l credentials/supervisor.sock
srw-------  1 you  staff  0 ... credentials/supervisor.sock
$ tunnel-client doctor --config client.toml; echo "exit=$?"
Local configuration, credential key match, permissions, and expiry are healthy.
Supervisor IPC: ok (SUPERVISOR_IPC_OK)
exit=0
$ tunnel-client status --config client.toml --json
{"schema_version":1,"command":"status","ok":true,"result":{"pid":51234,"state":"backoff","device_id":"33333333-3333-4333-8333-333333333333","sessions":0,"attempt":3,"retry_delay_ms":1947,"last_error_code":"TRANSPORT_ERROR","certificate_expires_at_unix":1790434565,"rotation_policy":{"interval_seconds":300,"handshake_timeout_seconds":10,"overlap_seconds":30},"exports":[{"name":"echo","kind":"echo"}],"session":null,"ipc":{"requests_served":4,"peers_refused":0,"bad_requests":1}},"error":null}
```

The supervisor check in `doctor` is informational: `not_running` when no
`connect` is up, and it never changes the exit status.

The profile lock (an exclusive `flock` on `credentials/supervisor.lock`) refuses a second supervisor, and the socket is owner-only:

```console
$ tunnel-client connect --config client.toml; echo "exit=$?"
tunnel-client: another tunnel-client connect is already supervising this profile
exit=9
$ chmod 666 credentials/supervisor.sock
$ tunnel-client status --config client.toml; echo "exit=$?"
tunnel-client: local supervisor IPC refused: the supervisor socket is accessible to other users
exit=3
$ chmod 600 credentials/supervisor.sock
$ kill -TERM %1; wait %1; echo "exit=$?"     # stopped while waiting to reconnect
exit=130
$ ls credentials/supervisor.sock
ls: credentials/supervisor.sock: No such file or directory
```

A SIGKILLed supervisor cannot remove its socket; `status` reads the stale file
as absent (`8`) and the next `connect` replaces it.

The same checks, automated, with planted canaries and every subcommand's exit
status: `cargo test -p tunnel-client --test ops_gate_cli`.

## Part B: SIGTERM in every rotation phase, through a real local relay (6 minutes)

This provisions a real relay against a disposable Redis exactly as the
operator guide does (device key and CSR, an `openssl`-issued device
certificate, `activate-first-incarnation`, `provision-catalog`, `serve`), runs
`connect` against it with a 12 s rotation interval, pins each rotation phase
with the test-only hook, witnesses the phase (client: `tunnel-client status
--json`; relay: `tunnel_relay_sessions_by_rotation_phase` on its private
metrics listener), sends SIGTERM with an echo in flight, and checks the stop.

```sh
docker run -d --name demo-redis -p 127.0.0.1:63790:6379 redis:7   # or any disposable Redis
TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m6-shutdown-phases-verify.sh
```

Expected: twelve `m606-shutdown ok case=...` lines, two `m606-shutdown matrix
ok` lines, `test result: ok. 2 passed`, and `m6-shutdown-phases-verify: ok`.
Each `ok` line names the hold, both sides' witnessed phases, the exit
latency, the in-flight echo's outcome and how fast the owner slot was
re-admitted, for example:

```text
m606-shutdown ok case=client-draining hold="ROTATE_DRAINED,ROTATE_COMMIT" client_phase=Some("draining") relay_phase=Some("committing") exit=0 stop_ms=... inflight=... readmitted_ms=...
```

The hook exists only in a client built with `--features test-hooks`, which
the script builds into its own directory (`$CARGO_TARGET_DIR/m606-test-hooks`)
so it can never be mistaken for the shipped binary.

To watch a rotation phase by hand against the same relay, keep the script's
work directory (`M606_KEEP_WORKDIR=1`) and poll
`tunnel-client status --config <workdir>/device/client.toml --json` while a
rotation runs: `result.session.phase` moves through `preparing`, `quiescing`,
`draining`, `committing`, `retiring` and back to `active`, and
`rotations_completed` increments.

## Failure recovery

* `status` says `IPC_PATH_TOO_LONG` or `connect` warns `supervisor status IPC
  unavailable`: the socket path beside the key is over 103 bytes (common
  under macOS's long temporary directories). Set `[supervisor] ipc_path` to a
  shorter path in a directory only you can write.
* `status` exits `3` `IPC_UNAUTHORIZED`: the socket or its directory is
  reachable by other users, or owned by someone else. Find who changed it;
  restart `connect` to recreate it `0600`.
* `connect` exits `9` `SUPERVISOR_RUNNING`: another `connect` holds the
  profile. `tunnel-client status` names its pid.
* The matrix script fails a case: the log names the case, both witnessed
  phases and the client's events. A gate failure while `uptime` shows a load
  above about 20 is not evidence; rerun it.
* Redis keys: each run uses its own namespace (`m606-<side>-<nonce>`) and
  deletes it however the test ends.
