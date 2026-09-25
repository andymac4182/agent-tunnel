# Demo: an ACP session through a local relay

This demo runs one [Agent Client Protocol](../acp.md) session from a consumer,
through a real local relay, to an ACP agent running as a stdio child on a
device. The consumer is the **official ACP client**
(`agent-client-protocol` / `agent-client-protocol-http` `=2.1.0`, the versions
`crates/tunnel-acp` pins). It shows, in order:

1. `initialize` and `session/new`;
2. a prompt whose streaming `session/update` chunks arrive before the turn
   ends `end_turn`;
3. a prompt where the agent asks for **permission**, the client's callback
   allows it, and the agent reports the outcome it received;
4. a prompt where the agent asks for permission and the client **cancels**
   the turn instead: `session/cancel` resolves the pending callback as
   `cancelled`, and the turn ends `cancelled`.

**The agent is the repository's synthetic ACP agent, not a real coding
agent.** `tunnel-acp-fixture agent` speaks ACP v1 over stdio with no model, no
credentials and no network. Its prompts are directives (`updates:5`,
`permission`) rather than natural language, and its only effects are marker
files in its own workspace. A real agent such as an editor's ACP agent needs
network access and model credentials, which this repository's tests and demos
never use. Nothing below claims that any third-party ACP agent has been run
through the relay.

## What runs where

Every hop is a separate process, and nothing bypasses the relay:

```text
acp-demo-client ──HTTP/2 + TLS, bearer token──▶ tunnel-relay serve
  (consumer, official ACP client)                 (consumer listener, Axum)
                                                        │ device data WebSocket (mTLS)
                                                        ▼
                                                  tunnel-client connect
                                                  (device, [exports.<id>.acp])
                                                        │ stdio, started by the device
                                                        ▼
                                                  tunnel-acp-fixture agent
```

- The relay is provisioned from the shipped records example
  `examples/m6-catalog-acp.toml` with the shipped commands
  (`activate-first-incarnation`, `provision-catalog`), in a fresh random Redis
  namespace that is deleted afterwards.
- The device's export is the one that example documents: `type =
  "http-forward"`, `profile = "acp-http-v1"`, and a fixed agent command and
  workspace. The relay never chooses the executable; the device does.
- The consumer reaches `/v1/devices/<device>/services/<service>/http/acp` with
  an access token scoped `http:invoke`.

What stands in for the outside world is the same as in the M6-C57 gate this
demo is built on (`crates/tunnel-relay/tests/m6_provisioning_process.rs`): a
synthetic server CA for the relay's listener, a local RSA key as the identity
issuer (its public half is the relay's JWKS), `openssl` as the device
certificate issuer, and a local TLS forwarder in front of a plaintext Redis
because `serve` accepts only `rediss://`.

## Run it

Needs: the Rust toolchain from `rust-toolchain.toml`, `openssl` on `PATH`, and
a **disposable** plaintext Redis. With Docker:

```sh
docker run -d --name acp-demo-redis -p 127.0.0.1:6390:6379 redis:7
```

Then, from the repository root:

```sh
TEST_REDIS_URL=redis://127.0.0.1:6390/ scripts/demo-acp.sh
```

The script builds `tunnel-relay`, `tunnel-client` and the agent, builds
`acp-demo-client` in its own `cargo build --features interop` (the pinned
client's `reqwest` must stay out of the shared build graph, task row M8-C09),
then runs the ignored test
`m8_acp_demo_official_client_runs_a_session_through_the_relay`, which brings
up the relay and the device and runs the client against them. A cold build
takes several minutes; the session itself takes about 2.5 seconds.

## Expected output

The script prints the client's transcript, then the test's summary line:

```text
demo-acp: run the session through a local relay
demo: ok initialize protocol=1
demo: ok session/new session=session-1
demo: update chunk-0
demo: update chunk-1
demo: update chunk-2
demo: update chunk-3
demo: update chunk-4
demo: ok prompt-streaming stopReason=end_turn
demo: permission requested "Read the synthetic fixture listing" options=["permit-one", "reject-one"]
demo: permission answered selected=permit-one
demo: update permission-outcome:selected:permit-one
demo: ok prompt-permission stopReason=end_turn
demo: permission requested "Read the synthetic fixture listing" options=["permit-one", "reject-one"]
demo: sending session/cancel
demo: update permission-outcome:cancelled:
demo: ok prompt-cancel stopReason=cancelled
demo: PASS initialize, session, streaming, permission and cancel through the relay
m8-acp-demo ok nonce=... namespace=m8-acp-demo-... client=agent-client-protocol-http=2.1.0 streaming=end_turn permission=selected:permit-one cancel=cancelled cancel_at_agent=cancelled elapsed_ms=...
demo-acp: ok
```

How to read it:

- Every `stopReason` is the one in the message the client received on the
  session's SSE stream. Nearly every POST in this binding answers `202`, which
  only means the bridge accepted it, so no line is based on an HTTP status.
- `permission-outcome:...` lines are chunks **the agent** sent, reporting what
  it actually received: the client's selection, and then the cancellation.
- `cancel_at_agent=cancelled` is read from the marker file the agent wrote in
  its workspace, so the cancellation is confirmed by the agent, not just by
  the client.
- Each update is printed before the result of the turn it belongs to. That
  ordering is guaranteed by the export, not by luck (task row M8-C27).

The script exits `0` only when the transcript, the agent's marker and the
test's own `m8-acp-demo ok` line all agree. Anything else exits `1` with the
full log.

## Pointing the client at your own relay

`acp-demo-client` is an ordinary binary, and it can drive a relay you brought
up yourself with [operator.md](../operator.md) (sections 2.3 and 3.1, with
`examples/m6-catalog-acp.toml` as the records file and the export table that
file documents in the device's profile, running `tunnel-acp-fixture agent`):

```sh
cargo build --locked -p tunnel-acp-fixture --features interop --bin acp-demo-client
target/debug/acp-demo-client \
  --url https://<relay host>:<consumer port>/v1/devices/<device id>/services/<service id>/http/acp \
  --ca <the CA that issued the relay's listener certificate>.pem \
  --token-file <a file holding an access token with scope http:invoke> \
  --cwd <the export's configured workspace, exactly as written in the device profile>
```

The token is read from a file and is never printed. `--cwd` must match the
export's `workspace` string exactly: the bridge refuses any other working
directory with `400`, because the consumer does not get to choose where the
agent runs.

## If it fails

| Symptom | Cause and recovery |
| --- | --- |
| `demo-acp: TEST_REDIS_URL (a disposable plaintext Redis) is required.` | Set `TEST_REDIS_URL` as above. Use a Redis you can throw away. The demo writes only under its own random namespace and deletes it, but it is still test data. |
| The test panics at `issuer key (openssl genpkey)` | `openssl` is not on `PATH`. |
| `step acp demo readiness: ...` after about 20 s | The device never registered with the relay. The panic message includes the device's `--json` log and the tail of its stderr. The usual causes are a Redis that is not reachable (check `redis-cli -u "$TEST_REDIS_URL" ping`) or a stale build: re-run the script, which rebuilds both binaries. |
| `demo: FAILED setup: ...` | The client could not read `--ca` or `--token-file`, or the CA is not PEM. |
| `demo: FAILED the ACP connection ended with an error: ...` | The relay or the device refused a request. A `401` means the token's issuer, audience, subject or scope does not match the catalog; a `404` means the device or service id in the URL is wrong or the device is not connected; a `501` means the request was not HTTP/2. |
| `demo: FAILED prompt-... stopReason=...` | The agent answered with a different stop reason than that step expects. Against anything other than `tunnel-acp-fixture agent`, this is what to expect: the demo's prompts are that agent's directives. |
| `demo: FAILED the session did not finish within 60s` | Something stopped forwarding. Re-run the script once; if it recurs, keep the log and file it with the transcript. |
| A leftover `tunnel-relay`, `tunnel-client` or `tunnel-acp-fixture` process after an interrupted run | The test kills its children when it is dropped, but `Ctrl-C` during `cargo test` may not reach them. `pkill -f tunnel-acp-fixture` and so on is safe: every process the demo starts is local and synthetic. |

To clean up the Redis container: `docker rm -f acp-demo-redis`.

## What this demo does not show

- **A real ACP agent.** Only the repository's synthetic agent has been run.
- **More than one relay.** The consumer and the device use the same relay. The
  three-relay path, where the consumer enters at a relay that does not own the
  device, is covered by the `verify-m8-acp-real-path` and
  `verify-m8-acp-cluster` gates in `scripts/m8-harness-verify.sh`, not by this
  demo.
- **A sandbox.** The device runs its configured agent as a trusted local
  process. No OS sandbox profile is claimed ([acp.md](../acp.md)).
- **Hosts other than macOS.** This demo has only been run on macOS.
- `session/load`, `Last-Event-ID` resume and ACP protocol v2. The bridge
  refuses them; see [acp.md](../acp.md).
