# Demo: off-the-shelf MCP clients through the relay

Task row M3-17. This shows the official MCP SDKs that a demo audience would
use, working through a real local relay without changes:

- the TypeScript SDK (`@modelcontextprotocol/sdk` 1.30.1);
- the Python SDK (`mcp` 2.2.0);
- the official conformance suite (`@modelcontextprotocol/conformance`
  0.2.0-alpha.11).

Each one connects over Streamable HTTP with a bearer token. The route is
always client → relay consumer listener (HTTPS and bearer) → device
WebSocket (mTLS) → `tunnel-client` → MCP server. Nothing bypasses the relay.

The pins, lockfiles and client scripts are in
[`tests/mcp-sdk-conformance`](../../tests/mcp-sdk-conformance). None of them
is a runtime dependency of any package.

## Prerequisites

- `cargo`, with Rust 1.95.0 from `rust-toolchain.toml`;
- Node 24 or later, with npm;
- `uv`, or Python 3.10 or later with `venv` and `pip`;
- `openssl` and `curl`;
- a Redis. Either:
  - a plaintext test Redis you already run, named by `M3SC_PLAIN_REDIS=host:port`
    or `TEST_REDIS_URL=redis://host:port/`. The script puts a TLS front on
    loopback in front of it, because `tunnel-relay serve` refuses a plaintext
    catalog. It writes only keys that contain the run's nonce, and deletes
    them when it exits;
  - or Docker, in which case the script starts its own TLS Redis container.
- network access to npm, PyPI and `raw.githubusercontent.com`. Every install
  is pinned: npm uses its lockfile, Python uses `--require-hashes`, and the
  reference server is checked against its SHA-256.

## Run it

From the repository root:

```sh
M3SC_PLAIN_REDIS=127.0.0.1:6379 scripts/m3-sdk-conformance.sh
```

The script:

1. builds `tunnel-relay`, `tunnel-client` and `tunnel-mcp-fixture`;
2. installs the pinned packages;
3. creates a throwaway PKI and identity issuer, and one consumer token with
   scope `http:invoke`;
4. starts three relay and device pairs, one for each MCP server the device
   exports:
   - `reference`: the conformance suite's reference server;
   - `sdkserver`: a plain server built on the TypeScript SDK;
   - `fixture`: the repository's rmcp fixture over stdio;
5. runs the clients through the relays, then runs the conformance suite
   twice: once directly against the reference server, and once through the
   relay.

A run takes about 2 to 2.5 minutes on a laptop, most of it the builds and
installs.

### Expected output (abridged)

```text
m3-sdk-conformance: reference stack up: relay :53043, device connected, backend streamable-http
m3-sdk-conformance: sdkserver stack up: relay :53254, device connected, backend streamable-http
m3-sdk-conformance: fixture stack up: relay :53323, device connected, backend stdio
  sdk=typescript case=initialize result=pass protocol=2025-11-25 server=mcp-conformance-test-server
  sdk=typescript case=resources/read result=pass text=1 blob=1
  sdk=typescript case=notifications/progress result=pass progress=0,50,100
  sdk=typescript case=cancellation result=pass client_outcome=AbortError server_marker=cancelled
  sdk=python mode=auto case=prompts/get result=pass messages=1+1
  sdk=python mode=legacy case=initialize-known-m3-47 result=pass backend_error=-32020 upstream_row=M3-47
  sdk=python mode=legacy case=cancellation result=pass client_outcome=cancelled server_marker=cancelled
  sdk=python mode=legacy case=close-cancel result=known row=M3-48 error="ClosedResourceError: "
  sdk=curl case=origin-refused result=pass status=400 header=origin
  conformance scenario=tools-call-with-progress direct=pass(2/2) relay=pass(2/2)
  conformance scenario=dns-rebinding-protection direct=pass(2/2) relay=fail(0/2) ... expected_failure_row=M3-49
  conformance scenarios direct=31 relay=31 relay_pass=30 verdict=pass
m3-sdk-conformance: summary nonce=... sdk_cases_pass=72 sdk_cases_fail=0 sdk_cases_known=... elapsed_s=...
m3-sdk-conformance: ok: the pinned TypeScript and Python MCP SDKs and the conformance suite work through the relay
```

The script exits 0 only if all of these hold:

- every SDK case passes;
- every conformance scenario passes directly;
- every scenario passes through the relay, except the ones listed in
  [`relay-expected-failures.txt`](../../tests/mcp-sdk-conformance/relay-expected-failures.txt).
  Each listed scenario must still fail, so a stale entry also turns the run
  red.

A `result=known` line is neither a pass nor a failure. It names the open row
that explains it.

## Point your own client at the relay

To keep the three stacks up for an agent or SDK of your own:

```sh
M3SC_HOLD=1 M3SC_KEEP=1 M3SC_PLAIN_REDIS=127.0.0.1:6379 scripts/m3-sdk-conformance.sh
```

When the stacks are up, the script prints the path of `stack.env`. That file
holds:

- the three endpoint URLs;
- the synthetic server CA;
- the path of a token file (mode 600, valid for one hour).

Then, for example:

```sh
. /path/from/the/message/stack.env
cd tests/mcp-sdk-conformance
AGENTUPLINK_TOKEN=$(cat "$TOKEN_FILE") NODE_EXTRA_CA_CERTS="$SERVER_CA" \
  node ts-client.ts reference "$SDKSERVER_URL"
AGENTUPLINK_TOKEN=$(cat "$TOKEN_FILE") AGENTUPLINK_CA="$SERVER_CA" \
  "$PYTHON" python/py_client.py reference auto "$SDKSERVER_URL"
```

Any Streamable HTTP MCP client works the same way. It needs to:

- send `Authorization: Bearer <token>`;
- trust `$SERVER_CA`.

Create `release` in the work directory to let the run finish and clean up.

## What a client must know about this relay

- **Profile.** Each service is exported with one pinned profile. This demo
  uses `mcp-2025-11-25`, which is sessioned and uses `initialize`. The Python
  SDK's default `auto` mode first probes `server/discover` with the 2026
  headers. The relay answers that probe with `400 HTTP_INVALID_HEAD`
  (`header: mcp-method`), and the SDK then falls back to `initialize`. This
  costs one round trip and works.
- **Headers.** The relay refuses unlisted request headers and names the
  first one in the error body. It drops a stock client's `user-agent`,
  `accept-encoding`, `accept-language`, `sec-fetch-mode` and
  `cache-control`. The last of these was added by M3-46 for the Python SDK's
  event stream. A request that carries `Origin` is refused, which is why
  browsers cannot use the relay yet (M3-49).
- **Python 3.13 and later reject a CA without `keyUsage`.** A bare
  `openssl req -x509` produces such a CA. This script adds
  `-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign`.

## Failure recovery

- **`FAIL: redis TLS front`, or a stack that never becomes ready.** Check that
  the plaintext Redis answers. Then read
  `<work>/logs/<stack>-relay.log` and `<work>/logs/<stack>-connect.log`. The
  work directory is kept after any failure.
- **`FAIL: docker run redis` or a hang there.** Docker is not responding. Set
  `M3SC_PLAIN_REDIS` so the script uses an existing Redis.
- **`reference server sha256 ... != pinned`.** The upstream file changed at
  the pinned commit. That should not happen. Do not update the pin without
  reviewing the diff.
- **A `conformance problem:` line.** The verdict names the scenario, and
  `<work>/conformance-relay/server-<scenario>-*/checks.json` has the
  details. If a scenario fails only through the relay, it is a relay
  incompatibility: record a row, then list the scenario in
  `relay-expected-failures.txt` with that row.
- **`initialize-known-m3-47 result=fail ... no longer reproduces`.** The
  upstream reference server now accepts the Python SDK. Re-examine M3-47
  and close it.
- **Leftover processes after an interrupted run.** Every child is killed on
  exit. If the script itself was killed with `SIGKILL`, stop any leftover
  `tunnel-relay serve`, `tunnel-client connect`, `everything-server.ts`,
  `ts-sdk-server.mjs` and `redis_tls_proxy.py` processes that name the
  run's work directory.
