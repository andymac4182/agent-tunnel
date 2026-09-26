# Demo: an MCP server on your computer, used through the relay

This is the MCP demo recipe. An MCP server runs on the "device", the computer
running `tunnel-client`. `tunnel-client` exports it through a relay. A real
MCP client, standing in for a cloud agent, then uses the server through the
relay's public HTTPS endpoint. The traffic goes from the client to the relay,
then over the device's mTLS WebSocket to `tunnel-client`, and from there to
the MCP server over stdio. Nothing bypasses the relay, and the device opens no
inbound port.

One script does it all locally with synthetic data:

```sh
scripts/demo-mcp.sh
```

**What has been run.** On 2026-09-25, on macOS arm64, `scripts/demo-mcp.sh`
passed with both profiles (`mcp-2025-11-25` and `mcp-2026-07-28`) and printed
the output shown below. No hosted agent (Claude or any other) has been
connected to a relay in this repository. The section
[Connecting a hosted agent](#connecting-a-hosted-agent) says what that needs,
and what is not yet proven.

## What you need

- The repository and Rust (the toolchain pinned in `rust-toolchain.toml`).
- `openssl`, `python3` (3.11 or later, for `tomllib`) and `xxd`.
- Docker, and the `redis:8.4.0-alpine` image (`docker pull redis:8.4.0-alpine`).
  The relay refuses a Redis catalog without TLS, so the demo starts its own
  Redis container, with TLS, on a free loopback port. It never uses any other
  Redis you have running, and it removes the container when it finishes.

## What the script does

Each step uses the shipped binaries and the shipped example files, as
[the operator guide](../operator.md) describes. Every key, certificate and
token is synthetic and made for the run. The steps are:

1. It builds `tunnel-relay`, `tunnel-client`, `tunnel-mcp-fixture` (the MCP
   server) and `tunnel-test-harness` (the MCP client).
2. It creates a throwaway server CA and a certificate for `localhost` and
   `127.0.0.1`, used by both relay listeners and the demo Redis.
3. It starts a Redis container with TLS (`agentuplink-mcp-demo-<nonce>`).
4. It creates an identity issuer: an RSA key, published to the relay as a
   one-key JWKS file.
5. It writes the catalog records: `examples/m6-catalog-mcp.toml` with the
   profile you chose. The records hold one tenant, one user (`trial-user`),
   one device, one `http-forward` service and one `http:invoke` grant.
6. It sets up the device: `examples/m1-client.toml` with one MCP export.
   The export's backend is `tunnel-mcp-fixture stdio`. The script then runs
   `tunnel-client credentials create`, signs the CSR with a throwaway device
   CA, and runs `tunnel-client credentials import`.
7. It sets up the relay: `examples/m1-relay.toml` plus an `[http_forward]`
   table that names the profile and `public_url`.
8. It runs `tunnel-relay activate-first-incarnation`, then
   `tunnel-relay provision-catalog`.
9. It starts `tunnel-relay serve` and `tunnel-client connect`, and waits for
   `Connected:`.
10. It signs a consumer token (RS256, `scope = "http:invoke"`, valid for one
    hour) and runs the MCP client against
    `https://localhost:<port>/v1/devices/<device>/services/<service>/http/mcp`.

### The MCP server

`tunnel-mcp-fixture` is a small deterministic MCP server, built with the
official Rust SDK (rmcp 3.4.0). It touches no user data. It offers:

- **Tools:** `echo` returns its arguments plus a 1×1 PNG image block.
  `progress` and `log` send notifications. `touch` reports a resource as
  updated to anyone subscribed to it. The others (`sleep`, `crash`, `big`,
  `stream` and more) exist for the test gates.
- **Resources:** a text resource, `fixture://synthetic/readme.txt`, and a
  binary one, `fixture://synthetic/pixel.png`.
- **Prompts:** `greet`, which takes a required `name` argument.
- **Subscriptions:**
  - `resources/subscribe` for 2025-11-25. A later `touch` sends
    `notifications/resources/updated` on the session's standalone GET stream.
  - `subscriptions/listen` for 2026-07-28. Each request gets a fresh child
    process, so the listener sends one update for each accepted URI and then
    ends the subscription cleanly.

You can export any MCP server that speaks stdio instead, such as one started
with `npx` or `uvx`. Change the export's `command`, `args` and `workspace` in
the device's `client.toml`. The server must implement the profile's MCP
revision itself, because the relay translates no lifecycle
(see [mcp.md](../mcp.md)).

### The MCP client

`tunnel-test-harness mcp-demo-client --url URL --ca PEM [--profile P]` runs
the official Rust MCP SDK client (rmcp 3.4.0). It reads the bearer token from
`AGENTUPLINK_TOKEN` and never prints it. The steps below are what a standard
client does:

1. **Discovery (task row M3-11).** A POST without a token gets `401`. The
   response carries `WWW-Authenticate: Bearer resource_metadata="…",
   scope="http:invoke"`. The client fetches the RFC 9728 protected-resource
   metadata from that URL, and checks that its `resource` is the endpoint URL.
2. **The MCP lifecycle.**
   - For 2025-11-25: `initialize`, which returns an `Mcp-Session-Id`. For
     2026-07-28: `server/discover`.
   - `tools/list`, then `tools/call echo`, which returns text and an image.
   - `resources/list`, then `resources/read` of the text and the binary
     resource.
   - `prompts/list`, then `prompts/get greet`.
   - A subscription, then the `notifications/resources/updated` it produces.
   - Progress and log notifications.
   - It then ends the session. For 2025-11-25 this is a `DELETE`.

## Expected output

This is the output of `scripts/demo-mcp.sh` (default profile). Ports and
nonces vary from run to run:

```text
demo-mcp: start the relay (tunnel-relay serve) on https://localhost:59271
demo-mcp: connect the device (tunnel-client connect)
demo-mcp: MCP endpoint: https://localhost:59271/v1/devices/33333333-3333-4333-8333-333333333333/services/55555555-5555-4555-8555-555555555555/http/mcp
demo-mcp: run the MCP client (tunnel-test-harness mcp-demo-client, rmcp 3.4.0)
mcp-demo: step=unauthenticated status=401 challenge=Bearer resource_metadata="https://localhost:59271/.well-known/oauth-protected-resource/v1/devices/33333333-3333-4333-8333-333333333333/services/55555555-5555-4555-8555-555555555555/http/mcp", scope="http:invoke"
mcp-demo: step=resource-metadata status=200 resource="https://localhost:59271/v1/devices/…/http/mcp" authorization_servers=["https://issuer.demo.agentuplink.test/"] scopes_supported=["http:invoke"]
mcp-demo: step=initialize ok profile=2025-11-25 server=tunnel-mcp-fixture
mcp-demo: step=tools/list count=11 names=echo,progress,sleep,crash,stderr_flood,big,log,stream,gate,touch,detach
mcp-demo: step=tools/call name=echo text={"arguments":{"greeting":"hello from the demo"},"meta":{"progressToken":1}} images=1
mcp-demo: step=resources/list count=2 uris=fixture://synthetic/readme.txt,fixture://synthetic/pixel.png
mcp-demo: step=resources/read uri=fixture://synthetic/readme.txt text="Synthetic fixture resource. It holds no user data."
mcp-demo: step=resources/read uri=fixture://synthetic/pixel.png blob_base64_bytes=92
mcp-demo: step=prompts/list count=1 names=greet
mcp-demo: step=prompts/get name=greet messages=["Say hello to Ada from the synthetic fixture."]
mcp-demo: step=resources/subscribe uri=fixture://synthetic/readme.txt touch="touched subscribed=true" notifications/resources/updated=received
mcp-demo: step=notifications logs_received=2 progress_received=3
mcp-demo: ok profile=2025-11-25 tools=11 resources=2 prompts=1
demo-mcp: ok: the device's MCP server answered a real MCP client through the relay
```

With `DEMO_PROFILE=mcp-2026-07-28`, the lifecycle line reads
`step=server/discover ok profile=2026-07-28`, and the subscription line reads
`step=subscriptions/listen uri=fixture://synthetic/readme.txt
notifications/resources/updated=received`.

## Options

| Variable | Effect |
| --- | --- |
| `DEMO_PROFILE` | `mcp-2025-11-25` (default; sessions and `initialize`) or `mcp-2026-07-28` (stateless, `server/discover`). |
| `DEMO_KEEP=1` | Leave the relay, the device and the Redis container running after a successful run. The script prints the endpoint, the server CA path and the token file, so you can point another client at it. It also prints the `kill` and `docker rm` commands that stop everything. |
| `DEMO_DIR` | The work directory (default: a new directory under `$TMPDIR`). It is removed after a successful run and kept after a failure. |
| `CARGO_TARGET_DIR` | Honoured when building and when locating the binaries. |

To use your own client against a kept demo, point it at the printed endpoint.
It must trust the printed server CA, send `Authorization: Bearer $(cat
<work>/consumer-token)`, and negotiate the profile's MCP revision. For
example, run the demo client again:

```sh
AGENTUPLINK_TOKEN=$(cat "$DEMO_DIR/consumer-token") \
  "$CARGO_TARGET_DIR/debug/tunnel-test-harness" mcp-demo-client \
  --url "https://localhost:<port>/v1/devices/<device>/services/<service>/http/mcp" \
  --ca "$DEMO_DIR/server-ca.pem"
```

## When it fails

- **`docker: … Unable to find image`**: run `docker pull redis:8.4.0-alpine`
  first. The script does not pull images for you.
- **`activate-first-incarnation` keeps failing**: the Redis container did not
  come up. Run `docker logs agentuplink-mcp-demo-<nonce>`. After a failure the
  script keeps the work directory, and you can look at `activate.log` there.
- **The relay or the device never becomes ready**: the script prints
  `relay.log` or `connect.log` from the work directory. Rerun with
  `RUST_LOG=info` for more detail. Neither log contains a token or payload.
- **`mcp-demo: step=… failed`**: the named step failed, and the line gives its
  status or error. A `401` or `403` at a step after discovery means the token
  was refused. Tokens last one hour, so a kept demo needs a fresh one after
  that; rerun the script.
- **Leftovers after an interrupted run**: `docker ps --filter
  name=agentuplink-mcp-demo` lists the demo's Redis containers. `docker rm -f`
  removes one.

## Connecting a hosted agent

A hosted agent needs three things. The first is the endpoint URL. The second
is a bearer token that the relay accepts. The third is a relay it can reach
over the public internet, with a certificate from a public CA. The local demo
provides none of the third: its relay listens on `localhost` with a throwaway
CA. To try this with a hosted agent, run a relay that the agent can reach
(see [deploy-fly.md](../deploy-fly.md) and the [operator guide](../operator.md)),
and provision the MCP service on it as step 5 above does.

**The endpoint** is

```text
https://<relay public host>/v1/devices/<device id>/services/<service id>/http/mcp
```

**The token** is an access token from the identity issuer that the relay is
configured with. It is not a relay-issued secret. The relay accepts it when
all of the following hold:

- `iss` is the relay's `oidc_issuer`.
- `aud` is one of the relay's `oidc_audience` values.
- It is signed by a key in the relay's JWKS (RS256 or EdDSA).
- It has not expired.
- `sub` is the `oidc_subject` of a user in the catalog, and that user is a
  member of the tenant.
- `scope` includes `http:invoke`, plus any scope the relay requires of every
  token.
- The catalog holds an unexpired grant for that user on that device and
  service, with the `http:invoke` operation.

The relay checks all of this itself, on the ingress relay and again on the
owner relay. The token is never passed on to the device or to the MCP server.

**Discovery.** An unauthenticated request gets `401` with
`WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource/v1/devices/<device>/services/<service>/http/mcp", scope="http:invoke"`.
That metadata names the relay's `oidc_issuer` as the one authorization
server, and `http:invoke` as the scope. A client that performs MCP
authorization (2025-11-25) follows it to the issuer and obtains a token
there. Set `[http_forward] public_url` (`https://host[:port]`) on any relay
that serves the internet. Without it, the relay builds these URLs from the
request's own authority, which is wrong behind a proxy that changes the host
name. The demo sets it. If the issuer puts the RFC 8707 `resource` value
(the endpoint URL) into `aud`, add that URL to `oidc_audience`.

**Claude, through the Messages API MCP connector.** Pass the endpoint and a
token you obtained from the issuer. The request uses the beta
`mcp-client-2025-11-20`:

```json
{
  "mcp_servers": [{
    "type": "url",
    "url": "https://<relay>/v1/devices/<device>/services/<service>/http/mcp",
    "name": "my-desktop",
    "authorization_token": "<access token with scope http:invoke>"
  }],
  "tools": [{"type": "mcp_toolset", "mcp_server_name": "my-desktop"}]
}
```

**Claude custom connectors, or any client that uses OAuth.** The client
discovers the issuer from the metadata above and runs OAuth against it. Whether
this works depends on your issuer: the client must be able to register or be
registered with it, and the tokens it issues must meet the rules above.

**Any other Streamable HTTP MCP client.** Configure the URL and the header
`Authorization: Bearer <token>`.

**Known limits.**

- **Protocol version.** Each service speaks exactly one MCP revision: its
  catalog `http_forward_profile`, `2025-11-25` or `2026-07-28`. The relay
  refuses any other `MCP-Protocol-Version` header. A client that negotiates
  an older revision, such as `2025-06-18`, fails at its first request after
  `initialize`, even though the MCP server may accept that revision
  (task row M3-38).
- **Browsers.** A request with an `Origin` header is refused. Browser-based
  clients are not supported (M3-11).
- **Not proven with a hosted agent.** No hosted agent has been connected in
  this repository. The discovery and the token rules above are proven only
  by the local demo and by the relay's tests.
