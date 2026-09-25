# Demo: computer use (CUA) through a local relay

Status: written for task rows M5-C20..M5-C27 on 2026-09-26 on branch
`feat-cua-demo`. Linux guest only; macOS and Windows guests are not built
(see [What is not covered](#what-is-not-covered)).

A consumer on your Mac takes a screenshot of a synthetic app, clicks it and
types into it. The app runs in a **disposable Linux VM**, and every request
goes consumer → local `tunnel-relay` → `tunnel-client` in the VM → the pinned
`cua-computer-server` 0.3.46 on the VM's loopback. The consumer never talks
to the CUA server directly.

```text
host (macOS)                                   guest (Tart clone of cua-golden)
curl --http2 ──► tunnel-relay ◄── mTLS WSS ──── tunnel-client --features cua
 (consumer)     consumer 127.0.0.1               AGENT_TUNNEL_CUA_LANE_B=1
                device   192.168.64.1                 │ supervises
                                                       ▼
                                          cua-computer-server 0.3.46 (127.0.0.1)
                                                       │ XTest / ImageGrab
                                                       ▼
                                          Xorg + fixture app (state.json)
```

## Safety: read this first

- **Computer control runs only inside the Tart guest** (a clone of
  `cua-golden`, deleted when the demo exits). Nothing on the host captures the
  screen or sends input. **Do not grant Screen Recording or Accessibility to
  any host process**: nothing here needs them.
- The CUA export exists only in a `tunnel-client` built with the non-default
  `cua` feature, and even that build refuses to serve it unless
  `AGENT_TUNNEL_CUA_LANE_B=1` is set. Release binaries do not have the
  feature.
- Before the first request, the script checks that the relay is the **only**
  listener on its consumer and device ports. Before any input, a screenshot
  taken **through the tunnel** must show the fixture's five marker colours;
  otherwise the consumer sends no input and the run fails.
- All data is synthetic. Tokens and keys live in a `0700` temporary directory
  that is deleted on exit. The bearer token is passed to `curl` in a header
  file, never on a command line. Typed text is never logged.

## Prerequisites

| What | Why | Check |
| --- | --- | --- |
| Apple Silicon Mac | Tart runs Linux arm64 guests | `uname -m` prints `arm64` |
| Tart **2.38.0** | the VM; the script refuses other versions | `~/.local/bin/tart --version` |
| `cua-golden` built by `scripts/m5-cua-vm.sh golden` | the hardened, hash-locked image | `tart list` shows `cua-golden` |
| ≥ 20 GiB free after the step | the scripts' disk floor | `df -h ~/.tart` |
| Docker (arm64) | builds the guest's `tunnel-client` for `aarch64-unknown-linux-gnu` | `docker info` |
| A disposable plaintext Redis | the relay's catalog; a TLS terminator is put in front of it | `redis-cli -p 63790 ping` |
| `openssl`, `python3`, `curl` with HTTP/2 | PKI, helper tools, the consumer | `curl -V` lists `HTTP2` |

Building `cua-golden` downloads about 5 GB and takes about 30 minutes; see
[testing.md, Disposable Linux CUA VM](../testing.md#disposable-linux-cua-vm-apple-silicon-host).

## Run it

From the repository root:

```sh
# 1. The golden image (once; --rebuild replaces an existing one).
PATH="$HOME/.local/bin:$PATH" scripts/m5-cua-vm.sh golden --rebuild

# 2. The guest binaries: tunnel-client with the cua feature, and the
#    tunnel-deadman sentinel, built natively for linux/arm64 in Docker.
mkdir -p /tmp/cua-guest-target
docker run --rm -v "$PWD":/src:ro -v /tmp/cua-guest-target:/target \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -w /src rust:1.95.0 \
  cargo build --offline --locked --release -p tunnel-client --features cua \
    -p tunnel-deadman --bins

# 3. The demo: clone, relay, device, consumer, verdict, teardown.
TART="$HOME/.local/bin/tart" TEST_REDIS_URL=redis://127.0.0.1:63790/0 \
GUEST_BIN_DIR=/tmp/cua-guest-target/release \
  scripts/m5-cua-demo.sh /tmp/cua-demo-evidence
```

`rust:1.95.0` is Debian 13 (glibc 2.41) and the guest is Ubuntu 24.04
(glibc 2.39). Check that the binary needs nothing newer than 2.39 before you
copy it in:

```sh
docker run --rm -v /tmp/cua-guest-target:/t rust:1.95.0 sh -c \
  "objdump -T /t/release/tunnel-client | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1"
```

## What the script does

1. **Clones and boots** `cua-demo-<nonce>` from `cua-golden`, and waits until a
   root capture *inside the guest* shows the fixture's red marker.
2. **Makes synthetic PKI** on the host: a server CA and a relay certificate
   for `relay.cua-demo.test` and the host's address on Tart's private network,
   a device CA, and an RSA identity issuer with a JWKS.
3. **Starts a TLS terminator** in front of the plaintext Redis
   (`tunnel-relay serve` requires `rediss://`).
4. **Enrols the device inside the guest** as the `cua` user:
   `tunnel-client credentials create` makes the key and CSR in the guest (the
   private key never leaves it); the host signs the CSR with the device CA,
   adding `URI:urn:agent-tunnel:device:<uuid>`; `credentials import` installs
   it. The guest's `/etc/hosts` maps `relay.cua-demo.test` to the host.
5. **Provisions and starts the relay** with
   [`examples/m6-catalog-cua.toml`](../../examples/m6-catalog-cua.toml)
   (`http_forward_profile = "computer-v1"`) and `[http_forward] profiles =
   ["computer-v1"]`: dry run, `activate-first-incarnation`,
   `provision-catalog`, `serve`.
6. **Starts the device**: `tunnel-client connect` with
   `AGENT_TUNNEL_CUA_LANE_B=1` and this export table:

   ```toml
   [exports."77777777-7777-4777-8777-777777777777"]
   type = "http-forward"

   [exports."77777777-7777-4777-8777-777777777777".cua]
   profile = "computer-v1"
   point_width = 1280
   point_height = 800
   operations = ["describe", "capture", "screen_info", "cursor_position", "click",
                 "double_click", "move", "drag", "scroll", "type_text", "press_key", "hotkey"]

   [exports."77777777-7777-4777-8777-777777777777".cua.backend]
   command = "/opt/cua-fixture/cua-backend-supervised.sh"
   args = ["/home/cua/cua-export/backend.address"]
   workspace = "/home/cua/cua-export"
   address_file = "/home/cua/cua-export/backend.address"
   env = { PATH = "/usr/local/bin:/usr/bin:/bin", HOME = "/home/cua" }
   startup_seconds = 90
   ```

   On the first request, the export starts
   [`cua-backend-supervised.sh`](../../tests/cua-fixture/cua-backend-supervised.sh).
   The wrapper binds the server to a free guest-loopback port and publishes
   the address only once `/status` answers. The export then probes
   `screen_info` (read-only, never a click) and reads `/commands` and
   `version`. It negotiates the operation set, and it declares the point space
   only if `get_screen_size` equals it.
7. **Runs the consumer**
   ([`scripts/m5-cua-demo.py consumer`](../../scripts/m5-cua-demo.py)), which
   `POST`s `computer.v1` bodies over HTTP/2 to
   `https://127.0.0.1:<port>/v1/devices/<device>/services/<service>/http/computer`:
   `describe`, `screen_info`, `cursor_position`, `capture` (with the marker
   check), a click **without** the lease (it must be refused), then
   `acquire_input_lease`. With the lease it clicks the text field, runs
   `type_text`, and clicks the button. It then takes a new `capture`, clicks
   on the **old** capture (it must be refused as superseded), and runs
   `release_input_lease`.
8. **Reads the verdict from the app's own state file** in the guest
   (`/tmp/cua-fixture/state.json`): exactly one more click, and the text
   field holds exactly the typed text.
9. **M5-C09a probe (guest only, after the device has stopped).** It holds the
   left button and Shift through the server's `mouse_down`/`key_down`, then
   reads the X server's pointer mask and keymap in three states: after the
   HTTP client has gone, after the server is `SIGKILL`ed, and after a
   guest-side `xdotool` cleanup.
10. **Tears down** on any exit: the device, relay and terminator stop, the
    Redis namespace is deleted, and the clone is stopped and deleted.

## Expected output

The last lines of a passing run (from the run recorded in
[`tests/cua-fixture/evidence/2026-09-26-linux-aarch64-tunnel-demo/`](../../tests/cua-fixture/evidence/2026-09-26-linux-aarch64-tunnel-demo/)):

```text
EXPECTED_OUTPUT_PLACEHOLDER
```

`OUTDIR` holds `consumer.json` (every call's outcome and timing; for each
capture, the image's SHA-256, size and marker colours instead of the image),
`screenshot-tunnel.png` (the synthetic frame as the consumer received it),
`fixture-state-before.json` and `fixture-state-after.json`, `manifest.json`
(the guest's OS, display, keyboard and package versions), `residue-probe.json`,
`verdict.json`, and the relay and device logs.

## The wire, by example

Every answer is HTTP 200 with a `computer.v1` body. **Read `outcome`, not the
status.**

```sh
# describe: answered from the negotiated set, no backend exchange
{"version":"computer.v1","operation":"describe","params":{}}
# -> {"outcome":"answered_locally","result":{"operations":[...],"endpoint_is_loopback":true},...}

# the input lease has a wire form in this export (task row M5-C20)
{"version":"computer.v1","operation":"acquire_input_lease","params":{}}
# -> {"outcome":"answered_locally","result":{"held":true,"lease":1,"target":"primary"},...}

# capture: the device reads the PNG's dimensions and issues a capture id
{"version":"computer.v1","operation":"capture","params":{}}
# -> {"outcome":"ok","result":{"capture":1,"display":0,"image_data":"<base64 PNG>","format":"png",...}}

# click: coordinates are pixels of a named capture
{"version":"computer.v1","operation":"click","params":{"capture":1,"x":180,"y":180}}
# -> {"outcome":"ok",...}
```

| `outcome` | Meaning | Retry? |
| --- | --- | --- |
| `ok` | dispatched and succeeded | n/a |
| `answered_locally` | answered by the device, nothing sent to the backend | safe |
| `not_dispatched` | refused before dispatch, for example `lease_not_held`, `capture_superseded`, `capture_scale_undeclared`, `not_permitted` or `backend_unavailable` | `error.retryable` says |
| `failed` | dispatched and the backend reported failure | only for reads |
| `unknown` | dispatched, and the effect is not known | **never** |

## If it fails

| Symptom | Cause and fix |
| --- | --- |
| `tart ... is not the pinned 2.38.0` | Put Tart 2.38.0 first on `PATH`, or set `TART`. |
| `aborting: free space would drop below 20 GiB` | Free disk space, or run `scripts/m5-cua-vm.sh destroy-golden` and rebuild later. |
| `X session / fixture did not start` | Guest boot problem: `KEEP_VM=1` keeps the clone; inspect `~/.local/state/agentuplink-m5-cua-vm/logs/`. |
| `port N listeners are '...', expected only the relay` | Something else is listening on the chosen port. Rerun (ports are chosen per run); never skip the check. |
| `device not ready` | Read `OUTDIR/connect.log`. `this tunnel-client was built without the cua feature` means `GUEST_BIN_DIR` holds the wrong build; `set AGENT_TUNNEL_CUA_LANE_B=1` means the opt-in did not reach the process. |
| `backend_unavailable` on the first call | The supervised server did not come up within `startup_seconds`. Read `/tmp/cua-server-*.log` in the guest (`KEEP_VM=1`). |
| `frame is not the fixture; no input will be sent` | The screenshot did not show the markers (for example the black-root-framebuffer defect in testing.md). No input was sent; that is the gate working. |
| `capture_scale_undeclared` on a click | `point_width`/`point_height` disagree with the guest's `get_screen_size` (M5-C19): the export refused to declare them. Fix the export table. |
| A leftover `cua-demo-*` VM | `tart list`, then `scripts/m5-cua-vm.sh destroy <name>`. |
| Leftover Redis keys | `python3 scripts/m5-cua-demo.py redis-clean 127.0.0.1:63790 0 m5-cua-demo-<nonce>`. |

## What is not covered

- **macOS and Windows guests** (M5-03): not built. The macOS path needs a
  golden image with Screen Recording and Accessibility granted to the
  server's Python *inside the guest*, and a permission-denied variant.
  Windows needs an interactive (not Session 0) desktop.
- **A non-identity display scale** (M5-C19): the Linux guest runs at 1x, so
  the point-space derivation is proven at 2x only against the Lane A
  fixture.
- **Restart on a failed health probe** (M5-C23), **grant revision delivery**
  (M5-C05) and **per-operation grants** (M5-C24).
- **A second principal through the relay**: the second-agent lease refusal
  is proven against the fixture (`cua_export::tests`), not through the relay.
