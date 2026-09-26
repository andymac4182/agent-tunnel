# Join an existing relay (testers)

Status: written for task row M6-C103 on 2026-09-25 against `origin/main` at
`f9f7abf`. Every command was checked against the published pre-release
`v0.1.0-main.36116938623.f9f7abfc5946` (`aarch64-apple-darwin`): its archive
layout, its `--help`, and a local rehearsal of sections 1 to 4 with a
throwaway CA standing in for the operator. Sections 5 and 6 (connect and echo)
match the live relay smoke check of 2026-09-25 (M6-C103). This page is **not**
executed by the docs check that runs [operator.md](operator.md).

This page is for a tester whose operator **already runs a relay**, such as the
project's alpha relay at `agentuplink-relay.fly.dev`. You install the device
half on your own Linux or macOS computer, get it a certificate, connect it,
and call the synthetic echo service through the relay. You do not run a
relay, Redis or an identity issuer. To run your own relay, follow the
[operator guide](operator.md) instead.

Windows can run `tunnel-client` but cannot create or import device credentials
in this alpha, so this page needs Linux or macOS.

## 0. What you exchange with the operator

| When | From | What |
| --- | --- | --- |
| Before you start | Operator | The **device URL**, for example `wss://agentuplink-relay.fly.dev:9443/v1/tunnel/control`, and the **consumer URL**, for example `https://agentuplink-relay.fly.dev` |
| Before you start | Operator | The **relay CA certificate** (`relay-ca.pem`). The relay uses a private CA, so nothing connects without it |
| Before you start | Operator | Your **device UUID** and your echo **service UUID** |
| Before you start | Operator | The **release tag** to install. Device and relay should run the same version |
| Section 3 | You | Your certificate signing request, `device.csr`. **Never send the private key** |
| Section 4 | Operator | Your signed **device certificate** (`device-cert.pem`), once they have added your user, device, service and grant to the relay's catalog ([deploy-fly.md section 6.6](deploy-fly.md#66-day-2-catalog-changes-onboarding-a-tester-and-revocation)) |
| Section 6 | Operator | A way to get a **consumer token**: a short-lived token, or access to their identity issuer. It must carry your user's `sub` and `echo:invoke` in `scope` |

All of these are placeholders below: `<device UUID>`, `<service UUID>`,
`<relay host>`. None of them is secret except the token. The private key never
leaves your computer.

## 1. Download and verify a release

Releases are GitHub pre-releases built by CI for `aarch64-apple-darwin`,
`x86_64-apple-darwin`, `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`.
They are development builds, not production releases. Download the tag your
operator names; `gh release list -R andymac4182/agentuplink` shows them all.
On an Apple silicon Mac:

```text
mkdir -p ~/agentuplink && cd ~/agentuplink
gh release download <tag> -R andymac4182/agentuplink -p '*aarch64-apple-darwin*'
shasum -a 256 -c agentuplink-*.tar.gz.sha256
```

On Linux use `-p '*x86_64-unknown-linux-gnu*'` and `sha256sum -c`. Expect
`agentuplink-<tag>-<target>.tar.gz: OK`. You can also download both files from
the releases page, `https://github.com/andymac4182/agentuplink/releases`, or
through the [downloads page](https://agentuplink.dev/docs/downloads).

**The checksum proves the download is intact, not who built it.** The
`.sha256` file comes from the same release page as the archive, so anyone who
could replace one could replace both.

**The build attestation says where it was built.** Releases built after the
release-hardening change (M6-C114) carry a GitHub build-provenance attestation
for every archive and every `.sha256` file. Check the archive with the GitHub
CLI, using exactly this command; each flag narrows what passes:

```text
gh attestation verify agentuplink-*.tar.gz -R andymac4182/agentuplink --signer-workflow andymac4182/agentuplink/.github/workflows/release.yml --source-ref refs/heads/main
```

A pass means GitHub's Sigstore-backed signing service recorded that a file with
exactly this SHA-256 was produced by a run of the release workflow
(`release.yml`) in `andymac4182/agentuplink`, running on `main`. The commit the
output names is **main's tip when the release ran**. This can be later than the
commit the archive was built from, because the release starts after CI finishes
on main. The source identity is `sourceSha` in the archive's `release.json`,
not the attested commit.

It does **not** mean the source was reviewed or is safe. It is not code signing:
macOS and Windows still treat the binaries as unsigned. Anyone with write access
to the repository's workflows can produce an attestation. Older releases have no
attestation, and the command fails with `HTTP 404` for them; for those, the
checksum is the only check.

The archive has **no top-level folder**; it unpacks `LICENSE`, `README.txt`,
`bin/`, `examples/`, `notices/` and `release.json` into the current directory
(archives built after M6-C50 also carry `docs/`). Unpack it into an empty
directory:

```text
mkdir release && tar -xzf agentuplink-*.tar.gz -C release && cd release
cat release.json
```

`release.json` names the `version`, the `sourceSha` it was built from, the CI
run and the `target`. `notices/` holds the third-party licence texts.
Archives built after M6-C102 carry every example the shipped documents name
(the Windows archive carries the client profile only). Older archives hold only
`m1-client.toml` and `m1-relay.toml`; for those, every other example is in the
repository at `sourceSha`:
`https://github.com/andymac4182/agentuplink/tree/<sourceSha>/examples`.
Newer archives' `README.txt` says to start with `docs/operator.md`. That guide
is for running a relay; as a tester joining one, ignore that pointer and follow
this page, which those archives also carry as `docs/join-relay.md`.

**macOS only:** the binaries are not code-signed or notarized. `gh release
download` does not mark files as quarantined, so they run as they are. An
archive downloaded **with a browser** is quarantined, and Gatekeeper refuses
to open its binaries. After the checksum passes, and only then, remove the
mark from the three binaries:

```text
xattr -dr com.apple.quarantine bin
```

Keep the three binaries in `bin/` together: `tunnel-client` looks for
`tunnel-deadman` beside itself. Put `bin/` on your `PATH`, in each terminal you
use below:

```text
export PATH="$PWD/bin:$PATH"
tunnel-client --version
```

This prints `tunnel-client 0.1.0`. The heading of `tunnel-client --help` in
releases up to `f9f7abf` still reads "Agent Tunnel M1 connector" and calls
rotation and resume future work; that text is stale, and the client rotates its
data socket and reconnects by itself. In releases built after the D6 fix,
`--help` after any subcommand (for example `tunnel-client connect --help`)
prints the usage and exits `0`; older releases print it and exit `2`, so use
`tunnel-client --help` there.

## 2. Write the device profile

Keep the profile, key and certificates in their own owner-only directory,
outside any repository. Start from the example profile and put the relay CA the
operator sent beside it:

```text
mkdir -m 700 ~/agentuplink-device
cp examples/m1-client.toml ~/agentuplink-device/client.toml
cp /path/to/relay-ca.pem ~/agentuplink-device/relay-ca.pem
```

Edit `~/agentuplink-device/client.toml` and change **three values**, leaving
the rest of the example (credential paths, limits and rotation) as it is:

```toml
device_id = "<device UUID>"
relay_url = "wss://<relay host>:9443/v1/tunnel/control"

[exports."<service UUID>"]
type = "echo"
device_canary = "my-device"
```

`device_id` and the export's table name must be exactly the UUIDs the operator
gave you, or the relay refuses the device or every call. `device_canary` is
any short string; the echo returns it in front of your payload. Then:

```text
tunnel-client config check --config ~/agentuplink-device/client.toml
```

Expect `Runtime client configuration is valid.`

## 3. Create your key and certificate request

```text
tunnel-client credentials create --config ~/agentuplink-device/client.toml --csr-out device.csr
```

Paths in a profile, and paths given to `credentials`, resolve from the
profile's own directory. Expect `Created local credential request at
.../agentuplink-device/device.csr and private key at
.../agentuplink-device/credentials/device-key.pem.` The key is written
owner-only (`0600`) and the command never overwrites one. **Send the operator
`device.csr` only.** Keep `credentials/device-key.pem` on this computer.

## 4. Import your signed certificate

Save the certificate the operator sends back as
`~/agentuplink-device/device-cert.pem`, then:

```text
tunnel-client credentials import --config ~/agentuplink-device/client.toml --certificate device-cert.pem --server-ca relay-ca.pem
tunnel-client doctor --config ~/agentuplink-device/client.toml
```

Expect `Imported 1 client certificate(s) and 1 server CA certificate(s).`, then
`Local configuration, credential key match, permissions, and expiry are
healthy.` followed by `Supervisor IPC: not implemented in this operations
slice.`, and exit `0`. The second line is expected, not an error: the alpha has
no supervisor IPC. Add `--json` to `doctor` for the detail. `doctor` is
local only; it does not contact the relay.

`credentials import` refuses a certificate that is X.509 v1, has no device-role
URI SAN, names another device, or does not match your key, and says which.
Each one needs the operator to sign again ([operator.md section
2.1](operator.md#21-device-credentials)).

## 5. Connect

```text
tunnel-client connect --config ~/agentuplink-device/client.toml --json
```

It runs in the foreground. Within about a second it prints a line with
`"state":"ready"` and then a `connect-status` line with `"phase":"active"`.
Leave it running. Every 300 seconds it replaces its data socket, and the log
shows `preparing`, `quiescing`, `draining`, `retiring` and `active`. If the
network drops it reconnects by itself, with backoff that grows after repeated
drops (up to 60 seconds between attempts); `--no-reconnect` makes it exit on
the first failure instead. Ctrl-C stops it in an orderly way and it exits `0`.

The device dials out on TCP port 9443, so the network must allow that
outbound. When `connect` exits, its status says why
([runtime.md](runtime.md#client-exit-codes)):

| Exit | Code | What to do |
| --- | --- | --- |
| `7` | `OWNER_BUSY` | Another `connect` for this device is still running, here or on another computer. Stop it (`pgrep -fl "tunnel-client connect"`) and run again. After a relay crash the old session holds the device for up to 30 seconds |
| `3` | `CREDENTIAL_ERROR` | The relay refused this device's identity. Check `device_id` and the export UUID with the operator; they must match the catalog |
| `4` | `TRANSPORT_ERROR` | With `--no-reconnect`: the relay was unreachable or the session was lost. Check the URL, port 9443 and `relay-ca.pem` |
| `1` | `PROTOCOL_ERROR` | A version mismatch with the relay, or, in releases up to `f9f7abf`, a known defect after a network stall with a request in flight ("STREAM_FORGET terminal proof did not converge before its deadline"; fixed on `main` by M6-C105, awaiting verification). Run `connect` again; a service manager should restart it on exit `1` |

## 6. Call the echo

The consumer side can be any machine that has `relay-ca.pem` and a token. Read
the token without echoing it, so it stays out of your shell history and off a
shared screen, then call the device's echo service:

```text
read -rs TOKEN
curl --cacert ~/agentuplink-device/relay-ca.pem \
  -H "Authorization: Bearer $TOKEN" --data-binary hello \
  https://<relay host>/v1/devices/<device UUID>/services/<service UUID>/echo
```

A working tunnel answers `200` with the device canary followed by the payload:
`my-devicehello`. Add `-w ' http=%{http_code}\n'` to see the status. On the
live relay the smoke check measured about 0.15 seconds per call from
Australia, including a fresh TLS handshake. Other answers:

| Status and code | Meaning |
| --- | --- |
| `503` `DEVICE_OFFLINE`, `"execution":"not_dispatched"` | The device is not connected. Start `connect` (section 5) |
| `401` | No token, or a token the relay did not accept: expired, wrong issuer, audience or key, or a `sub` with no catalog user |
| `403` | A valid token without `echo:invoke` in its `scope` (M6-C53). A relay built before M6-C53 answers `401` for this too; `main-77bfd28`, which served `agentuplink-relay.fly.dev` on 2026-09-25, is one |
| `404` `SERVICE_NOT_FOUND` | Wrong service UUID, or no grant for your user |
| `503` `RESOURCE_EXHAUSTED`, `"execution":"not_dispatched"` | Seen for about half a second at a data-socket rotation, every 300 seconds. The request never ran; repeat it (M6-C103) |
| `503` `REVERSE_CHANNEL_INTERRUPTED`, `"execution":"unknown"` | The connection broke with the request in flight, so it may or may not have run. Repeating an echo is harmless; for any service with side effects, check before repeating |
| curl error `60` | `--cacert` is missing or names the wrong CA |

## 7. When you are done

Stop `connect` with Ctrl-C and ask the operator to revoke your device. A
revoked device cannot be reactivated; a later test needs a new device UUID and
key. Delete `~/agentuplink-device` to remove the private key.
