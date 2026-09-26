# Demo: a relay re-keys its peer identity while it serves

This demo shows a serving `tunnel-relay serve` process swapping its private
HTTP/3 peer certificate and key **without a restart**. The relay stays Ready,
keeps its owner claim and its device session, and a public request that
enters one relay and is answered by a device on the other keeps working. The
path is always device → relay → consumer. The design is in
[cluster.md](../cluster.md#certificate-and-key-lifecycle) and the operator
procedure is in [operator.md §3.4](../operator.md#34-rotating-a-relays-peer-key-without-a-restart).
Task rows: M8-C45, M8-C46, M8-C24.

All data is synthetic. No key material is printed: every log line and
evidence line carries public SPKI digests only.

## Prerequisites

- Rust 1.95.0, as pinned in `rust-toolchain.toml`.
- A disposable Redis primary. The examples use `redis://127.0.0.1:63790/`.
  The demo writes only to its own random namespace and removes it afterwards.

```console
$ export TEST_REDIS_URL=redis://127.0.0.1:63790/
$ export TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
$ cargo build --locked -p tunnel-relay -p tunnel-client --bins
```

## 1. Two real relay processes, one re-keying on `SIGHUP`

```console
$ cargo test --locked -p tunnel-test-harness --test m8_relay_rekey_process \
    -- --ignored --nocapture
```

What it does, in order:

1. Starts relay A and relay B as separate `tunnel-relay serve` processes. They
   use a signed checkpoint authority and signed membership records in Redis.
   B's `[cluster]` section names a successor under `peer_tls_next_cert_chain`
   and `peer_tls_next_private_key`, with `peer_rekey_convergence_seconds = 4`.
2. Attaches a device to B and sends a public canary into A. A forwards it over
   the private HTTP/3 hop to B, and B forwards it to the device.
3. Sends B `SIGHUP` while `peer_tls_next_private_key` holds a key that does
   not match the successor certificate. B logs
   `peer rekey refused: peer identity private key does not match its certificate`
   and stages nothing. The gate then writes the right key and sends `SIGHUP`
   again. B logs
   `peer identity staged: staged_spki_sha256=<successor>`. Fresh handshakes
   still present the original key, because no signed record approves the
   successor yet. The gate checks this after both relays have reconciled at
   least twice more. That is a condition wait, not a fixed sleep.
4. Publishes B's record approving both keys. After the hold, B logs
   `peer identity switched`. Fresh handshakes now present the successor and no
   longer the original. The canary still works.
5. Publishes B's record approving only the successor. B logs
   `previous peer identity retired` with `cause="withdrawn"` and stays Ready.
   A reconnects to B under the new key, and the canary works again.

Expected final line (the digests and numbers vary from run to run):

```
m8-relay-rekey-process b_pid=4242->4242 old_spki=… new_spki=… … staged_logged=true staged(new=authentication old=accepted) switched(new=accepted old=authentication) switch_logged=true retired_logged=true retired(new=accepted old=authentication) canary(initial=true overlap=true after_retirement_attempts=1) b_ready_samples=… b_unready=0 … payload_free=true
test m8_serving_relay_rekeys_its_peer_identity_without_restart ... ok
```

`b_pid` is the same on both sides of the arrow, so B was never restarted, and
`b_unready=0` means B stayed Ready throughout its own rotation.

## 2. Against a live ACP stream on a three-relay cluster

```console
$ cargo run --locked -p tunnel-test-harness -- verify-m8-acp-cluster
```

The `genuine-peer-key-rotation` case re-keys the owner relay while a held ACP
turn and a flooded forwarded stream are live on the non-owner ingress. Look
for:

```
ACP cluster genuine peer-key rotation: staged_not_served=true switched=true … acp_survived_switch=true forward_survived_switch=true successor_presented=true predecessor_not_presented=true interrupted=true no_stop_reason=true ingress_reasons=["membership_revoked"] owner_reasons=[…] owner_unready=false retired_by_withdrawal=true post_rotation_turn=true resigned_on_successor=true
```

Both live streams keep serving across the switch. The held turn ends when the
predecessor is **withdrawn**, and the ingress attributes that to the key. The
relay does not yet GOAWAY-drain its inbound connections before retiring the
old key (M8-C47). The owner is not rotated back afterwards, because a retired
key cannot be restaged. The fixture adopts the successor, and a full re-sign
on it must leave the owner Ready.

Both gates also run from `scripts/m8-harness-verify.sh`.

## Failure recovery

- `TEST_REDIS_URL is required`: export it as shown above.
- `relay B did not present the expected identity`: B's stderr is printed with
  the error. `peer rekey refused: …` names why the successor was refused
  (key mismatch, different node, untrusted CA, or narrowed server names).
- If the host is heavily loaded, a timing bound can trip. Re-run when the
  load average is low. A failure under load is not evidence.
- Leftover namespaces: each run uses `m8-relay-rekey-fixture-<uuid>` and
  deletes it during cleanup. An interrupted run leaves that namespace behind,
  and it is safe to delete.
