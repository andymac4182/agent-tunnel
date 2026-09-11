# Recovery CLI wiring

The reviewed recovery implementation lives in `crates/tunnel-relay/src/recovery.rs`, with the
workflow input, redacted output, and typed error types re-exported from the
relay library. The commands below are deliberately separate from ordinary
`serve`, which never opens the recovery fence.

## Commands

The relay should expose three separate operator commands:

```text
relay recovery-initialize --config CONFIG
relay recovery-observe --config CONFIG
relay recover --config CONFIG --approval PATH --expected-nonce NONCE \
  --acknowledgement-id ID --old-primary-fenced --old-relays-fenced
```

`recovery.fence_path` in the checked configuration is the sole source of the
approval-version fence path.  The commands must not add a competing
`--fence` override that could select a different authority file at runtime.

`recovery-initialize` is the only command allowed to call
`RecoveryApprovalVersionStore::bootstrap`.  It must be a deliberate
create-only operation in the deployment owner directory.  `recover` calls
`open`; it fails closed for a missing, corrupt, identity-mismatched, insecure,
or busy fence and never creates or resets one.  Ordinary `serve` uses the
membership version state path and does not open the recovery fence.
`recovery-observe` is read-only and does not open the fence or trust-key file.
The fence identity is `(cluster.deployment_id,
redis.namespace)`, so changing the candidate deployment incarnation does not
reset the approval high-water mark.

`recovery-observe` is read-only.  It connects with
`RedisCatalog::connect_for_recovery` or
`connect_for_recovery_with_tls`, calls `observe_durable_catalog`, and prints
only `redis_run_id`, `catalog_digest`, `catalog_generation`, `key_count`,
`byte_count`, deployment identifiers, and `quiescence: "unproven"`.  It must
not open the fence, read approval or trusted-key files, call an activation
method, or claim that Redis observation proves an old-primary or relay has
stopped.

`recover` requires all of the following operator inputs:

* `--expected-nonce` is a fresh challenge supplied by the external recovery
  authority.  The command must not derive it from the signed approval file.
* The deployment ID, Redis namespace, candidate deployment incarnation, and
  Redis URL come from the checked configuration.  They must match the signed
  approval policy; an approval cannot select them.
* `--approval` is a bounded, canonical signed approval file.  The trusted
  public-key document is a separate owner-provisioned file outside Redis; it
  contains only key IDs and public keys.  Unknown/private-key fields are
  rejected.
* The two fencing flags and acknowledgement ID are an explicit operator
  declaration that the old primary and relays were fenced.  They are required
  before activation, but remain a declaration rather than proof.  Redis cannot
  prove quiescence from a read-only observation.

## Ordering and failure semantics

The command must perform this sequence without reordering:

1. Validate bounded arguments and the quiescence declaration.
2. Open the existing local approval-version fence.
3. Connect to the candidate Redis authority without activating its
   incarnation and obtain a fresh bounded durable-catalog observation.
4. Verify the signed approval against the configured deployment and namespace,
   observed Redis `run_id`, candidate incarnation, fresh catalog digest,
   externally supplied nonce, validity window, trusted external public keys,
   and the fence's current highest version.
5. Persist the approval version with temp-file write, file fsync, atomic rename,
   and parent-directory fsync.  A persistence error leaves admission closed
   and must not call Redis activation.
6. Call
   `RedisCatalog::activate_deployment_incarnation_with_approval` exactly once.
   That API rechecks the live run ID, digest, watched generation, and live
   owner leases before its bounded `EXEC`.

If durable fence persistence succeeds and activation fails or returns an
unknown outcome, the version is consumed.  The command must report that the
operator needs observation/reconciliation and a fresh higher approval.  It
must never automatically retry the same signed approval or roll the fence
back.  The `recovery-observe` result is diagnostic only and must not be used as
an authorization cache.

The synchronous fence and control-file operations are bounded to the
recovery-file size limits. `recovery.rs` runs each prepare and
persistence phase in a supervised `spawn_blocking` task and joins its handle
after a timeout; a timeout cannot leave an outstanding rename that races a
later activation.  If a caller drops the outer recovery future, Tokio may
detach the join handle, but the task retains the cloned fence store and its
stable sidecar lock until the operation completes.  A production CLI that
needs cancellation to wait for completion must own the workflow in a
supervisor and run it to completion.  The catalog calls already have bounded
observation and activation deadlines and do not reconnect after an authority
error.

## Config and trust boundary

The linked `main.rs`/`config.rs` wiring adds a dedicated recovery config
section with `fence_path`, `trusted_keys_path`, and the Redis authority/TLS
material selected for the recovery command. Do not reuse the membership
version state path or membership signer trust path for these controls.  The
trusted-key file and fence must be provisioned in owner-private directories;
the module rejects symlink components, non-regular files, broad permissions,
oversized input, and replacement races.  The Redis URL is necessarily used to
connect to the authority and may contain operator credentials, so config debug
and error paths must redact it.  Private signing keys and catalog payloads are
never read or stored by this workflow.  The relay stores only the bounded
approval version and stable deployment/namespace identity.

## Dedicated Redis workflow tests

The executable `tests/recovery_workflow.rs` cases assert through the public
`recover` workflow that:

* a valid approval persists its version before the activation call, and a
  persistence failure leaves the catalog untouched;
* a catalog activation failure leaves the consumed version durable, so a
  restart rejects the same approval and requires a fresh higher version; and
* a held or unknown `EXEC` response reports an ambiguous outcome, retains the
  durable version fence, and never retries the same approval automatically.

The binary-level `tests/recovery_cli.rs` cases cover strict argument rejection,
create-only initialization, missing-fence fail-closed recovery, and the
read-only observation boundary using a loopback connection fixture.
