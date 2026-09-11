# `tunnel-catalog`

This crate is the narrow durable catalog boundary for M1. It owns
tenant-qualified users, OIDC identities and memberships, devices, credentials,
services, grants, authorization revisions, and live owner fencing. It does not
own sockets, replay buffers, adapter state, payloads, private keys, or bearer
tokens.

The relay depends on `Arc<dyn Catalog>`:

```rust,ignore
let device = catalog.resolve_device(spki_fingerprint, wall_clock).await?;
let consumer = catalog.resolve_consumer(issuer, subject, Some(tenant_id)).await?;
let grant = catalog
    .authorize(&consumer, device_id, service_id, read_started_at, wall_clock)
    .await?;
let devices = catalog
    .list_devices_filtered(&consumer, &DeviceListFilter::default(), wall_clock)
    .await?;
```

`GrantSnapshot::valid_until` is no later than `read_started_at + 5s` and any
grant expiry. The relay should convert that wall-clock bound into its injected
monotonic deadline before queueing work. A cache hit retains the original
read-start bound.

## Redis authority

`RedisCatalog` uses one explicitly selected Redis primary as the authoritative
store. Construct it with:

```rust,ignore
let catalog = RedisCatalog::connect(redis_url, namespace).await?;
```

The low-level constructor intentionally remains transport-agnostic for the
disposable local test harness, which may use a loopback `redis://` URL. The
production `tunnel-relay serve` configuration validates the boundary before
connecting and requires `rediss://`; plaintext Redis is not a supported relay
deployment profile.

For a normal owner-enabled process, use
`RedisCatalog::connect_with_deployment_incarnation(redis_url, namespace, incarnation)`.
That constructor accepts only an already initialized active incarnation and
the same active Redis server run. It rejects missing metadata and any active
incarnation or Redis server run mismatch. A fresh namespace must use
`connect_for_recovery`, followed by `activate_deployment_incarnation()`, after
the operator has reviewed bootstrap or recovery. The durable namespace remains
the same across deployments; the deployment incarnation and Redis `run_id`
fence owner tokens after restart or restore. If Redis `run_id` changes, the
recovery operation also requires a new approved deployment incarnation; M1
does not infer safe rollback state from a backup.

The crate deliberately uses redis-rs `MultiplexedConnection`, without the
reconnecting `ConnectionManager`. Every connection acquisition and command is
bounded by two seconds. Redis errors are returned to the caller so relay
authorization and ownership fail closed during an authority outage, and no
command is ever replayed. A lane whose connection was lost reconnects only for
a later command, after repeating the startup PING/INFO identity check; a
primary whose `run_id` differs from the verified startup identity is refused
with a typed conflict, so a Redis restart, restore or promotion remains an
operator recovery event rather than a silent resume. Redis pub/sub is not part
of the authority path.

The catalog opens seven physical lanes to the primary: one catalog lane for
owner claim/release, tickets, membership and fixture pipelines; four
authorization lanes for `authorize`; and two maintenance lanes for the
relay's per-session `resolve_device` re-checks and `renew_owner` renewals.
A lane never serializes its callers. Its lock is held only across the
bounded probe or reconnect that verifies the physical connection; each
caller then runs its own command on that multiplexed connection, so
concurrent commands pipeline on one socket and the two-second deadline
(enforced both by redis-rs' per-command response timeout and by the catalog)
measures the authority's reply, never the time spent behind other callers.
A queueing delay therefore cannot surface as an authority timeout. A reply
that is genuinely later than two seconds fails that command closed with an
I/O `TimedOut` error (`RedisError::is_timeout()`), which the relay reports as
`timeout`; a severed connection fails with a connection-dropped I/O error,
reported as `redis_io`. Both release the lane so its next command
re-verifies the primary; neither replays the failed command. The relay bounds
how many sessions it maintains per tick (see `docs/cluster.md`), so the lane
count is a transport choice rather than a concurrency limit.

Owner lease comparisons and recovery quiescence checks use Redis server
`TIME`; a caller-side clock skew can fail an operation closed. Authorization
and credential expiry checks use the wall-clock instant supplied by the relay,
which must come from its trusted clock source and is bounded by the relay's
five-second authorization deadline.

Records are stored as per-tenant/device/user hashes with bounded indexes. Lua
scripts perform authorization snapshots, grant and revocation updates,
credential/device revocation, and owner claim/renew/release atomically. Device
epochs and grant revisions are canonical decimal strings and are incremented
with exact string arithmetic; Lua numeric doubles are never used for those
counters. Fixture cleanup is available only for names beginning with
`test-` or `fixture-` (or containing `-fixture-`) through
`cleanup_fixture_namespace()`.

`seed_fixture` is likewise restricted to those isolated fixture namespaces.
An atomic Redis reservation scans the namespace and permits one seed only when
it contains no catalog records. The reservation survives a partial seed and
rejects retries while records remain, so a failed or completed seed cannot be
retried in place. Explicit fixture teardown removes records and the
reservation last; a harness should still use a new namespace for each run.

OIDC verification is separate from catalog membership. `OidcVerifier` accepts
only operator-approved static RS256 or EdDSA keys, checks issuer, audience,
expiry, not-before, subject, and configured scopes, and then asks the catalog
to map `(issuer, subject, tenant)` to an active membership. JWT tenant claims
are ignored. `authenticate_for_scope` is the route helper for an explicit
scope such as `echo:invoke`; the resulting service grant remains required.
Approved RSA keys must be 2048–4096-bit public keys (PEM or JWK `n`/`e`) and
approved Ed25519 keys are the raw 32-byte public key; key material that does
not match its approved algorithm family, or an RSA key outside that range, is
rejected when the verifier is configured rather than failing every token at
request time. Signature verification uses jsonwebtoken's RustCrypto backend.

`MemoryCatalog` is available for pure unit tests and fixture wiring. Redis
integration coverage is intentionally ignored by the default workspace suite
because Redis is an external authority. The dedicated harness must provide a
disposable primary URL and runs it explicitly:

```text
TUNNEL_CATALOG_REDIS_URL=redis://127.0.0.1:6379 \
  cargo test -p tunnel-catalog --test redis_catalog --locked -- --ignored
```

A missing URL is a harness configuration error; the test is never converted
to a passing skip. Each run uses a unique fixture namespace and cleans it up
through the guarded cleanup method.
