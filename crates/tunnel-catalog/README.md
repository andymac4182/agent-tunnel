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
authorization and ownership fail closed during an authority outage. Redis
pub/sub is not part of the authority path.

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
