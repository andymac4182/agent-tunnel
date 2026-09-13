# Operator-configured Redis TLS

The relay can use an operator-installed Redis trust bundle and optional client
certificate for the authoritative catalog. The material stays in files and is
loaded at `serve` startup through `tunnel_relay::redis_connection::connect`;
the relay does not put PEM bytes, private keys, or credentials in Redis or
TOML.

The minimal top-level TOML fields are optional:

```toml
redis_url = "rediss://redis.example.test:6379/0"
redis_tls_root_ca_path = "/etc/agent-tunnel/redis/ca-chain.pem"
redis_tls_client_cert_path = "/etc/agent-tunnel/redis/relay-client-chain.pem"
redis_tls_client_key_path = "/etc/agent-tunnel/redis/relay-client-key.pem"
```

When all three fields are omitted, the existing M1 connection profile remains
in use. A root CA path may be supplied by itself to replace the default trust
roots. The client certificate and private key paths must be supplied together;
their pair enables Redis mTLS. Supplying any Redis TLS material selects the
verified `rediss://` profile and rejects `redis://` and the redis-rs
`#insecure` URL fragment before a connection is attempted.

Each PEM file is bounded to 1 MiB and must be a regular file with no symlink in
its path. On Unix, the client private-key file must be owner-only with mode
`0600`, matching the existing credential and persisted-state handling. The
loader reads the bytes into bounded catalog TLS options and never includes
paths, URLs, PEM data, or backend error details in `Debug` or user-facing
errors.

The startup integration passes the configured values as
`RedisTlsMaterialPaths`:

```rust
let redis_tls = RedisTlsMaterialPaths {
    root_ca_path: config.redis_tls_root_ca_path.clone(),
    client_cert_path: config.redis_tls_client_cert_path.clone(),
    client_key_path: config.redis_tls_client_key_path.clone(),
};
let catalog = tunnel_relay::redis_connection::connect(
    &config.redis_url,
    &config.redis_namespace,
    &config.deployment_incarnation,
    &redis_tls,
)
.await?;
```

The helper calls the existing no-material catalog constructor when the fields
are absent. With material configured it calls the catalog TLS constructor,
which performs the authenticated TLS handshake, PING/INFO startup check, and
deployment-incarnation fence before the relay starts serving.
