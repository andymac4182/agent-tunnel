# M1 transport provenance and boundaries

This note records the transport choices implemented in `crates/tunnel-transport`.
It is deliberately scoped to reusable TLS, HTTP/1.1/HTTP/2, and bounded
private HTTP/3 foundations.  It does not make tenant, device, stream, or relay
routing decisions.

## Version and MSRV evidence

The package versions below were checked against the crates.io package metadata
and docs.rs pages on 2026-09-09.  The repository toolchain is Rust 1.95.0;
the highest published dependency MSRV observed in this set is below that
floor.  The exact pins live in the crate manifest so the workspace can
converge on one lockfile without silently floating transport behavior.

| package | pin | published MSRV observed | primary API/source |
| --- | --- | --- | --- |
| `axum` | `0.8.9` | 1.80 | <https://docs.rs/axum/0.8.9/axum/fn.serve.html> |
| `hyper` | `1.8.1` | 1.63 | <https://docs.rs/hyper/1.8.1/hyper/> |
| `hyper-util` | `0.1.20` | 1.64 | <https://docs.rs/hyper-util/0.1.20/hyper_util/> |
| `rustls` | `0.23.44` | 1.71 | <https://docs.rs/rustls/0.23.44/rustls/> |
| `tokio-rustls` | `0.26.4` | 1.71 | <https://docs.rs/tokio-rustls/0.26.4/tokio_rustls/> |
| `rustls-pemfile` | `2.2.0` | package metadata | <https://docs.rs/rustls-pemfile/2.2.0/rustls_pemfile/> |
| `tokio-tungstenite` | `0.30.0` | 1.85 | <https://docs.rs/tokio-tungstenite/0.30.0/tokio_tungstenite/> |
| `quinn` | `0.11.11` | 1.85 | <https://docs.rs/quinn/0.11.11/quinn/> |
| `h3` | `0.0.8` | 1.70 | <https://docs.rs/h3/0.0.8/h3/> |
| `h3-quinn` | `0.0.10` | 1.70 | <https://docs.rs/h3-quinn/0.0.10/h3_quinn/> |
| `x509-parser` | `0.17.0` | 1.67.1 | <https://docs.rs/x509-parser/0.17.0/x509_parser/> |

The manifest selects rustls' `ring` provider and Quinn's `rustls-ring` runtime
feature.  No custom crypto provider or unsafe platform boundary is introduced.

## TLS boundary

The PEM helpers construct TLS 1.3-only rustls configurations.  Server helpers
use `NoServerSessionStorage`, send no TLS 1.3 tickets, set
`max_early_data_size` to zero, and disable half-RTT data.  Client helpers use
`Resumption::disabled()` and set `enable_early_data` to false.  The HTTP/3
wrappers preserve those settings when converting to Quinn's rustls crypto
configuration.

`require_client_ca` builds a mandatory `WebPkiClientVerifier`; an empty or
malformed CA bundle fails configuration rather than falling back to anonymous
clients.  Device and relay-peer trust bundles are passed independently by the
caller.  CA validation authorizes certificate issuance, while
`ApprovedPeerPins` applies the separate current relay-key approval set for
private peer probes.

After rustls completes certificate and usage validation, the server extracts
the actual peer chain from the TLS connection.  The resulting `TlsIdentity` is
inserted into Axum request extensions.  No request header participates in this
metadata path.  The leaf identity contains:

* SPKI SHA-256 as `SpkiSha256`, rendered as lower-case hexadecimal by
  `to_hex()`;
* the leaf `notAfter` timestamp as signed Unix seconds;
* the parsed subject and all retained SAN values;
* exactly one role URI SAN: `urn:agent-tunnel:device:<device_id>` or
  `urn:agent-tunnel:peer:<node_id>`.

The URI SAN is a role hint and catalogue key.  The relay still must authorize
the fingerprint, role, and identifier against its durable credential record.
`TlsIdentity` has no public constructor, and its parser is crate-private, so a
caller cannot manufacture a verified identity by parsing an arbitrary leaf.
The public `spki_sha256_from_der` helper returns the distinct fingerprint type
and does not create a `TlsIdentity`.

## HTTP/1.1 and HTTP/2 supervisor

`serve` accepts a Tokio TCP listener, an Axum router, an `Arc<ServerConfig>`,
and a `CancellationToken`.  It bounds accepted TLS/HTTP connection tasks at 64
permits, applies a ten-second handshake deadline, and holds each permit until
the HTTP connection future finishes.  Cancellation stops accepting sockets,
asks active Hyper connections to drain, then joins every task.  HTTP/1.1 and
HTTP/2 are negotiated by ALPN; Hyper advertises at most 100 HTTP/2 streams per
connection, caps HTTP/2 header lists at 32 KiB, and caps HTTP/1 header count at
100.  Route handlers own request-body limits and upgraded WebSocket quotas.

## Bounded HTTP/3 proof

`PeerProbe` is intentionally a one-request body echo proof.  It requires
Quinn mutual TLS, a `peer` role URI, and an approved SPKI pin on both sides;
request and response bodies, connection count, and the overall exchange
deadline are bounded.  It does not implement relay routing, stream ownership,
replay handling, or recovery.  It also never invokes a Quinn 0-RTT API.

The transport API uses the `h3` and `h3-quinn` builder/driver interfaces from
their published 0.0.8/0.0.10 sources rather than relying on a private fork.
