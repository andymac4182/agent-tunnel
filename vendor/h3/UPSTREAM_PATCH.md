# Local h3 0.0.8 patch

Source is the locked crates.io h3 0.0.8 archive, checksum `10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be`, copied from the existing local Cargo registry. The upstream license and metadata are retained. Dependency versions are unchanged.

`Connection::wait_for_remote_goaway` exposes receipt of a validated remote GOAWAY while continuing normal control-frame and server-stream validation. It opens no synthetic request and leaves the connection open for admitted response streams. The Agent Tunnel driver uses this event to gate new requests, wait for retained stream leases, acknowledge GOAWAY, and join within its existing deadline.

The causal real HTTP/3 no-post-GOAWAY-open regression failed on unmodified h3/client driving with Timeout in0.91 seconds. Full patched validation is recorded in docs/m7-verification.md when complete.

Patch SHA-256: `272f33e58cdc95604f71b613088100d63066153f0ea1e91debe5b79c5f4ce7c4`.

`ConnectionError::is_remote_no_error_application_close` reports a remote QUIC
application close carrying code 0. `is_h3_no_error` accepts only the HTTP/3
`H3_NO_ERROR` code (0x100), while this crate and the relay close gracefully with
application code 0, and the `Remote` variant is otherwise reachable only behind
the third-party-backend feature. The peer driver needs that distinction to tell
a peer's clean shutdown during its own post-GOAWAY drain from a real protocol
failure, which always carries a defined 0x1xx code.

This vendored crate is not a workspace member, so it carries no runnable test of
its own; the accessor's behaviour is exercised through `tunnel-transport`.
