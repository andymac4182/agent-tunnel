# Local h3 0.0.8 patch

Source is the locked crates.io h3 0.0.8 archive, checksum `10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be`, copied from the existing local Cargo registry. The upstream license and metadata are retained. Dependency versions are unchanged.

`Connection::wait_for_remote_goaway` exposes receipt of a validated remote GOAWAY while continuing normal control-frame and server-stream validation. It opens no synthetic request and leaves the connection open for admitted response streams. The Agent Tunnel driver uses this event to gate new requests, wait for retained stream leases, acknowledge GOAWAY, and join within its existing deadline.

The causal real HTTP/3 no-post-GOAWAY-open regression failed on unmodified h3/client driving with Timeout in0.91 seconds. Full patched validation is recorded in docs/m7-verification.md when complete.

Patch SHA-256: `272f33e58cdc95604f71b613088100d63066153f0ea1e91debe5b79c5f4ce7c4`.
