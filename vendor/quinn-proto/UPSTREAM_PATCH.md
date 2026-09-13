# Vendored `quinn-proto` 0.11.17 patch

This directory is a complete copy of the crates.io `quinn-proto` 0.11.17
package.  The source provenance is the local Cargo registry package at
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/quinn-proto-0.11.17`.
The version is unchanged.  The registry entry currently pinned by
`Cargo.lock` has checksum
`04759210543be93709136e28212294a659ef5001836ff4eab4d663e4529bba83`; applying
the local path patch will replace that registry source entry.  The upstream
license remains `MIT OR Apache-2.0`.

The only source change is in
`src/connection/streams/state.rs::StreamsState::queue_max_stream_id`: the
announcement threshold changes from `diff > max_concurrent / 8` to `diff > 0`.
When a peer has consumed its previously announced stream IDs, a completed
stream can therefore advertise one newly available ID immediately.  The old
hysteresis is unsafe for the tunnel's fixed stream ceiling: seven completions
at a configured limit of 128 leave `diff == 7`, below the old threshold of 16,
so the next H3 open can remain blocked indefinitely.

The tradeoff is more frequent `MAX_STREAMS` control frames when streams are
short-lived.  The patch does not raise a QUIC or application cap, add a
connection, or change a timeout.  The transport continues to own exactly the
configured application semaphore (8 or 128 in the regression), and the
regression proves a full connection still rejects its next open as typed
`PeerTransportError::Capacity` without server-side dispatch.
