# Local h3-quinn patch

This directory is the crates.io `h3-quinn` 0.0.10 source with its upstream
MIT license retained. The workspace applies it through the root
`[patch.crates-io]` entry.

The upstream Quinn receive adapter moves its `quinn::RecvStream` into a
reusable boxed future while `poll_data` is pending. `stop_sending` and
`recv_id` then unwrap an empty `Option` when an HTTP/3 receive operation is
bounded by an idle timeout. This patch keeps the receive stream directly in
the adapter, polls Quinn's cancellation-safe `read_chunk` operation by
borrow, caches the H3 stream ID, and synchronously sends the requested stop
code. Repeated cancellation is idempotent and does not close the shared QUIC
connection or affect another H3 stream.

The public h3-quinn API and dependency versions remain unchanged. Keep this
patch until an upstream release provides the same cancellation guarantees;
then remove the local source and the root patch entry after rerunning the
blackhole, repeated-cancel, and independent-stream regressions.

## Upstream commit

`.cargo_vcs_info.json` records upstream `hyperium/h3` commit
`2dc3412bdf6083451920d5bfd7a9484d054c1859` ("h3-quinn v0.0.10 (#304)",
2025-05-06, the target of tag `h3-quinn-v0.0.10`), path `h3-quinn`. The file
is copied byte for byte from the published crate
(`h3-quinn-0.0.10.crate`, SHA-256
`8b2e732c8d91a74731663ac8479ab505042fbf547b9a207213ab7fbcbfc4f8b4`, equal to
the crates.io index checksum). It was then checked against the upstream
history rather than trusted: at that commit `h3-quinn/Cargo.toml` (this
directory's `Cargo.toml.orig`), `README.md` and `src/datagram.rs` are
byte-identical to this directory as git blobs, `h3-quinn/LICENSE` is a symlink
to the root `LICENSE` whose blob equals this directory's `LICENSE`, and
`src/lib.rs` equals the published crate's and differs from this directory's
only by the patch above. No later upstream commit touched `h3-quinn/` until
`18df8ce` (2025-11-02). docs/tasks.md M6-C02 records the measurement.

Upstream has since changed the same code path: `704b37a` ("Fix stop_sending
panic when recv stream is in-flight", #331) and `b986a53` ("allow checking
recv_id while a read is pending", #357). Neither is in a released h3-quinn
(the newest tag is `h3-quinn-v0.0.10`), so the removal condition above still
holds; re-check it when a release after 0.0.10 appears.
