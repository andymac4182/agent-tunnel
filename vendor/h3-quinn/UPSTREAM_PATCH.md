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
