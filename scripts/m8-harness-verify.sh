#!/bin/sh
set -eu

# M8 harness gates.  The ACP gates run over the M7 production cluster fixture
# (three in-process relays, real HTTP/3 peers, real device WebSockets) but
# prove M8 behavior, so they are registered here rather than in the M7, M4 or
# M3 suites.  Keep Cargo configuration supplied by the caller intact.
if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m8-harness-verify: TEST_REDIS_URL is required for a disposable Redis primary." >&2
  exit 2
fi

if [ -z "${TUNNEL_CATALOG_REDIS_URL:-}" ]; then
  export TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
fi

# The ACP gate starts the agent fixture by absolute path.  `cargo build` below
# puts it next to the harness binary, which is where the gate looks by
# default; this only has to be set when the caller has moved it.
if [ -n "${TUNNEL_ACP_FIXTURE_BIN:-}" ]; then
  export TUNNEL_ACP_FIXTURE_BIN
fi

gate() {
  label=$1
  shift
  echo "m8-harness-verify: ${label}" >&2
  "$@"
}

gate "build locked workspace binaries" \
  cargo build --locked --workspace --bins

# **What this gate does not claim.**  It re-signs membership only at case
# boundaries and at most every 15 s, which is a harness accommodation for the
# open defect M7-C80 — a same-key membership re-sign invalidates every peer
# admission and every stream riding it, and ACP is a long-lived SSE response
# through a non-owner ingress.  Nothing here shows an ACP connection surviving
# normal cluster operation.  The gate's own NOT_COVERED carries this too.
# **This gate is known to fail about one run in ten, and the failure is filed.**
# M8-C14: the consumer learns of a crashed turn either in ~50 ms or in ~58.7 s,
# bimodally, and the slow mode trips the gate's own hygiene invariant "every
# case ended inside the membership records' lifetime".  A red run showing
# `unknown_error_latency_ms` near 58700 with `export_ended_connection=true` and
# `live_connections=0` is that defect -- the export side is sound and the lost
# RESET is in the shared forwarding teardown path, not in ACP.
#
# A failure WITHOUT that signature is a NEW finding and must not borrow
# M8-C14's explanation.  The validator names M8-C14 only when the signature
# matches, so the two cannot be confused.  The invariant is deliberately NOT
# relaxed to make this gate green: it is what caught the defect.
gate "M8 ACP over three relays: a v1 conversation, permissions, cancellation, subscriber loss and an unknown outcome through a non-owner ingress" \
  cargo run --locked -p tunnel-test-harness -- verify-m8-acp-real-path

# **What this gate does and does not claim.**  Unlike the gate above, this one
# *does* carry two ACP sessions across three completed scheduled rotations, and
# asserts it.  That is possible because a scheduled **device data-socket**
# rotation and a cluster **membership re-sign** are different mechanisms and
# only the second is M7-C80: the consumer still enters at the non-owner
# relay-c, the peer hop is still crossed, and membership is simply not
# re-signed while the streams are live.  What it does not claim is a connection
# that outlives its membership record: a peer admission's deadline is never
# extended, so one record is the ceiling on a non-owner ingress either way, and
# the rotation case is bounded to finish inside it rather than escaping it.
#
# It also does not claim per-OS process-tree cleanup (macOS is the only host,
# and M8-C07's escaping descendant is not reached at all), any OS sandbox
# guarantee (the export is trusted-agent execution until a tested sandbox
# profile exists), or real-agent interoperability (the agent is this
# repository's own synthetic fixture).  The gate's own NOT_COVERED carries all
# of this, and the validator requires the evidence to carry it.
# The label distinguishes peer-**path** loss from peer-**key** rotation and
# names one saturated direction rather than two segments.  A label is evidence
# too -- it is what a reader sees when the gate passes.
#
# Chunk 7 adds the key rotation (M8-C16) and, with it, the reason the two are
# listed apart: a pin withdrawal governs new dials and leaves an in-flight
# stream serving, while the verifier dropping the old key tears it down.  The
# key arm's teardown is attributed by the product's own invalidation reason
# against a same-key control arm, not by the timing of the interruption.
#
# **What that key arm is, stated here because a label is what a reader sees.**
# The withdrawn key is the owner's OWN serving key and its replacement is a
# phantom no certificate presents, so the owner also fails closed and
# invalidates its own admission of the ingress.  The case attributes the
# INGRESS's decision and records both ends' reasons; which end closed the
# socket first is not shown, and a genuine rotation needs a fixture relay that
# re-keys.
#
# Simultaneity splits between the two hops.  The peer hop cannot show it at
# all: `record_exchange` fires at exchange termination and the hop publishes no
# live gauge, so its two figures are independent all-time latches (M8-C22).
# The owner-to-device segment does publish live per-direction gauges, and the
# gate asserts both directions carrying bytes at one coherent instant, sampled
# while the near-limit upload is still in flight.  An earlier version claimed
# the reverse for that segment; it had sampled only after the upload's POST
# returned, which on this profile means after the body had already arrived.
gate "M8 ACP across three relays: three completed rotations with two sessions live, two tenants reusing identical ids, forged heads, revocation, an owner-key withdrawal whose teardown the ingress attributes to the key rather than the record version, peer-path loss, owner loss, and the request direction of the ingress-to-owner hop driven against its credit window with both directions of the owner-to-device segment carrying bytes at one coherent instant" \
  cargo run --locked -p tunnel-test-harness -- verify-m8-acp-cluster

echo "m8-harness-verify: implemented M8 harness suite passed" >&2
