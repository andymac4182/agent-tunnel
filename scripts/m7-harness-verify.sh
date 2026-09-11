#!/bin/sh
set -eu

# Keep Cargo configuration supplied by the caller intact.  In particular,
# CARGO_HOME, CARGO_TARGET_DIR, RUSTFLAGS, and offline/cache settings are not
# replaced by this script.
if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m7-harness-verify: TEST_REDIS_URL is required for a disposable Redis primary." >&2
  exit 2
fi

if [ -z "${TUNNEL_CATALOG_REDIS_URL:-}" ]; then
  export TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
fi

gate() {
  label=$1
  shift
  echo "m7-harness-verify: ${label}" >&2
  "$@"
}

gate "build locked workspace binaries" \
  cargo build --locked --workspace --bins

gate "Redis catalog integration tests" \
  cargo test -p tunnel-catalog --test redis_catalog --locked -- --ignored --test-threads=1
gate "opaque identity byte bounds and Redis key isolation" \
  cargo test -p tunnel-catalog --test redis_scope_isolation --locked -- --ignored --test-threads=1
gate "duplicate service identities reject without namespace mutation" \
  cargo test -p tunnel-catalog --test redis_duplicate_service --locked -- --ignored --test-threads=1
gate "isolated authorization and owner reads during a held Redis reply" \
  cargo test -p tunnel-catalog --test redis_authorize_concurrency --locked -- --ignored --test-threads=1
gate "same-authority concurrent catalog lease and ticket operations" \
  cargo test -p tunnel-catalog --test redis_concurrent_authority --locked -- --ignored --test-threads=1
gate "committed owner write with lost reply is not replayed" \
  cargo test -p tunnel-catalog --test redis_authority_lost_reply --locked -- --ignored --test-threads=1
gate "Redis cluster integration tests" \
  cargo test -p tunnel-catalog --test redis_cluster --locked -- --ignored --test-threads=1
gate "Redis recovery integration tests" \
  cargo test -p tunnel-catalog --test redis_recovery --locked -- --ignored --test-threads=1
gate "Redis recovery-race integration tests" \
  cargo test -p tunnel-catalog --test redis_recovery_races --locked -- --ignored --test-threads=1

gate "operator recovery CLI tests" \
  cargo test -p tunnel-relay --test recovery_cli --locked -- --test-threads=1
gate "operator recovery workflow tests" \
  cargo test -p tunnel-relay --test recovery_workflow --locked -- --ignored --test-threads=1

gate "operator namespace backup rollback recovery" \
  cargo test -p tunnel-relay --test recovery_backup_rollback --locked -- --ignored --test-threads=1

gate "relay readiness tests" \
  cargo test -p tunnel-relay --test m7_readiness --locked -- --test-threads=1
gate "relay binary startup tests" \
  cargo test -p tunnel-relay --test m7_startup --locked -- --test-threads=1
gate "relay health endpoint tests" \
  cargo test -p tunnel-relay --test m7_health_endpoints --locked -- --test-threads=1
gate "relay membership persistence tests" \
  cargo test -p tunnel-relay --test m7_membership_persistence --locked -- --test-threads=1
gate "configured relay process Redis TLS and checkpoint acceptance" \
  cargo test -p tunnel-test-harness --test m7_deployment_process --locked -- --ignored --test-threads=1
gate "configured relay bootstrap fault matrix" \
  cargo test -p tunnel-test-harness --test m7_deployment_failures --locked -- --ignored --test-threads=1
gate "configured relay runtime dependency loss and liveness" \
  cargo test -p tunnel-test-harness --test m7_deployment_runtime_faults --locked -- --ignored --test-threads=1

gate "configured relay Redis connection and command-stage faults" \
  cargo test -p tunnel-test-harness --test m7_deployment_redis_stages --locked -- --ignored --test-threads=1
gate "configured relay fresh checkpoint refresh and persisted restart fences" \
  cargo test -p tunnel-test-harness --test m7_checkpoint_refresh_process --locked -- --ignored --test-threads=1

gate "configured relay approved peer port binding" \
  cargo test -p tunnel-test-harness --test m7_deployment_port_binding --locked -- --ignored --test-threads=1
gate "configured relay full-quiescence recovery" \
  cargo test -p tunnel-test-harness --test m7_recovery_process --locked -- --ignored --test-threads=1

gate "live signed membership tests" \
  cargo test -p tunnel-test-harness --test m7_live_membership --locked -- --test-threads=1
gate "live membership boot replacement tests" \
  cargo test -p tunnel-test-harness --test m7_live_membership_boot_replacement --locked -- --test-threads=1
gate "privileged RPC analogue tests" \
  cargo test -p tunnel-test-harness --test m7_privileged_rpc --locked -- --test-threads=1

gate "M7 transport acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-transport
gate "M7 authenticated peer body fragmentation and malformed records" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-peer-fragmentation
gate "M7 Redis-backed cluster acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-cluster
gate "M7 production relay acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-production
gate "M7 synthetic Echo through actual CLI same-owner rotations" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i08-synthetic-rotation
gate "M7 planned retirement and unexpected active-carrier recovery/failure" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i08-rotation-faults
gate "M7 public negative-admission acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-admission
gate "M7 live device credential revocation" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-device-revocation
gate "M7 consumer credential expiry during active rotation" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-credential-expiry-rotation
gate "M7 peer-key revocation during rotation acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-key-rotation
gate "M7 signed peer trust expiry after a missed invalidation hint" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-trust-expiry
gate "M7 peer-route readiness loss and recovery acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-peer-readiness
gate "M7 occupied peer capacity and admitted-stream survival" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-peer-capacity
gate "Owner-local stream capacity and reclamation" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-owner-local-capacity
gate "M7 concurrent owner claims and stale cleanup acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-owner-contention
gate "M7 Redis TLS acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-redis-tls
gate "M7 Redis partition acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-redis-partition
gate "M7 process-pause acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-process-pause
gate "M7 resource-pressure acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-pressure
gate "M7 stalled consumer physical-write cleanup" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-lifecycle
gate "M7 selected-owner side-effect interruption without replay" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-side-effect

gate "M7 admitted append through owner loss with held sibling" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-owner-loss-effect

gate "M7 production timing boundaries" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-timing-boundaries
gate "M7 pending-owner admission and ready retry" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-pending-owner
gate "M7 successor owner readiness before body forwarding" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-successor-pending-owner
gate "M7 concurrent ingress and exact stream-cap admission" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-concurrent-load
gate "M7 fail-closed admission, readiness, routing and fallback matrix" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i04-fail-closed
gate "M7 configured message-queue saturation through non-owner ingress" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-queue-saturation
gate "M7 remote consumer ingress body and prefix limits" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-remote-body-limits
gate "M7 remote-route body-limit boundaries through non-owner ingress" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-remote-body-limits

echo "m7-harness-verify: implemented M7 harness suite passed" >&2
