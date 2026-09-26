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
# The C11/OG-02 diagnostics gates label captures with bounded safe identifiers only.
if [ -z "${C11_SOURCE_ID:-}" ]; then
  export C11_SOURCE_ID="git-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
fi
if [ -z "${C11_BUILD_ID:-}" ]; then
  export C11_BUILD_ID="local-$(date -u +%Y%m%dT%H%M%SZ)"
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

gate "catalog authority lane reconnect tests" \
  cargo test -p tunnel-catalog --test redis_lane_reconnect --locked -- --ignored --test-threads=1
gate "catalog maintenance queue tests" \
  cargo test -p tunnel-catalog --test redis_maintenance_queue --locked -- --ignored --test-threads=1

# The live-catalog Redis restart gate owns its own pinned loopback Redis and
# restarts that process while one catalog stays connected to it, so it does not
# touch TEST_REDIS_URL.  It requires Docker and must run from the repository root.
gate "live-catalog Redis process restart refuses a changed run identifier" \
  bash scripts/m7-redis-lane-restart-verify.sh

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
gate "membership re-sign re-binding tests (M7-C80/C83)" \
  cargo test -p tunnel-relay --test m7_membership_resign --locked -- --test-threads=1
gate "relay membership persistence tests" \
  cargo test -p tunnel-relay --test m7_membership_persistence --locked -- --test-threads=1
gate "configured relay process Redis TLS and checkpoint acceptance" \
  cargo test -p tunnel-test-harness --test m7_deployment_process --locked -- --ignored --test-threads=1
gate "configured relay dependency restore and fresh authenticated echo" \
  cargo test -p tunnel-test-harness --test m7_deployment_dependency_restore --locked -- --ignored --test-threads=1
gate "configured relay dynamic SPKI replacement" \
  cargo test -p tunnel-test-harness --test m7_deployment_spki_replacement --locked -- --ignored --test-threads=1
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
gate "M7 EC-044 reordered, duplicate and late frames through a real peer forward" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-ec044-peer-frames
gate "M7 reserved control delivery and frame ordering on one saturated non-owner-ingress route" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-saturated-peer-frames
gate "M7 Redis-backed cluster acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-cluster
gate "M7 production relay acceptance" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-production
gate "M7 synthetic Echo through actual CLI same-owner rotations" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i08-synthetic-rotation
gate "M7 partly delivered maximum-size synthetic response across same-owner rotations" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i08-partial-response-rotation
gate "M7 planned retirement and unexpected active-carrier recovery/failure" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i08-rotation-faults
gate "M7 three failed recovery attempts and second-attempt recovery" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i08-recovery-attempts
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
gate "M7 long-lived peer stream across same-key and back-to-back membership re-signs" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-resign-stream
gate "M7 membership convergence from the bounded refresh with the hint dropped" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-membership-hint-drop
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
gate "M7 bounded multi-fault chaos classification" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-chaos
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
gate "M7 exhausted and recovered same-session recovery attempts" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i08-recovery-attempts
gate "M7 real Redis owner lease expiry without renewal" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-owner-lease-expiry
gate "M7 remote-route body-limit boundaries through non-owner ingress" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-remote-body-limits

gate "M7 admission framing and control-record boundaries" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-admission-framing
gate "M7 GOAWAY-driven rotation through actual CLI" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-i08-goaway-rotation
gate "M7 late DATA/FIN receipt after selected peer fault" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-side-effect-late
gate "M7 public abandoned upgrade reclamation" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-public-abandoned-upgrade
gate "M7 EC-041 device data ticket race across two ingress relays" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-ec041-device-attachment
gate "M7 EC-023 owner death during control and data admission" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-ec023-owner-death
gate "M7 EC-025 cross-relay handover under peer grace and owner readiness" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-ec025-handover
gate "M7 C11 payload-free diagnostics capture and mutation scan" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-c11-diagnostics
gate "M7 OG-02 correlation completeness across fault gates" \
  cargo run --locked -p tunnel-test-harness -- verify-m7-og02-correlation

echo "m7-harness-verify: implemented M7 harness suite passed" >&2
