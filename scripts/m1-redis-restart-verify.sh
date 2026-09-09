#!/usr/bin/env bash

# Run the Redis durability acceptance fixture against one isolated, pinned
# Redis container. The harness owns all catalog writes; this script owns only
# the container it labels with the run ID.

set -euo pipefail

readonly REDIS_IMAGE="redis:8.4.0-alpine@sha256:6cbef353e480a8a6e7f10ec545f13d7d3fa85a212cdcc5ffaf5a1c818b9d3798"

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'redis restart acceptance requires Docker' >&2
    exit 1
fi
if ! command -v uuidgen >/dev/null 2>&1; then
    printf '%s\n' 'redis restart acceptance requires uuidgen' >&2
    exit 1
fi

readonly RUN_ID="$(uuidgen | tr -d '-')"
readonly CONTAINER_NAME="agent-tunnel-m1-redis-restart-${RUN_ID}"
readonly CONTAINER_LABEL="agent-tunnel.redis-restart-owner=${RUN_ID}"
readonly NAMESPACE="m1-redis-restart-fixture-${RUN_ID}"
readonly RECEIPT_FILE="${REDIS_RESTART_RECEIPT_FILE:-${TMPDIR:-/tmp}/agent-tunnel-m1-redis-${RUN_ID}.json}"

container_started=0

cleanup() {
    if [[ "${container_started}" != 1 ]]; then
        return
    fi

    # The name is generated above and the label check prevents this trap from
    # removing a container that a separate process happens to have created.
    local owner_label
    owner_label="$(docker inspect --format '{{index .Config.Labels "agent-tunnel.redis-restart-owner"}}' "${CONTAINER_NAME}" 2>/dev/null || true)"
    if [[ "${owner_label}" == "${RUN_ID}" ]]; then
        docker rm --force --volumes "${CONTAINER_NAME}" >/dev/null
    fi
}
trap cleanup EXIT

if [[ "${CONTAINER_NAME}" != agent-tunnel-m1-redis-restart-[0-9A-Fa-f]* ]]; then
    printf '%s\n' 'refusing an unexpected generated container name' >&2
    exit 1
fi

# Docker forwards the host loopback port through its bridge. This disposable
# fixture disables Redis protected mode inside the container; the published
# listener remains bound to 127.0.0.1 and contains only synthetic data.
docker run --detach \
    --name "${CONTAINER_NAME}" \
    --label "${CONTAINER_LABEL}" \
    --publish "127.0.0.1::6379/tcp" \
    --memory 256m \
    --cpus 1.0 \
    --pids-limit 64 \
    --ulimit nofile=1024:1024 \
    "${REDIS_IMAGE}" \
    redis-server \
    --appendonly yes \
    --appendfsync always \
    --aof-load-truncated no \
    --save "" \
    --maxmemory 64mb \
    --maxmemory-policy noeviction \
    --protected-mode no \
    --bind 0.0.0.0 \
    >/dev/null
container_started=1

redis_port=""
for _ in {1..60}; do
    if redis_port="$(docker port "${CONTAINER_NAME}" 6379/tcp 2>/dev/null | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')" && [[ -n "${redis_port}" ]]; then
        break
    fi
    sleep 1
done
if [[ -z "${redis_port}" ]]; then
    printf '%s\n' 'Redis did not publish a loopback port' >&2
    exit 1
fi

redis_url="redis://127.0.0.1:${redis_port}"
for _ in {1..60}; do
    if docker exec "${CONTAINER_NAME}" redis-cli ping 2>/dev/null | grep -qx PONG; then
        break
    fi
    sleep 1
done
if ! docker exec "${CONTAINER_NAME}" redis-cli ping 2>/dev/null | grep -qx PONG; then
    printf '%s\n' 'Redis did not become ready' >&2
    exit 1
fi

if [[ -n "${HARNESS_BIN:-}" ]]; then
    harness_command=("${HARNESS_BIN}")
else
    harness_command=(cargo run --locked -p tunnel-test-harness --)
fi

"${harness_command[@]}" redis-restart-seed \
    --redis-url "${redis_url}" \
    --namespace "${NAMESPACE}" \
    --receipt-file "${RECEIPT_FILE}"

docker restart "${CONTAINER_NAME}" >/dev/null
for _ in {1..60}; do
    if docker exec "${CONTAINER_NAME}" redis-cli ping 2>/dev/null | grep -qx PONG; then
        break
    fi
    sleep 1
done
if ! docker exec "${CONTAINER_NAME}" redis-cli ping 2>/dev/null | grep -qx PONG; then
    printf '%s\n' 'Redis did not become ready after restart' >&2
    exit 1
fi

# Docker may assign a new host port when restarting a random-port mapping.
redis_port="$(docker port "${CONTAINER_NAME}" 6379/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')"
if [[ -z "${redis_port}" ]]; then
    printf '%s\n' 'Redis did not republish its loopback port after restart' >&2
    exit 1
fi
redis_url="redis://127.0.0.1:${redis_port}"

"${harness_command[@]}" redis-restart-check \
    --redis-url "${redis_url}" \
    --namespace "${NAMESPACE}" \
    --receipt-file "${RECEIPT_FILE}"

printf 'Redis AOF restart acceptance passed; receipt: %s\n' "${RECEIPT_FILE}"
