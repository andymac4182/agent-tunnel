#!/usr/bin/env bash

# Restart one isolated, pinned Redis process while a single live catalog is
# held open against it, and require the catalog's authority lanes to refuse
# the changed primary with their typed run-identifier conflict.
#
# This script owns only the container it labels with the run ID, and it never
# touches the shared development Redis: the harness command connects to the
# fixed loopback port published below.  The harness owns every catalog write
# and every assertion; this script owns the process restart.

set -euo pipefail

readonly REDIS_IMAGE="redis:8.4.0-alpine@sha256:6cbef353e480a8a6e7f10ec545f13d7d3fa85a212cdcc5ffaf5a1c818b9d3798"

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'the live-catalog Redis restart gate requires Docker' >&2
    exit 1
fi
if ! command -v uuidgen >/dev/null 2>&1; then
    printf '%s\n' 'the live-catalog Redis restart gate requires uuidgen' >&2
    exit 1
fi

readonly RUN_ID="$(uuidgen | tr -d '-')"
readonly CONTAINER_NAME="agent-tunnel-m7-lane-restart-${RUN_ID}"
readonly CONTAINER_LABEL="agent-tunnel.lane-restart-owner=${RUN_ID}"
readonly NAMESPACE="m7-lane-restart-fixture-${RUN_ID}"
readonly HANDSHAKE_FILE="${LANE_RESTART_HANDSHAKE_FILE:-${TMPDIR:-/tmp}/agent-tunnel-m7-lane-restart-${RUN_ID}.handshake}"

container_started=0
harness_pid=""

cleanup() {
    if [[ -n "${harness_pid}" ]] && kill -0 "${harness_pid}" 2>/dev/null; then
        kill "${harness_pid}" 2>/dev/null || true
        wait "${harness_pid}" 2>/dev/null || true
    fi
    rm -f "${HANDSHAKE_FILE}" "${HANDSHAKE_FILE%.handshake}.tmp" 2>/dev/null || true
    if [[ "${container_started}" != 1 ]]; then
        return
    fi
    # The name is generated above and the label check prevents this trap from
    # removing a container that a separate process happens to have created.
    local owner_label
    owner_label="$(docker inspect --format '{{index .Config.Labels "agent-tunnel.lane-restart-owner"}}' "${CONTAINER_NAME}" 2>/dev/null || true)"
    if [[ "${owner_label}" == "${RUN_ID}" ]]; then
        docker rm --force --volumes "${CONTAINER_NAME}" >/dev/null
    fi
}
trap cleanup EXIT

if [[ "${CONTAINER_NAME}" != agent-tunnel-m7-lane-restart-[0-9A-Fa-f]* ]]; then
    printf '%s\n' 'refusing an unexpected generated container name' >&2
    exit 1
fi

# The live catalog keeps one URL across the restart, so the published host
# port must be fixed rather than reassigned by Docker on restart.  A port
# found free by a probe can be taken by anything else on the host before
# Docker publishes it (task row M7-C119), so a publish refused with "address
# already in use" -- and only that -- is retried on a fresh port, a bounded
# number of times.  Nothing about the restart under test is retried.
pick_port() {
    python3 - <<'PY'
import socket

probe = socket.socket()
probe.bind(("127.0.0.1", 0))
print(probe.getsockname()[1])
probe.close()
PY
}

remove_owned_container() {
    local owner_label
    owner_label="$(docker inspect --format '{{index .Config.Labels "agent-tunnel.lane-restart-owner"}}' "${CONTAINER_NAME}" 2>/dev/null || true)"
    if [[ "${owner_label}" == "${RUN_ID}" ]]; then
        docker rm --force --volumes "${CONTAINER_NAME}" >/dev/null
    fi
}

REDIS_PORT=""
for publish_attempt in 1 2 3 4 5; do
    candidate_port="$(pick_port)"
    if [[ -z "${candidate_port}" ]]; then
        printf '%s\n' 'could not reserve a loopback port for the fixture Redis' >&2
        exit 1
    fi
    # From here the container may exist, so the exit trap must remove it.
    container_started=1
    # This disposable fixture disables Redis protected mode inside the
    # container; the published listener remains bound to 127.0.0.1 and
    # contains only synthetic data.
    if run_error="$(docker run --detach \
        --name "${CONTAINER_NAME}" \
        --label "${CONTAINER_LABEL}" \
        --publish "127.0.0.1:${candidate_port}:6379/tcp" \
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
        2>&1 >/dev/null)"; then
        REDIS_PORT="${candidate_port}"
        break
    fi
    if [[ "${run_error}" != *"address already in use"* ]]; then
        printf '%s\n' "${run_error}" >&2
        exit 1
    fi
    printf 'lane-restart: loopback port %s was taken before Docker published it (attempt %s); retrying on a fresh port\n' \
        "${candidate_port}" "${publish_attempt}" >&2
    remove_owned_container
done
if [[ -z "${REDIS_PORT}" ]]; then
    printf '%s\n' 'every probed loopback port was taken before Docker could publish it' >&2
    exit 1
fi
readonly REDIS_PORT

wait_for_redis() {
    local attempt
    for attempt in $(seq 1 60); do
        if docker exec "${CONTAINER_NAME}" redis-cli ping 2>/dev/null | grep -qx PONG; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if ! wait_for_redis; then
    printf '%s\n' 'Redis did not become ready' >&2
    exit 1
fi

readonly REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"

if [[ -n "${HARNESS_BIN:-}" ]]; then
    harness_command=("${HARNESS_BIN}")
else
    harness_command=(cargo run --locked -p tunnel-test-harness --)
fi

rm -f "${HANDSHAKE_FILE}"
"${harness_command[@]}" redis-lane-restart \
    --redis-url "${REDIS_URL}" \
    --namespace "${NAMESPACE}" \
    --handshake-file "${HANDSHAKE_FILE}" &
harness_pid=$!

# Wait for the harness to report that its single catalog is connected and
# verified against this Redis process.
connected=0
for _ in $(seq 1 600); do
    if [[ -f "${HANDSHAKE_FILE}" ]] && [[ "$(cat "${HANDSHAKE_FILE}" 2>/dev/null)" == "connected" ]]; then
        connected=1
        break
    fi
    if ! kill -0 "${harness_pid}" 2>/dev/null; then
        break
    fi
    sleep 1
done
if [[ "${connected}" != 1 ]]; then
    printf '%s\n' 'the harness never reported a connected live catalog' >&2
    wait "${harness_pid}" || true
    harness_pid=""
    exit 1
fi

# The restart is the whole point of this gate: the same container's Redis
# process is replaced, so the primary comes back with a new run identifier on
# the same fixed loopback port.
docker restart "${CONTAINER_NAME}" >/dev/null
if ! wait_for_redis; then
    printf '%s\n' 'Redis did not become ready after the restart' >&2
    exit 1
fi

printf 'restarted' >"${HANDSHAKE_FILE}.writing"
mv "${HANDSHAKE_FILE}.writing" "${HANDSHAKE_FILE}"

set +e
wait "${harness_pid}"
harness_status=$?
set -e
harness_pid=""
if [[ "${harness_status}" != 0 ]]; then
    printf 'live-catalog Redis restart gate failed with status %s\n' "${harness_status}" >&2
    exit "${harness_status}"
fi

printf 'live-catalog Redis process restart acceptance passed\n'
