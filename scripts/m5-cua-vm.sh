#!/usr/bin/env bash
# M5 CUA disposable Linux VM on an Apple Silicon Mac, via Tart.
#
# SAFETY. Every screen capture and every input event happens INSIDE the guest.
# This script never starts cua-computer-server, a VNC server, a screenshot tool
# or a tunnel CUA export on the macOS host, and nothing here needs the host to
# grant Screen Recording or Accessibility to anything. The host reaches the
# guest's server only through an SSH forward to the guest's loopback, over
# Tart's private NAT network; the server itself binds 127.0.0.1 in the guest.
# Screen content is the synthetic fixture app in tests/cua-fixture/.
#
# Usage:
#   scripts/m5-cua-vm.sh golden [--rebuild]   build the golden image cua-golden
#   scripts/m5-cua-vm.sh create NAME          clone cua-golden -> NAME
#   scripts/m5-cua-vm.sh run NAME             boot NAME headless, wait for the X session
#   scripts/m5-cua-vm.sh probe NAME [OUTDIR]  read-only probe of every backend
#   scripts/m5-cua-vm.sh manifest NAME        print the per-run OS/display/package record
#   scripts/m5-cua-vm.sh stop NAME
#   scripts/m5-cua-vm.sh destroy NAME         stop and delete (refuses cua-golden)
#   scripts/m5-cua-vm.sh destroy-golden       delete cua-golden and its cached base image
#   scripts/m5-cua-vm.sh cycle [NAME]         create, run, probe, stop, destroy; proves disposability
#   scripts/m5-cua-vm.sh build-client OUTDIR  build the guest tunnel-client (--features cua) in a clone
#
# Environment: TART (default: tart on PATH), TART_HOME (Tart's storage, default
# ~/.tart; the disk floor is checked on the filesystem holding it),
# M5_CUA_VM_STATE (default ~/.local/state/agentuplink-m5-cua-vm) for the SSH
# key, logs and evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="${ROOT}/tests/cua-fixture"
TART="${TART:-tart}"
STATE="${M5_CUA_VM_STATE:-${HOME}/.local/state/agentuplink-m5-cua-vm}"
TART_STORAGE="${TART_HOME:-${HOME}/.tart}"
# The Tart release this was built and verified with: GitHub release asset
# tart.tar.gz SHA-256 1712be82b687cc27792d5a2bae3f36fcb5e5dea4d5772231f5508dea567999e2,
# signed "Developer ID Application: Cirrus Labs, Inc." Team ID 9M2P8L4D89.
TART_VERSION_PINNED="2.38.0"

# Official Cirrus Labs image, pinned by digest. `ubuntu:latest` resolved to
# this on 2026-09-25 (Ubuntu 24.04.4 LTS, arm64).
BASE_IMAGE="ghcr.io/cirruslabs/ubuntu@sha256:e1814edfeddabeaed5e6bdc646445c96701618d6a2a3d0fe993b0c2914417c07"
GOLDEN="cua-golden"
VM_CPU=4          # owner cap: at most 4 vCPU
VM_MEM_MB=4096    # owner cap: at most 4 GB
VM_DISK_GB=20     # the base image ships 20 GB; owner cap is 25 GB and this script never grows it
VM_DISPLAY="1280x800"
MIN_FREE_GIB=20   # other agents build in parallel; never go below this
SERVER_PORT=8000

die() { echo "m5-cua-vm: $*" >&2; exit 1; }
log() { echo "m5-cua-vm: $*" >&2; }

[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || die "host must be an Apple Silicon Mac"
command -v "${TART}" >/dev/null || die "tart not found (see docs/testing.md, 'Disposable Linux CUA VM')"
tart_version="$("${TART}" --version 2>/dev/null || true)"
[ "${tart_version}" = "${TART_VERSION_PINNED}" ] \
  || die "tart ${tart_version:-unknown} is not the pinned ${TART_VERSION_PINNED}"

# Free space on the filesystem that holds Tart's storage, where the golden
# image, clones and the OCI cache live (the nearest existing ancestor if
# TART_HOME has not been created yet).
free_gib() {
  local dir="${TART_STORAGE}"
  while [ ! -d "${dir}" ]; do dir="$(dirname "${dir}")"; done
  df -k "${dir}" | awk 'NR==2 {print int($4 / 1048576)}'
}

# Exit-time cleanup. Functions push commands; they run in reverse order on any
# exit, success or error, so a failed step never leaves a VM or forward behind.
CLEANUP=()
on_exit() {
  local i
  for ((i = ${#CLEANUP[@]} - 1; i >= 0; i--)); do
    # A subshell, so a `die` inside one cleanup cannot skip the rest.
    ( eval "${CLEANUP[i]}" ) || true
  done
}
trap on_exit EXIT

# disk_check NEED_GIB: abort unless NEED_GIB can be spent and MIN_FREE_GIB remains.
disk_check() {
  local need="$1" free
  free="$(free_gib)"
  log "disk: ${free} GiB free, step may use ${need} GiB, floor ${MIN_FREE_GIB} GiB"
  [ $((free - need)) -ge "${MIN_FREE_GIB}" ] || die "aborting: free space would drop below ${MIN_FREE_GIB} GiB"
}

# Not `grep -q`: under `pipefail` an early-exiting grep leaves `tart list`
# writing into a closed pipe, and the SIGPIPE makes an existing VM read as
# absent -- measured on 2026-09-26, when `destroy` of a demo clone printed
# "does not exist" and left it running (task row M5-C25).
vm_exists() { "${TART}" list --quiet 2>/dev/null | grep -x "$1" >/dev/null; }
vm_running() { "${TART}" list --format json | python3 -c 'import json,sys; n=sys.argv[1]; sys.exit(0 if any(v["Name"]==n and v["Running"] for v in json.load(sys.stdin)) else 1)' "$1"; }
gexec() { local vm="$1"; shift; "${TART}" exec "${vm}" "$@"; }
# gexec_in VM CMD...: as gexec, with the host's stdin attached (`tart exec -i`
# takes its flags before the VM name).
gexec_in() { local vm="$1"; shift; "${TART}" exec -i "${vm}" "$@"; }

ssh_key() {
  mkdir -p "${STATE}"
  chmod 700 "${STATE}"
  [ -f "${STATE}/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C m5-cua-vm -f "${STATE}/id_ed25519"
}

boot() {
  local vm="$1"
  if ! vm_running "${vm}"; then
    mkdir -p "${STATE}/logs"
    # Detached so the VM outlives this shell; `stop`/`destroy` end it.
    nohup "${TART}" run --no-graphics "${vm}" >"${STATE}/logs/${vm}.tart.log" 2>&1 &
  fi
  # The guest agent can answer once and then restart while first boot settles,
  # so require three consecutive answers a second apart.
  local _ ok=0
  for _ in $(seq 1 90); do
    if gexec "${vm}" true 2>/dev/null; then
      ok=$((ok + 1))
      [ "${ok}" -ge 3 ] && return 0
    else
      ok=0
    fi
    sleep 1
  done
  die "${vm}: guest agent did not come up"
}

wait_x() {
  local vm="$1" _
  for _ in $(seq 1 60); do
    # Up means the fixture has written its state AND a root capture inside the
    # guest shows its top-left red marker; a black root framebuffer is an
    # environment failure, not something to blame on a backend later.
    if gexec "${vm}" sudo test -s /tmp/cua-fixture/state.json 2>/dev/null \
      && gexec "${vm}" sudo -u cua env DISPLAY=:0 XAUTHORITY=/home/cua/.Xauthority \
        /opt/cua-server/bin/python -c 'from PIL import ImageGrab; import sys; sys.exit(ImageGrab.grab().getpixel((20, 20))[:3] != (255, 0, 0))' 2>/dev/null; then
      log "${vm}: X session up, fixture mapped, root capture shows the markers"
      return 0
    fi
    sleep 2
  done
  die "${vm}: X session / fixture did not start"
}

copy_fixture() {
  local vm="$1"
  COPYFILE_DISABLE=1 tar -C "${FIXTURE}" -cf - fixture_app.py provision-guest.sh guest-manifest.sh \
      requirements-linux-aarch64.lock requirements-build-linux-aarch64.lock \
    | gexec_in "${vm}" sudo bash -c 'rm -rf /opt/cua-fixture && mkdir -p /opt/cua-fixture && tar -C /opt/cua-fixture -xf - && chown -R root:root /opt/cua-fixture && chmod -R a+rX /opt/cua-fixture'
}

check_lock_matches_pin() {
  # The lock's two cua-computer-server hashes must be exactly the wheel and
  # sdist digests the M5-01 pin records.
  local pin="${ROOT}/crates/tunnel-http-forward/src/cua_pin.rs" lock="${FIXTURE}/requirements-linux-aarch64.lock" h
  for h in WHEEL_SHA256 SDIST_SHA256; do
    local d
    d="$(sed -n "s/^pub const ${h}: &str = \"\([0-9a-f]*\)\";/\1/p" "${pin}")"
    [ -n "${d}" ] || die "cannot read ${h} from cua_pin.rs"
    awk '/^cua-computer-server==/{f=1} f&&/--hash/{print} f&&/# via/{exit}' "${lock}" | grep -q "sha256:${d}" \
      || die "lock does not carry cua_pin ${h} ${d}"
  done
  grep -q '^cua-computer-server==0.3.46 ' "${lock}" || die "lock does not pin cua-computer-server==0.3.46"
}

cmd_golden() {
  local rebuild="${1:-}"
  if vm_exists "${GOLDEN}"; then
    [ "${rebuild}" = "--rebuild" ] || die "${GOLDEN} exists; pass --rebuild to replace it"
    "${TART}" stop "${GOLDEN}" 2>/dev/null || true
    "${TART}" delete "${GOLDEN}"
  fi
  check_lock_matches_pin
  disk_check 12   # ~5 GiB cached base image + ~5 GiB VM disk + packages
  ssh_key
  "${TART}" clone "${BASE_IMAGE}" "${GOLDEN}"
  # Stop the golden VM on every exit, including a failed provisioning step.
  CLEANUP+=("cmd_stop $(printf %q "${GOLDEN}")")
  "${TART}" set "${GOLDEN}" --cpu "${VM_CPU}" --memory "${VM_MEM_MB}" --display "${VM_DISPLAY}"
  local disk
  disk="$("${TART}" get "${GOLDEN}" --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Disk"])')"
  [ "${disk}" -le "${VM_DISK_GB}" ] || die "base image disk is ${disk} GB, over the ${VM_DISK_GB} GB cap"
  boot "${GOLDEN}"
  log "installing the probe SSH key for admin"
  gexec_in "${GOLDEN}" bash -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys' <"${STATE}/id_ed25519.pub"
  log "copying tests/cua-fixture into the guest"
  copy_fixture "${GOLDEN}"
  disk_check 3
  log "provisioning (apt, Xorg, openbox, hash-locked cua-computer-server)"
  gexec "${GOLDEN}" sudo bash /opt/cua-fixture/provision-guest.sh >"${STATE}/logs/${GOLDEN}.provision.log" 2>&1 \
    || die "provisioning failed; see ${STATE}/logs/${GOLDEN}.provision.log"
  gexec "${GOLDEN}" sudo systemctl reboot || true
  sleep 10
  boot "${GOLDEN}"
  wait_x "${GOLDEN}"
  gexec "${GOLDEN}" sudo bash /opt/cua-fixture/guest-manifest.sh | tee "${STATE}/golden-manifest.json"
  # Clean shutdown so clones start from a quiescent disk.
  gexec "${GOLDEN}" sudo rm -f /tmp/cua-fixture/state.json
  "${TART}" stop "${GOLDEN}"
  log "golden image ${GOLDEN} ready; $(free_gib) GiB free"
}

cmd_create() {
  local vm="${1:?name}"
  [ "${vm}" != "${GOLDEN}" ] || die "refusing to create over the golden image"
  vm_exists "${GOLDEN}" || die "no ${GOLDEN}; run 'golden' first"
  vm_exists "${vm}" && die "${vm} already exists"
  vm_running "${GOLDEN}" && die "${GOLDEN} is running; stop it before cloning"
  disk_check 2   # APFS clone: blocks are shared until the guest writes
  "${TART}" clone "${GOLDEN}" "${vm}"
}

cmd_run() {
  local vm="${1:?name}"
  [ "${vm}" != "${GOLDEN}" ] || die "runs use a disposable clone, never ${GOLDEN} itself"
  disk_check 1   # the guest's writes land in the clone's copy-on-write disk
  boot "${vm}"
  wait_x "${vm}"
  "${TART}" ip "${vm}"
}

# start_server VM LABEL BACKEND [ENV...] -- [SERVER ARGS...]
start_server() {
  local vm="$1" label="$2" backend="$3"; shift 3
  local envs=() args=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
  [ "${1:-}" = -- ] && shift
  args=("$@")
  gexec "${vm}" sudo -u cua env "${envs[@]+"${envs[@]}"}" setsid bash -c \
    "cua-server-start ${backend} ${SERVER_PORT} ${args[*]+"${args[*]}"} >/tmp/cua-server-${label}.log 2>&1 </dev/null &"
  local _
  for _ in $(seq 1 60); do
    gexec "${vm}" curl -s -o /dev/null "http://127.0.0.1:${SERVER_PORT}/status" 2>/dev/null && return 0
    sleep 1
  done
  log "${label}: server did not answer; log follows"
  gexec "${vm}" sudo cat "/tmp/cua-server-${label}.log" >&2 || true
  return 1
}

stop_server() {
  local vm="$1"
  gexec "${vm}" sudo pkill -u cua -f cua-computer-server 2>/dev/null || true
  gexec "${vm}" sudo pkill -u cua -x x11vnc 2>/dev/null || true
  sleep 1
}

cmd_probe() {
  local vm="${1:?name}" out="${2:-}"
  [ "${vm}" != "${GOLDEN}" ] || die "probe a disposable clone, never ${GOLDEN} itself"
  vm_running "${vm}" || die "${vm} is not running"
  disk_check 1
  ssh_key
  [ -n "${out}" ] || out="${STATE}/runs/${vm}-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "${out}"
  local ip lport
  ip="$("${TART}" ip "${vm}")"
  case "${ip}" in 192.168.64.*) ;; *) die "unexpected guest address ${ip}; expected Tart's private NAT network";; esac

  gexec "${vm}" sudo bash /opt/cua-fixture/guest-manifest.sh >"${out}/manifest.json"
  gexec "${vm}" sudo -u cua env DISPLAY=:0 XAUTHORITY=/home/cua/.Xauthority xdpyinfo \
    | awk '/dimensions:|resolution:/' >"${out}/xdpyinfo.txt"
  gexec "${vm}" cat /tmp/cua-fixture/state.json >"${out}/fixture-state.json"

  # Per-run known_hosts holding the guest's own host key, read over the
  # hypervisor channel (`tart exec`), so the SSH forward authenticates the
  # guest instead of trusting whatever answers at that address.
  local key
  key="$(gexec "${vm}" cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1, $2}')"
  case "${key}" in "ssh-ed25519 "?*) ;; *) die "could not read the guest's ed25519 host key";; esac
  echo "${ip} ${key}" >"${out}/known_hosts"

  # A free host loopback port, then forward it to guest 127.0.0.1:SERVER_PORT.
  lport="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
  ssh -i "${STATE}/id_ed25519" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="${out}/known_hosts" \
      -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes \
      -o LogLevel=ERROR -o ExitOnForwardFailure=yes -N \
      -L "127.0.0.1:${lport}:127.0.0.1:${SERVER_PORT}" "admin@${ip}" &
  local ssh_pid=$!
  CLEANUP+=("kill ${ssh_pid} 2>/dev/null")

  # Before any request: the forward must be alive and must be the ONLY listener
  # on that port. Anything else there (a race for the port, a stray host
  # service) would receive the probe instead of the guest.
  local listeners="" _
  for _ in $(seq 1 20); do
    kill -0 "${ssh_pid}" 2>/dev/null || die "ssh forward exited before listening"
    # lsof exits 1 while nothing listens yet; that is "not yet", not an error.
    listeners="$({ lsof -nP -iTCP:"${lport}" -sTCP:LISTEN -t 2>/dev/null || true; } | sort -u | tr '\n' ' ')"
    [ -n "${listeners}" ] && break
    sleep 0.5
  done
  kill -0 "${ssh_pid}" 2>/dev/null || die "ssh forward is not running"
  [ "${listeners}" = "${ssh_pid} " ] \
    || die "port ${lport} listeners are '${listeners}', expected only the ssh forward ${ssh_pid}"

  local variant label backend envs sargs failed=0
  # label|backend|env (space separated)|server args
  for variant in \
      "native|native||" \
      "native-width640|native||--width 640 --height 400" \
      "native-503|native|UNAVAILABLE_WITHOUT_CONTAINER_NAME=1|" \
      "vnc|vnc||" \
      "cua-driver|cua-driver||"; do
    IFS='|' read -r label backend envs sargs <<<"${variant}"
    log "probe ${label}"
    stop_server "${vm}"
    # shellcheck disable=SC2086
    if ! start_server "${vm}" "${label}" "${backend}" ${envs} -- ${sargs}; then
      echo "{\"label\":\"${label}\",\"started\":false}" >"${out}/probe-${label}.json"
      gexec "${vm}" sudo cat "/tmp/cua-server-${label}.log" >"${out}/server-${label}.log" 2>/dev/null || true
      continue
    fi
    python3 "${FIXTURE}/probe.py" --base-url "http://127.0.0.1:${lport}" --label "${label}" \
      --out-dir "${out}" >"${out}/probe-${label}.json" \
      || { log "${label}: probe.py failed (exit 3 = frame is not the fixture; nothing kept)"; failed=$((failed + 1)); }
    gexec "${vm}" sudo cat "/tmp/cua-server-${label}.log" >"${out}/server-${label}.log" 2>/dev/null || true
  done
  stop_server "${vm}"
  kill "${ssh_pid}" 2>/dev/null || true
  log "evidence in ${out}"
  echo "${out}"
  [ "${failed}" -eq 0 ] || die "${failed} probe variant(s) failed"
}

cmd_manifest() { gexec "${1:?name}" sudo bash /opt/cua-fixture/guest-manifest.sh; }

cmd_stop() { "${TART}" stop "${1:?name}" 2>/dev/null || true; }

cmd_destroy() {
  local vm="${1:?name}"
  [ "${vm}" != "${GOLDEN}" ] || die "refusing to destroy ${GOLDEN}; use destroy-golden"
  vm_exists "${vm}" || { log "${vm} does not exist"; return 0; }
  "${TART}" stop "${vm}" 2>/dev/null || true
  "${TART}" delete "${vm}"
  vm_exists "${vm}" && die "${vm} still listed after delete"
  log "${vm} deleted"
}

cmd_destroy_golden() {
  "${TART}" stop "${GOLDEN}" 2>/dev/null || true
  vm_exists "${GOLDEN}" && "${TART}" delete "${GOLDEN}"
  "${TART}" prune --entries caches --older-than 0 >/dev/null 2>&1 || true
}

cmd_cycle() {
  local vm="${1:-cua-run-1}"
  cmd_create "${vm}"
  # Whatever fails after the clone exists, stop and delete it.
  local q
  q="$(printf %q "${vm}")"
  CLEANUP+=("cmd_stop ${q}; cmd_destroy ${q}")
  cmd_run "${vm}"
  cmd_probe "${vm}"
  cmd_stop "${vm}"
  cmd_destroy "${vm}"
  vm_exists "${vm}" && die "${vm} survived the cycle"
  log "cycle complete: ${vm} created, probed and deleted; remaining: $("${TART}" list --quiet | tr '\n' ' ')"
}

# build-client OUTDIR: build tunnel-client (--features cua) and tunnel-deadman
# for aarch64-unknown-linux-gnu INSIDE a disposable clone, copy them to
# OUTDIR, and delete the clone. The clone's Ubuntu matches the guest's glibc.
# It downloads rustup and the pinned toolchain from the official Rust
# distribution inside the guest; crates come from the host's cargo registry
# (run `cargo fetch --locked` first), so the build itself is --offline.
cmd_build_client() {
  local out="${1:?output directory}" vm q
  mkdir -p "${out}"
  vm="cua-build-$(openssl rand -hex 3)"
  cmd_create "${vm}"
  q="$(printf %q "${vm}")"
  CLEANUP+=("cmd_stop ${q}; cmd_destroy ${q}")
  boot "${vm}"
  disk_check 3
  gexec "${vm}" bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh && sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.95.0 >/tmp/rustup.log 2>&1' \
    || die "rustup install failed in ${vm}"
  COPYFILE_DISABLE=1 tar -C "${HOME}/.cargo/registry" -cf - cache index \
    | gexec_in "${vm}" bash -c 'mkdir -p ~/.cargo/registry && tar -x -C ~/.cargo/registry 2>/dev/null'
  git -C "${ROOT}" archive --format=tar HEAD | gexec_in "${vm}" bash -c 'mkdir -p ~/src && tar -x -C ~/src'
  log "building in ${vm} (release, 3 jobs, nice 10; about 20 minutes)"
  gexec "${vm}" bash -c 'cd ~/src && CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 nice -n 10 ~/.cargo/bin/cargo build --offline --locked --release -p tunnel-client --features cua -p tunnel-deadman --bins' >"${STATE}/logs/${vm}.build.log" 2>&1 \
    || die "build failed; see ${STATE}/logs/${vm}.build.log"
  local b
  for b in tunnel-client tunnel-deadman; do
    gexec "${vm}" cat "/home/admin/src/target/release/${b}" >"${out}/${b}.tmp"
    chmod 0755 "${out}/${b}.tmp"
    mv "${out}/${b}.tmp" "${out}/${b}"
  done
  log "built from $(git -C "${ROOT}" rev-parse --short HEAD): $(cd "${out}" && shasum -a 256 tunnel-client tunnel-deadman | tr '\n' ' ')"
}

sub="${1:-}"; shift || true
case "${sub}" in
  golden) cmd_golden "$@" ;;
  create) cmd_create "$@" ;;
  run) cmd_run "$@" ;;
  probe) cmd_probe "$@" ;;
  manifest) cmd_manifest "$@" ;;
  stop) cmd_stop "$@" ;;
  destroy) cmd_destroy "$@" ;;
  destroy-golden) cmd_destroy_golden ;;
  cycle) cmd_cycle "$@" ;;
  build-client) cmd_build_client "$@" ;;
  *) sed -n '2,26p' "$0"; exit 2 ;;
esac
