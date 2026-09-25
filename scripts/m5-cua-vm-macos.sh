#!/usr/bin/env bash
# M5 CUA disposable macOS VM on an Apple Silicon Mac, via Tart.
#
# SAFETY. Every screen capture and every input event happens INSIDE the guest.
# This script never starts cua-computer-server, a VNC server, a screenshot tool
# or a tunnel CUA export on the macOS host, and nothing here asks the host to
# grant Screen Recording or Accessibility to anything. The guest's server is
# started by launchd inside the guest's `cua` session, binds 127.0.0.1 there,
# and the host reaches it only through an SSH forward over Tart's private NAT
# network. Screen content is the synthetic fixture app in tests/cua-fixture/.
#
# Two golden images, never run directly by this script:
#   cua-macos-golden         provisioned; the owner grants Screen Recording and
#                            Accessibility to the guest's Python.app ONCE, by hand
#                            (docs/testing.md, "Disposable macOS CUA VM")
#   cua-macos-golden-denied  cloned from cua-macos-golden before any grant, and
#                            never granted: the permission-denied variant
#
# Usage:
#   scripts/m5-cua-vm-macos.sh golden [--rebuild]      build both golden images
#   scripts/m5-cua-vm-macos.sh create NAME [--from golden|denied] [--display WxH(pt|px)]
#   scripts/m5-cua-vm-macos.sh run NAME                boot headless, start the fixture, wait until it is in front
#   scripts/m5-cua-vm-macos.sh probe NAME --expect granted|denied|record [OUTDIR]
#   scripts/m5-cua-vm-macos.sh manifest NAME
#   scripts/m5-cua-vm-macos.sh stop NAME
#   scripts/m5-cua-vm-macos.sh destroy NAME            stop and delete (refuses both golden images)
#   scripts/m5-cua-vm-macos.sh destroy-golden          delete both golden images and the cached base image
#   scripts/m5-cua-vm-macos.sh cycle NAME --from golden|denied --expect granted|denied|record [--display WxH(pt|px)]
#
# Environment: TART (default: tart on PATH), TART_HOME (default ~/.tart; the
# disk floor is checked on the filesystem holding it), M5_CUA_VM_STATE
# (default ~/.local/state/agentuplink-m5-cua-vm-macos) for the SSH key, logs
# and evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="${ROOT}/tests/cua-fixture"
TART="${TART:-tart}"
STATE="${M5_CUA_VM_STATE:-${HOME}/.local/state/agentuplink-m5-cua-vm-macos}"
TART_STORAGE="${TART_HOME:-${HOME}/.tart}"
TART_VERSION_PINNED="2.38.0"   # see scripts/m5-cua-vm.sh for the release digest

# Official Cirrus Labs image, pinned by digest. `macos-sequoia-base:latest`
# resolved to this on 2026-09-26 (uploaded 2026-09-05; 25.3 GB compressed,
# 50 GB sparse disk).
BASE_IMAGE="ghcr.io/cirruslabs/macos-sequoia-base@sha256:4947ac5ab1b2fdc46ab856132d2ba958f8e45b5f85192c66370dafc028c514dd"
GOLDEN="cua-macos-golden"
DENIED="cua-macos-golden-denied"
VM_CPU=4           # owner cap: at most 4 vCPU
VM_MEM_MB=8192     # owner cap: at most 8 GB
VM_DISK_GB=50      # the base image ships 50 GB (sparse); this script never grows it
# Points, so macOS drives the virtual display at a 2x backing scale
# (2560x1600 pixels): the non-identity scale M5-C19 needs. `create --display
# 1280x800px` gives an identity-scale clone.
VM_DISPLAY="1280x800pt"
MIN_FREE_GIB=20
SERVER_PORT=8000
AGENT_PREFIX=org.agentuplink

die() { echo "m5-cua-vm-macos: $*" >&2; exit 1; }
log() { echo "m5-cua-vm-macos: $*" >&2; }

[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || die "host must be an Apple Silicon Mac"
command -v "${TART}" >/dev/null || die "tart not found (see docs/testing.md, 'Disposable Linux CUA VM')"
tart_version="$("${TART}" --version 2>/dev/null || true)"
[ "${tart_version}" = "${TART_VERSION_PINNED}" ] \
  || die "tart ${tart_version:-unknown} is not the pinned ${TART_VERSION_PINNED}"

free_gib() {
  local dir="${TART_STORAGE}"
  while [ ! -d "${dir}" ]; do dir="$(dirname "${dir}")"; done
  df -k "${dir}" | awk 'NR==2 {print int($4 / 1048576)}'
}

CLEANUP=()
on_exit() {
  local i
  for ((i = ${#CLEANUP[@]} - 1; i >= 0; i--)); do
    ( eval "${CLEANUP[i]}" ) || true
  done
}
trap on_exit EXIT

disk_check() {
  local need="$1" free
  free="$(free_gib)"
  log "disk: ${free} GiB free, step may use ${need} GiB, floor ${MIN_FREE_GIB} GiB"
  [ $((free - need)) -ge "${MIN_FREE_GIB}" ] || die "aborting: free space would drop below ${MIN_FREE_GIB} GiB"
}

is_golden() { [ "$1" = "${GOLDEN}" ] || [ "$1" = "${DENIED}" ]; }
vm_exists() { "${TART}" list --quiet 2>/dev/null | grep -qx "$1"; }
vm_running() { "${TART}" list --format json | python3 -c 'import json,sys; n=sys.argv[1]; sys.exit(0 if any(v["Name"]==n and v["Running"] for v in json.load(sys.stdin)) else 1)' "$1"; }
base_cached() { "${TART}" list --format json | python3 -c 'import json,sys; n=sys.argv[1]; sys.exit(0 if any(v["Name"]==n for v in json.load(sys.stdin)) else 1)' "${BASE_IMAGE}"; }
gexec() { local vm="$1"; shift; "${TART}" exec "${vm}" "$@"; }
gexec_in() { local vm="$1"; shift; "${TART}" exec -i "${vm}" "$@"; }
# Run a command as root in the guest. The guest agent runs as the image's
# admin user, which has passwordless sudo.
groot() { local vm="$1"; shift; gexec "${vm}" sudo "$@"; }
cua_uid() { groot "$1" id -u cua; }

ssh_key() {
  mkdir -p "${STATE}"
  chmod 700 "${STATE}"
  [ -f "${STATE}/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C m5-cua-vm-macos -f "${STATE}/id_ed25519"
}

# The guest itself must say it is a VM before anything else runs in it: a
# second, independent check that `tart exec` did not reach the host.
assert_guest() {
  local vm="$1" v
  v="$(gexec "${vm}" sysctl -n kern.hv_vmm_present 2>/dev/null || true)"
  [ "${v}" = 1 ] || die "${vm}: kern.hv_vmm_present is '${v}', not 1; refusing"
}

boot() {
  local vm="$1"
  if ! vm_running "${vm}"; then
    mkdir -p "${STATE}/logs"
    nohup "${TART}" run --no-graphics "${vm}" >"${STATE}/logs/${vm}.tart.log" 2>&1 &
  fi
  local _ ok=0
  for _ in $(seq 1 240); do
    if gexec "${vm}" true 2>/dev/null; then
      ok=$((ok + 1))
      [ "${ok}" -ge 3 ] && { assert_guest "${vm}"; return 0; }
    else
      ok=0
    fi
    sleep 1
  done
  die "${vm}: guest agent did not come up"
}

# cua's Aqua session is up: loginwindow logged cua in, Finder and Dock run in
# its session, and no first-login Setup Assistant is on screen.
wait_session() {
  local vm="$1" uid _
  uid="$(cua_uid "${vm}")"
  for _ in $(seq 1 90); do
    if groot "${vm}" launchctl print "gui/${uid}" >/dev/null 2>&1 \
      && groot "${vm}" pgrep -u "${uid}" -x Dock >/dev/null 2>&1 \
      && groot "${vm}" pgrep -u "${uid}" -x Finder >/dev/null 2>&1; then
      if groot "${vm}" pgrep -u "${uid}" -f 'Setup Assistant.app' >/dev/null 2>&1; then
        die "${vm}: Setup Assistant is running in cua's session; the golden image is not ready"
      fi
      log "${vm}: cua's Aqua session is up"
      return 0
    fi
    sleep 2
  done
  die "${vm}: cua did not log in automatically"
}

window_state() {
  local vm="$1" uid
  uid="$(cua_uid "${vm}")"
  groot "${vm}" launchctl asuser "${uid}" sudo -u cua /opt/cua-server/bin/python /opt/cua-fixture/window-state-macos.py
}

# The fixture is up when it has written its state and the frontmost on-screen
# window at or above the normal layer is the fixture's, covering the whole
# screen, with nothing above it. Without a Screen Recording grant nothing in
# the guest can check the markers by capture, so this stacking check is the
# gate; with a grant, probe.py's marker gate checks the frame itself.
wait_fixture() {
  local vm="$1" _ ws
  for _ in $(seq 1 45); do
    if groot "${vm}" test -s /tmp/cua-fixture/state.json 2>/dev/null; then
      ws="$(window_state "${vm}" 2>/dev/null || true)"
      if [ -n "${ws}" ] && python3 - "${ws}" "$(groot "${vm}" pgrep -u "$(cua_uid "${vm}")" -f fixture_app.py | head -1)" <<'EOF'
import json, sys
ws, pid = json.loads(sys.argv[1]), int(sys.argv[2] or 0)
w, h = ws["screen_points"]
# Front-to-back list; ignore zero-alpha and zero-size helper windows.
visible = [x for x in ws["windows"] if x["alpha"] > 0 and x["bounds"][2] > 0 and x["bounds"][3] > 0]
top = next((x for x in visible if x["layer"] >= 0), None)
ok = top is not None and top["pid"] == pid and top["bounds"] == [0, 0, w, h]
sys.exit(0 if ok else 1)
EOF
      then
        log "${vm}: fixture is in front and covers the ${ws%%]*}] point screen"
        return 0
      fi
    fi
    sleep 2
  done
  [ -n "${ws:-}" ] && echo "${ws}" >&2
  die "${vm}: fixture did not come to the front full-screen"
}

# guest_detached VM NAME CMD TIMEOUT_S HOSTLOG: run CMD as root in the guest,
# detached from the `tart exec` stream, and poll for its exit status. Measured
# 2026-09-26: a single `tart exec` held open through the ~20-minute silent pip
# install ended with "unavailable (14): Transport became inactive", killing
# provisioning half-way; short polls do not depend on one long stream.
guest_detached() {
  local vm="$1" name="$2" cmd="$3" timeout="$4" hostlog="$5" waited=0 rc
  groot "${vm}" rm -f "/var/log/agentuplink-${name}.log" "/var/log/agentuplink-${name}.rc"
  groot "${vm}" bash -c "( ${cmd} >/var/log/agentuplink-${name}.log 2>&1; echo \$? >/var/log/agentuplink-${name}.rc ) </dev/null >/dev/null 2>&1 &"
  while ! groot "${vm}" test -s "/var/log/agentuplink-${name}.rc" 2>/dev/null; do
    [ "${waited}" -lt "${timeout}" ] || { log "${name}: no exit after ${timeout}s"; return 1; }
    sleep 10
    waited=$((waited + 10))
  done
  groot "${vm}" cat "/var/log/agentuplink-${name}.log" >"${hostlog}" 2>&1 || true
  rc="$(groot "${vm}" cat "/var/log/agentuplink-${name}.rc")"
  log "${name}: exit ${rc} after ~${waited}s"
  [ "${rc}" = 0 ]
}

copy_fixture() {
  local vm="$1"
  COPYFILE_DISABLE=1 tar -C "${FIXTURE}" -cf - fixture_app.py provision-guest-macos.sh guest-manifest-macos.sh \
      window-state-macos.py requirements-macos-arm64.lock \
    | gexec_in "${vm}" sudo bash -c 'rm -rf /opt/cua-fixture && mkdir -p /opt/cua-fixture && tar -C /opt/cua-fixture -xf - && chown -R root:wheel /opt/cua-fixture && chmod -R a+rX /opt/cua-fixture'
}

check_lock_matches_pin() {
  local pin="${ROOT}/crates/tunnel-http-forward/src/cua_pin.rs" lock="${FIXTURE}/requirements-macos-arm64.lock" h
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
  local rebuild="${1:-}" vm
  for vm in "${GOLDEN}" "${DENIED}"; do
    if vm_exists "${vm}"; then
      [ "${rebuild}" = "--rebuild" ] || die "${vm} exists; pass --rebuild to replace both golden images (this discards the owner's grants)"
    fi
  done
  for vm in "${DENIED}" "${GOLDEN}"; do
    vm_exists "${vm}" && { "${TART}" stop "${vm}" 2>/dev/null || true; "${TART}" delete "${vm}"; }
  done
  check_lock_matches_pin
  if base_cached; then disk_check 8; else disk_check 45; fi
  ssh_key
  "${TART}" clone "${BASE_IMAGE}" "${GOLDEN}"
  CLEANUP+=("cmd_stop $(printf %q "${GOLDEN}")")
  "${TART}" set "${GOLDEN}" --cpu "${VM_CPU}" --memory "${VM_MEM_MB}" --display "${VM_DISPLAY}"
  local disk
  disk="$("${TART}" get "${GOLDEN}" --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Disk"])')"
  [ "${disk}" -le "${VM_DISK_GB}" ] || die "base image disk is ${disk} GB, over ${VM_DISK_GB} GB"
  boot "${GOLDEN}"
  log "installing the probe SSH key for admin"
  gexec_in "${GOLDEN}" bash -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys' <"${STATE}/id_ed25519.pub"
  log "copying tests/cua-fixture into the guest"
  copy_fixture "${GOLDEN}"
  disk_check 3
  log "provisioning (python.org CPython, hash-locked cua-computer-server, cua user, launchd agents)"
  mkdir -p "${STATE}/logs"
  guest_detached "${GOLDEN}" provision "bash /opt/cua-fixture/provision-guest-macos.sh" 3600 \
    "${STATE}/logs/${GOLDEN}.provision.log" \
    || die "provisioning failed; see ${STATE}/logs/${GOLDEN}.provision.log"
  log "rebooting into cua's autologin session"
  groot "${GOLDEN}" shutdown -r now >/dev/null 2>&1 || true
  sleep 20
  boot "${GOLDEN}"
  wait_session "${GOLDEN}"
  groot "${GOLDEN}" bash /opt/cua-fixture/guest-manifest-macos.sh | tee "${STATE}/golden-manifest.json"
  "${TART}" stop "${GOLDEN}"
  # The denied variant is the golden image as it is now, before any grant.
  "${TART}" clone "${GOLDEN}" "${DENIED}"
  log "golden images ${GOLDEN} and ${DENIED} ready; $(free_gib) GiB free"
  log "NEXT (a person, at the VM's window): grant Screen Recording and Accessibility in ${GOLDEN} only;"
  log "  see docs/testing.md, 'Disposable macOS CUA VM', 'Owner: granting the permissions'"
}

# create NAME [--from golden|denied] [--display WxH(pt|px)]
cmd_create() {
  local vm="${1:?name}" from=golden display="" src
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --from) from="${2:?}"; shift 2 ;;
      --display) display="${2:?}"; shift 2 ;;
      *) die "create: unknown argument $1" ;;
    esac
  done
  case "${from}" in golden) src="${GOLDEN}" ;; denied) src="${DENIED}" ;; *) die "--from golden|denied" ;; esac
  is_golden "${vm}" && die "refusing to create over a golden image"
  vm_exists "${src}" || die "no ${src}; run 'golden' first"
  vm_exists "${vm}" && die "${vm} already exists"
  vm_running "${src}" && die "${src} is running; stop it before cloning"
  disk_check 3
  "${TART}" clone "${src}" "${vm}"
  [ -z "${display}" ] || "${TART}" set "${vm}" --display "${display}"
  mkdir -p "${STATE}/clones"
  printf 'from=%s\ndisplay=%s\n' "${src}" "${display:-${VM_DISPLAY}}" >"${STATE}/clones/${vm}"
}

cmd_run() {
  local vm="${1:?name}" uid
  is_golden "${vm}" && die "runs use a disposable clone, never a golden image"
  disk_check 2
  boot "${vm}"
  wait_session "${vm}"
  uid="$(cua_uid "${vm}")"
  groot "${vm}" rm -rf /tmp/cua-fixture
  groot "${vm}" launchctl kickstart -k "gui/${uid}/${AGENT_PREFIX}.cua-fixture"
  wait_fixture "${vm}"
  "${TART}" ip "${vm}"
}

permcheck() {
  local vm="$1" uid _
  uid="$(cua_uid "${vm}")"
  groot "${vm}" rm -f /tmp/cua-permcheck.json
  groot "${vm}" launchctl kickstart "gui/${uid}/${AGENT_PREFIX}.cua-permcheck"
  for _ in $(seq 1 30); do
    groot "${vm}" test -s /tmp/cua-permcheck.json 2>/dev/null && { groot "${vm}" cat /tmp/cua-permcheck.json; return 0; }
    sleep 1
  done
  die "${vm}: permission preflight did not report"
}

# start_server VM LABEL BACKEND ENV ARGS: the fixed variant, written as a
# root-owned file the launchd agent sources, then kickstarted in cua's session.
start_server() {
  local vm="$1" label="$2" backend="$3" envs="$4" sargs="$5" uid e
  uid="$(cua_uid "${vm}")"
  {
    printf 'LABEL=%q\nBACKEND=%q\nARGS=%q\nPORT=%q\n' "${label}" "${backend}" "${sargs}" "${SERVER_PORT}"
    for e in ${envs}; do printf 'export %q\n' "${e}"; done
  } | gexec_in "${vm}" sudo bash -c 'umask 022; cat >/etc/agentuplink-cua/server-run.sh && chown root:wheel /etc/agentuplink-cua/server-run.sh'
  groot "${vm}" launchctl kickstart -k "gui/${uid}/${AGENT_PREFIX}.cua-server"
  local _
  for _ in $(seq 1 60); do
    gexec "${vm}" curl -s -o /dev/null "http://127.0.0.1:${SERVER_PORT}/status" 2>/dev/null && return 0
    sleep 1
  done
  log "${label}: server did not answer; log follows"
  groot "${vm}" cat "/tmp/cua-server-${label}.log" >&2 || true
  return 1
}

stop_server() {
  local vm="$1" uid
  uid="$(cua_uid "${vm}")"
  groot "${vm}" launchctl kill SIGTERM "gui/${uid}/${AGENT_PREFIX}.cua-server" >/dev/null 2>&1 || true
  sleep 1
  groot "${vm}" pkill -u "${uid}" -f cua-computer-server >/dev/null 2>&1 || true
  sleep 1
}

# probe NAME --expect granted|denied|record [OUTDIR]
cmd_probe() {
  local vm="${1:?name}" expect="" out=""
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --expect) expect="${2:?}"; shift 2 ;;
      *) out="$1"; shift ;;
    esac
  done
  case "${expect}" in granted|denied|record) ;; *) die "probe: --expect granted|denied|record is required" ;; esac
  is_golden "${vm}" && die "probe a disposable clone, never a golden image"
  vm_running "${vm}" || die "${vm} is not running"
  disk_check 1
  ssh_key
  [ -n "${out}" ] || out="${STATE}/runs/${vm}-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "${out}"
  local ip lport
  ip="$("${TART}" ip "${vm}")"
  case "${ip}" in 192.168.64.*) ;; *) die "unexpected guest address ${ip}; expected Tart's private NAT network";; esac
  { echo "nonce=$(uuidgen) head=$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown) vm=${vm} expect=${expect}"
    cat "${STATE}/clones/${vm}" 2>/dev/null || true
    "${TART}" get "${vm}" --format json; } >"${out}/run.txt"

  groot "${vm}" bash /opt/cua-fixture/guest-manifest-macos.sh >"${out}/manifest.json"
  groot "${vm}" cat /tmp/cua-fixture/state.json >"${out}/fixture-state.json"
  window_state "${vm}" | python3 -m json.tool >"${out}/window-state.json"
  permcheck "${vm}" | python3 -m json.tool >"${out}/permcheck.json"

  local key
  key="$(gexec "${vm}" cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1, $2}')"
  case "${key}" in "ssh-ed25519 "?*) ;; *) die "could not read the guest's ed25519 host key";; esac
  echo "${ip} ${key}" >"${out}/known_hosts"

  lport="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
  ssh -i "${STATE}/id_ed25519" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="${out}/known_hosts" \
      -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes \
      -o LogLevel=ERROR -o ExitOnForwardFailure=yes -N \
      -L "127.0.0.1:${lport}:127.0.0.1:${SERVER_PORT}" "admin@${ip}" &
  local ssh_pid=$!
  CLEANUP+=("kill ${ssh_pid} 2>/dev/null")

  local listeners="" _
  for _ in $(seq 1 20); do
    kill -0 "${ssh_pid}" 2>/dev/null || die "ssh forward exited before listening"
    listeners="$({ lsof -nP -iTCP:"${lport}" -sTCP:LISTEN -t 2>/dev/null || true; } | sort -u | tr '\n' ' ')"
    [ -n "${listeners}" ] && break
    sleep 0.5
  done
  kill -0 "${ssh_pid}" 2>/dev/null || die "ssh forward is not running"
  [ "${listeners}" = "${ssh_pid} " ] \
    || die "port ${lport} listeners are '${listeners}', expected only the ssh forward ${ssh_pid}"

  # The permission expectation is checked against the preflight first: it is
  # the direct readout; the probe's frame and AX outcomes are the behaviour.
  local sr ax
  sr="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["screen_recording_preflight"])' "${out}/permcheck.json")"
  ax="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["accessibility_trusted"])' "${out}/permcheck.json")"
  log "preflight: screen_recording=${sr} accessibility=${ax}"
  case "${expect}" in
    granted) [ "${sr}/${ax}" = "True/True" ] || die "expected both grants; preflight says screen_recording=${sr} accessibility=${ax}" ;;
    denied) [ "${sr}/${ax}" = "False/False" ] || die "expected no grants; preflight says screen_recording=${sr} accessibility=${ax}" ;;
  esac

  local variant label backend envs sargs failed=0 rc
  # label|backend|env (space separated)|server args. No `vnc` variant: macOS
  # would need Screen Sharing enabled in the guest, which is not provisioned.
  for variant in \
      "native|native||" \
      "native-width640|native||--width 640 --height 400" \
      "native-503|native|UNAVAILABLE_WITHOUT_CONTAINER_NAME=1|" \
      "cua-driver|cua-driver||"; do
    IFS='|' read -r label backend envs sargs <<<"${variant}"
    log "probe ${label}"
    stop_server "${vm}"
    if ! start_server "${vm}" "${label}" "${backend}" "${envs}" "${sargs}"; then
      echo "{\"label\":\"${label}\",\"started\":false}" >"${out}/probe-${label}.json"
      groot "${vm}" cat "/tmp/cua-server-${label}.log" >"${out}/server-${label}.log" 2>/dev/null || true
      [ "${expect}" = record ] || failed=$((failed + 1))
      continue
    fi
    rc=0
    python3 "${FIXTURE}/probe.py" --base-url "http://127.0.0.1:${lport}" --label "${label}" \
      --permission-reads --out-dir "${out}" >"${out}/probe-${label}.json" || rc=$?
    groot "${vm}" cat "/tmp/cua-server-${label}.log" >"${out}/server-${label}.log" 2>/dev/null || true
    echo "${rc}" >"${out}/probe-${label}.rc"
    # exit 3: the frame is not the fixture (nothing of it kept). Under
    # --expect denied that IS the expected outcome; a verified fixture frame
    # there means the denied image can capture, which is the failure.
    case "${expect}/${rc}" in
      granted/0|denied/3|record/0|record/3) ;;
      denied/0)
        if grep -q '"fixture_markers_verified": true' "${out}/probe-${label}.json"; then
          log "${label}: DENIED image captured the fixture frame"; failed=$((failed + 1))
        fi ;;
      *) log "${label}: probe.py exit ${rc} under --expect ${expect}"; failed=$((failed + 1)) ;;
    esac
  done
  stop_server "${vm}"
  kill "${ssh_pid}" 2>/dev/null || true
  log "evidence in ${out}"
  echo "${out}"
  [ "${failed}" -eq 0 ] || die "${failed} probe variant(s) did not match --expect ${expect}"
}

cmd_manifest() { groot "${1:?name}" bash /opt/cua-fixture/guest-manifest-macos.sh; }
cmd_stop() { "${TART}" stop "${1:?name}" 2>/dev/null || true; }

cmd_destroy() {
  local vm="${1:?name}"
  is_golden "${vm}" && die "refusing to destroy ${vm}; use destroy-golden"
  vm_exists "${vm}" || { log "${vm} does not exist"; return 0; }
  "${TART}" stop "${vm}" 2>/dev/null || true
  "${TART}" delete "${vm}"
  vm_exists "${vm}" && die "${vm} still listed after delete"
  rm -f "${STATE}/clones/${vm}"
  log "${vm} deleted"
}

cmd_destroy_golden() {
  local vm
  for vm in "${DENIED}" "${GOLDEN}"; do
    "${TART}" stop "${vm}" 2>/dev/null || true
    vm_exists "${vm}" && "${TART}" delete "${vm}"
  done
  "${TART}" prune --entries caches --older-than 0 >/dev/null 2>&1 || true
}

# cycle NAME --from golden|denied --expect granted|denied|record [--display WxH(pt|px)]
cmd_cycle() {
  local vm="${1:?name}" from="" expect="" display=""
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --from) from="${2:?}"; shift 2 ;;
      --expect) expect="${2:?}"; shift 2 ;;
      --display) display="${2:?}"; shift 2 ;;
      *) die "cycle: unknown argument $1" ;;
    esac
  done
  [ -n "${from}" ] && [ -n "${expect}" ] || die "cycle needs --from and --expect"
  if [ -n "${display}" ]; then cmd_create "${vm}" --from "${from}" --display "${display}"
  else cmd_create "${vm}" --from "${from}"; fi
  local q
  q="$(printf %q "${vm}")"
  CLEANUP+=("cmd_stop ${q}; cmd_destroy ${q}")
  cmd_run "${vm}"
  cmd_probe "${vm}" --expect "${expect}"
  cmd_stop "${vm}"
  cmd_destroy "${vm}"
  "${TART}" list --quiet | grep -qx "${vm}" && die "${vm} survived the cycle"
  log "cycle complete: ${vm} created, probed and deleted; remaining: $("${TART}" list --quiet | tr '\n' ' ')"
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
  *) sed -n '2,32p' "$0"; exit 2 ;;
esac
