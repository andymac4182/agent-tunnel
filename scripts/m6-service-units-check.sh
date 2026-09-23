#!/bin/sh
# Task row M6-C23: check the example service units in examples/service/.
#
#   scripts/m6-service-units-check.sh                 # static checks
#   M6_SERVICE_LINUX_CLIENT=/path/to/linux/tunnel-client \
#     scripts/m6-service-units-check.sh --live        # plus a real systemd
#
# Static (needs `plutil`, which macOS has, and Docker for a Linux systemd):
#   * `plutil -lint` on the launchd plist;
#   * `systemd-analyze verify` on both systemd units, inside a Debian
#     container with systemd installed.  `verify` prints a warning and still
#     exits 0 for a setting it ignores, so the check requires exit 0 **and no
#     output**.
#   * Controls, so neither check is one that cannot fail: a copy of each unit
#     with a broken setting and a truncated plist must each be refused.
#
# Live (`--live`): boots systemd as PID 1 in a privileged container, installs
# tunnel-client.service unchanged apart from a check drop-in -- RestartSec=1s,
# and a privileged ExecStopPost that records systemd's own $SERVICE_RESULT,
# $EXIT_CODE and $EXIT_STATUS, because systemd drops an inactive unit's
# ExecMain* properties when it collects it -- and a Linux build of
# `tunnel-client`, and measures what the unit is for:
#   * against an unreachable relay the client stays active, backing off; a
#     `systemctl stop` then records ExecMainStatus=130 and Result=success
#     (SuccessExitStatus=130), and without that setting Result=exit-code;
#   * an invalid profile exits 2 and is **not** restarted
#     (RestartPreventExitStatus=2 3), and without that setting it is.
#
# The relay unit is checked statically only: running it needs Redis.
# `M6_SERVICE_KEEP=1` leaves the scratch directory and container for a look.
#
# Each check prints `m6-service-units: ok <name>` only after it ran; the
# script exits 1 on the first failure and 2 when a prerequisite is missing.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
units="$repo/examples/service"
image=${M6_SERVICE_IMAGE:-m6c23-systemd:local}
live=0
[ "${1:-}" = "--live" ] && live=1

fail() {
  echo "m6-service-units: FAILED $*" >&2
  exit 1
}
ok() {
  echo "m6-service-units: ok $*"
}

command -v plutil >/dev/null 2>&1 || { echo "m6-service-units: plutil is required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "m6-service-units: docker is required" >&2; exit 2; }

scratch=$(mktemp -d "${TMPDIR:-/tmp}/m6-service-units.XXXXXX")
container=""
cleanup() {
  [ -n "$container" ] && docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
[ -n "${M6_SERVICE_KEEP:-}" ] || trap cleanup EXIT

# --- launchd ---------------------------------------------------------------
plist="$units/local.agent-tunnel.tunnel-client.plist"
plutil -lint "$plist" >/dev/null || fail "plutil -lint $plist"
head -c 400 "$plist" > "$scratch/broken.plist"
if plutil -lint "$scratch/broken.plist" >/dev/null 2>&1; then
  fail "control: plutil accepted a truncated plist"
fi
ok "plutil -lint (and a truncated copy refused)"

# --- systemd, static -------------------------------------------------------
if ! docker image inspect "$image" >/dev/null 2>&1; then
  printf 'FROM rust:1.95.0\nRUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv >/dev/null && rm -rf /var/lib/apt/lists/*\n' \
    | docker build -q -t "$image" - >/dev/null
fi
cp "$units/tunnel-relay.service" "$units/tunnel-client.service" "$scratch/"
sed 's/^KillMode=mixed/KillMode=bogus/' "$units/tunnel-relay.service" > "$scratch/broken-relay.service"
sed 's/^RestartPreventExitStatus=2 3/RestartPreventExitStatus=two three/' \
  "$units/tunnel-client.service" > "$scratch/broken-client.service"
cmp -s "$units/tunnel-relay.service" "$scratch/broken-relay.service" && fail "control edit did not apply (relay)"
cmp -s "$units/tunnel-client.service" "$scratch/broken-client.service" && fail "control edit did not apply (client)"

verify() {
  # $1: unit file name inside $scratch.  Prints the combined output and
  # `exit=N`.
  docker run --rm -v "$scratch:/units:ro" "$image" sh -c "
    useradd -r agent-tunnel 2>/dev/null
    install -m 0755 /dev/null /usr/local/bin/tunnel-relay
    install -m 0755 /dev/null /usr/local/bin/tunnel-client
    cp /units/$1 /etc/systemd/system/$1
    systemd-analyze verify /etc/systemd/system/$1 2>&1; echo exit=\$?"
}
systemd_version=$(docker run --rm "$image" systemd-analyze --version | head -1)
for unit in tunnel-relay.service tunnel-client.service; do
  out=$(verify "$unit")
  [ "$out" = "exit=0" ] || fail "systemd-analyze verify $unit: $out"
  ok "systemd-analyze verify $unit ($systemd_version): exit 0, no output"
done
for unit in broken-relay.service broken-client.service; do
  out=$(verify "$unit")
  [ "$out" = "exit=0" ] && fail "control: verify accepted $unit silently"
  ok "control: verify refused $unit: $(echo "$out" | head -1)"
done

[ "$live" = 1 ] || exit 0

# --- systemd, live ---------------------------------------------------------
client=${M6_SERVICE_LINUX_CLIENT:-}
[ -n "$client" ] && [ -f "$client" ] || {
  echo "m6-service-units: --live needs M6_SERVICE_LINUX_CLIENT (a Linux tunnel-client)" >&2
  exit 2
}
cp "$client" "$scratch/tunnel-client"
container=$(docker run -d --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v "$scratch:/units:ro" "$image" /lib/systemd/systemd)
in_container() { docker exec "$container" sh -c "$1"; }
i=0
until in_container 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"'; do
  i=$((i + 1)); [ $i -lt 60 ] || fail "systemd did not boot in the container"; sleep 1
done
in_container '
  set -e
  useradd -r agent-tunnel
  install -m 0755 /units/tunnel-client /usr/local/bin/tunnel-client
  mkdir -p /etc/agent-tunnel/credentials && cd /etc/agent-tunnel/credentials
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -subj /CN=m6c23-service-check -keyout device-key.pem -out device-cert-chain.pem 2>/dev/null
  cp device-cert-chain.pem relay-ca.pem
  chmod 0700 /etc/agent-tunnel/credentials && chmod 0600 device-key.pem
  chown -R agent-tunnel:agent-tunnel /etc/agent-tunnel
  printf "device_id = \"m6c23-service-check\"\nrelay_url = \"wss://127.0.0.1:9/v1/tunnel/control\"\n[credentials]\nclient_certificate = \"credentials/device-cert-chain.pem\"\nclient_key = \"credentials/device-key.pem\"\nserver_ca = \"credentials/relay-ca.pem\"\n[exports.echo]\ntype = \"echo\"\ndevice_canary = \"x\"\n" > /etc/agent-tunnel/client.toml
  chown agent-tunnel /etc/agent-tunnel/client.toml
  cp /units/tunnel-client.service /etc/systemd/system/
  mkdir -p /etc/systemd/system/tunnel-client.service.d
  printf "[Service]\nExecStopPost=+/bin/sh -c \"echo result=\$SERVICE_RESULT code=\$EXIT_CODE status=\$EXIT_STATUS >> /run/m6c23-stoppost.log\"\nRestartSec=1s\n" > /etc/systemd/system/tunnel-client.service.d/10-check.conf
  systemctl daemon-reload
'

show() { in_container "systemctl show tunnel-client -p $1 --value"; }
# systemd drops an inactive unit's ExecMain* properties when it collects the
# unit, so the exit is read from the check drop-in's ExecStopPost record,
# which systemd fills from the real exit ($SERVICE_RESULT, $EXIT_STATUS).
last_exit() { in_container 'tail -1 /run/m6c23-stoppost.log'; }
now() { in_container 'date +%s'; }
wait_backoff() {
  # $1: label; $2: container time the start was issued at.  Only a backoff
  # event logged since then counts.
  i=0
  until in_container "journalctl -u tunnel-client --since @$2 --no-pager -o cat | grep -q '\"state\":\"backoff\"'"; do
    i=$((i + 1)); [ $i -lt 30 ] || fail "$1: no backoff event in the journal"; sleep 1
  done
}

# 1. Unreachable relay: active, backing off; stop -> 130 -> success.
since=$(now)
in_container 'systemctl start tunnel-client'
wait_backoff "unreachable relay" "$since"
[ "$(show ActiveState)" = active ] || fail "unreachable relay: not active while backing off"
before=$(date +%s)
in_container 'systemctl stop tunnel-client'
took=$(( $(date +%s) - before ))
exit_record=$(last_exit); state=$(show ActiveState)
[ "$exit_record" = "result=success code=exited status=130" ] && [ "$state" = inactive ] \
  || fail "stop during backoff: $exit_record state=$state"
ok "live: stop during backoff exits 130, Result=success, inactive (${took}s)"

# 1b. Control: without SuccessExitStatus the same stop is a failure.
in_container '
  printf "[Service]\nExecStopPost=+/bin/sh -c \"echo result=\$SERVICE_RESULT code=\$EXIT_CODE status=\$EXIT_STATUS >> /run/m6c23-stoppost.log\"\nRestartSec=1s\nSuccessExitStatus=\n" > /etc/systemd/system/tunnel-client.service.d/10-check.conf
  systemctl daemon-reload; systemctl reset-failed tunnel-client 2>/dev/null || true'
sleep 1
since=$(now)
in_container 'systemctl start tunnel-client'
wait_backoff "control start" "$since"
in_container 'systemctl stop tunnel-client' || true
exit_record=$(last_exit); state=$(show ActiveState)
[ "$exit_record" = "result=exit-code code=exited status=130" ] && [ "$state" = failed ] \
  || fail "control: without SuccessExitStatus: $exit_record state=$state"
ok "live: control without SuccessExitStatus=130 records Result=exit-code"

# 2. Invalid profile: exit 2, not restarted.
in_container '
  printf "[Service]\nExecStopPost=+/bin/sh -c \"echo result=\$SERVICE_RESULT code=\$EXIT_CODE status=\$EXIT_STATUS >> /run/m6c23-stoppost.log\"\nRestartSec=1s\n" > /etc/systemd/system/tunnel-client.service.d/10-check.conf
  cp /etc/agent-tunnel/client.toml /etc/agent-tunnel/client.toml.good
  sed -i "s#wss://#ws://#" /etc/agent-tunnel/client.toml
  systemctl daemon-reload; systemctl reset-failed tunnel-client 2>/dev/null || true
  systemctl start tunnel-client || true'
sleep 6
exit_record=$(last_exit); restarts=$(show NRestarts); state=$(show ActiveState)
[ "$exit_record" = "result=exit-code code=exited status=2" ] && [ "$restarts" = 0 ] && [ "$state" = failed ] \
  || fail "invalid profile: $exit_record restarts=$restarts state=$state"
ok "live: invalid profile exits 2, NRestarts=0, failed (RestartPreventExitStatus)"

# 2b. Control: without RestartPreventExitStatus it restarts.
in_container '
  printf "[Service]\nExecStopPost=+/bin/sh -c \"echo result=\$SERVICE_RESULT code=\$EXIT_CODE status=\$EXIT_STATUS >> /run/m6c23-stoppost.log\"\nRestartSec=1s\nRestartPreventExitStatus=\n" > /etc/systemd/system/tunnel-client.service.d/10-check.conf
  systemctl daemon-reload; systemctl reset-failed tunnel-client 2>/dev/null || true
  systemctl start tunnel-client || true'
sleep 6
restarts=$(show NRestarts)
[ "${restarts:-0}" -ge 1 ] || fail "control: without RestartPreventExitStatus NRestarts=$restarts"
ok "live: control without RestartPreventExitStatus restarts (NRestarts=$restarts)"
