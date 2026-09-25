#!/bin/sh
# The supervised CUA backend for the M5 Lane B demo. Runs INSIDE the Tart
# guest only, as the unprivileged `cua` user that owns the X session; the
# tunnel-client CUA export starts it (never a person, never on the host).
#
# usage: cua-backend-supervised.sh ADDRESS_FILE [BACKEND]
#
# The export's supervisor reads the backend's address from ADDRESS_FILE and
# refuses anything that is not loopback; the address is observed, never
# configured. So this wrapper picks a free guest-loopback port, starts the
# pinned cua-computer-server on it (through the image's cua-server-start),
# waits until /status answers, and only then publishes 127.0.0.1:PORT
# atomically. Publishing before the server listens would hand the supervisor
# a port that nothing (or something else) is bound to.
#
# The server stays this script's child, in the process group the supervisor
# signals, so the group kill and the deadman sentinel reach it.
set -eu

address_file="${1:?address file}"
backend="${2:-native}"

if [ "$(uname -s)" != Linux ] || [ ! -x /usr/local/bin/cua-server-start ]; then
  echo "refusing: cua-backend-supervised.sh runs only inside the cua-golden guest" >&2
  exit 2
fi

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
/usr/local/bin/cua-server-start "${backend}" "${port}" &
server=$!

up=0
for _ in $(seq 1 120); do
  if ! kill -0 "${server}" 2>/dev/null; then
    echo "cua-backend-supervised: server exited before listening" >&2
    exit 1
  fi
  if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${port}/status"; then
    up=1
    break
  fi
  sleep 0.5
done
[ "${up}" = 1 ] || { kill "${server}" 2>/dev/null; echo "cua-backend-supervised: /status never answered" >&2; exit 1; }

printf '127.0.0.1:%s' "${port}" >"${address_file}.tmp"
mv "${address_file}.tmp" "${address_file}"
wait "${server}"
