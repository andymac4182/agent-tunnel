#!/usr/bin/env bash
# M5 Lane B end-to-end demo: a consumer on the macOS host drives the synthetic
# fixture app inside a disposable Tart guest THROUGH A LOCAL RELAY.
#
#   consumer (host, curl HTTP/2) -> tunnel-relay (host) -> tunnel-client
#   (guest, --features cua, AGENT_TUNNEL_CUA_LANE_B=1) -> cua-computer-server
#   0.3.46 (guest loopback) -> Xorg + fixture app (guest)
#
# SAFETY. Every screen capture and every input event happens INSIDE the guest.
# Nothing on the host captures a screen or synthesises input, and nothing here
# needs the host to grant Screen Recording or Accessibility. The guest is a
# fresh clone of cua-golden, deleted on every exit. Input is sent only after
# a capture taken THROUGH THE TUNNEL shows the fixture's five markers, and the
# relay's consumer and device ports must each have the relay as their only
# listener before the first request (the same two gates scripts/m5-cua-vm.sh
# applies to its probe).
#
# Usage:
#   TEST_REDIS_URL=redis://127.0.0.1:63790/0 scripts/m5-cua-demo.sh [OUTDIR]
#
# Environment:
#   TEST_REDIS_URL     plaintext disposable Redis (a TLS terminator is put in
#                      front of it; relay serve requires rediss://)
#   GUEST_BIN_DIR      directory holding aarch64-unknown-linux-gnu
#                      tunnel-client (built --features cua) and tunnel-deadman
#   RELAY_BIN          host tunnel-relay (default: cargo build it)
#   TART               tart binary (default: tart on PATH; pinned 2.38.0)
#   KEEP_VM=1          do not delete the clone (for debugging only)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TART="${TART:-tart}"
VM_SCRIPT="${ROOT}/scripts/m5-cua-vm.sh"
TOOLS="${ROOT}/scripts/m5-cua-demo.py"
NONCE="$(openssl rand -hex 6)"
HEAD="$(git -C "${ROOT}" rev-parse --short HEAD)$(git -C "${ROOT}" diff --quiet || echo +dirty)"
VM="cua-demo-${NONCE}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/m5-cua-demo.${NONCE}.XXXX")"
OUT="${1:-${WORK}/evidence}"
RELAY_HOST="relay.cua-demo.test"
ISSUER="https://issuer.m5-cua-demo.invalid/"
AUDIENCE="agent-tunnel"
RECORDS="${ROOT}/examples/m6-catalog-cua.toml"
DEVICE="33333333-3333-4333-8333-333333333333"
SERVICE="77777777-7777-4777-8777-777777777777"
SUBJECT="trial-user"
NAMESPACE="m5-cua-demo-${NONCE}"
DEMO_TEXT="agentuplink-demo"

die() { echo "m5-cua-demo: $*" >&2; exit 1; }
log() { echo "m5-cua-demo: $*" >&2; }

: "${TEST_REDIS_URL:?TEST_REDIS_URL (a disposable plaintext Redis) is required}"
REDIS_HOSTPORT="${TEST_REDIS_URL#redis://}"; REDIS_HOSTPORT="${REDIS_HOSTPORT%%/*}"
REDIS_DB="${TEST_REDIS_URL##*/}"; [ -n "${REDIS_DB}" ] && [ "${REDIS_DB}" != "${TEST_REDIS_URL}" ] || REDIS_DB=0
: "${GUEST_BIN_DIR:?GUEST_BIN_DIR must hold aarch64 tunnel-client (--features cua) and tunnel-deadman}"
for bin in tunnel-client tunnel-deadman; do
  [ -x "${GUEST_BIN_DIR}/${bin}" ] || die "${GUEST_BIN_DIR}/${bin} is missing"
  file "${GUEST_BIN_DIR}/${bin}" | grep -q 'ELF 64-bit.*aarch64' || die "${bin} is not an aarch64 ELF"
done

mkdir -p "${OUT}"
echo "nonce=${NONCE} head=${HEAD} m5-cua-demo start $(date +%Y-%m-%dT%H:%M:%S%z) vm=${VM} namespace=${NAMESPACE}" | tee "${OUT}/run.txt" >&2

CLEANUP=()
on_exit() {
  local i
  for ((i = ${#CLEANUP[@]} - 1; i >= 0; i--)); do ( eval "${CLEANUP[i]}" ) || true; done
}
trap on_exit EXIT
CLEANUP+=("rm -rf $(printf %q "${WORK}/secrets")")

# ---- host binaries ---------------------------------------------------------
if [ -z "${RELAY_BIN:-}" ]; then
  log "building tunnel-relay"
  cargo build --locked -p tunnel-relay --bin tunnel-relay --manifest-path "${ROOT}/Cargo.toml" >&2
  RELAY_BIN="${CARGO_TARGET_DIR:-${ROOT}/target}/debug/tunnel-relay"
fi
[ -x "${RELAY_BIN}" ] || die "no tunnel-relay at ${RELAY_BIN}"

# ---- the disposable guest --------------------------------------------------
PATH="$(dirname "$(command -v "${TART}")"):${PATH}" "${VM_SCRIPT}" create "${VM}"
if [ "${KEEP_VM:-0}" != 1 ]; then
  CLEANUP+=("TART=$(printf %q "${TART}") $(printf %q "${VM_SCRIPT}") destroy $(printf %q "${VM}")")
fi
# `run` boots headless and refuses to return until a root capture INSIDE the
# guest shows the fixture's red marker.
GUEST_IP="$(TART="${TART}" "${VM_SCRIPT}" run "${VM}" | tail -1)"
case "${GUEST_IP}" in 192.168.64.*) ;; *) die "unexpected guest address ${GUEST_IP}";; esac
HOST_IP="$(ifconfig | awk -v net="${GUEST_IP%.*}." '$1=="inet" && index($2, net)==1 {print $2; exit}')"
[ -n "${HOST_IP}" ] || die "no host address on the guest's private network"
log "guest ${GUEST_IP}, host ${HOST_IP} on Tart's private network"
gexec() { "${TART}" exec "${VM}" "$@"; }
gexec_in() { "${TART}" exec -i "${VM}" "$@"; }
gexec sudo bash /opt/cua-fixture/guest-manifest.sh >"${OUT}/manifest.json"
gexec cat /tmp/cua-fixture/state.json >"${OUT}/fixture-state-before.json"

# ---- synthetic PKI and identity issuer (host, in WORK/secrets) -------------
S="${WORK}/secrets"; mkdir -m 700 -p "${S}"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=m5-cua-demo synthetic server CA" \
  -keyout "${S}/server-ca-key.pem" -out "${S}/server-ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=m5-cua-demo synthetic relay" \
  -keyout "${S}/relay-key.pem" -out "${S}/relay.csr" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1,IP:%s\n' \
  "${RELAY_HOST}" "${HOST_IP}" >"${S}/relay-ext.cnf"
openssl x509 -req -in "${S}/relay.csr" -CA "${S}/server-ca.pem" -CAkey "${S}/server-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "${S}/relay-ext.cnf" -out "${S}/relay-cert.pem" 2>/dev/null
cat "${S}/relay-cert.pem" "${S}/server-ca.pem" >"${S}/relay-chain.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=m5-cua-demo synthetic device CA" \
  -keyout "${S}/device-ca-key.pem" -out "${S}/device-ca.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${S}/issuer-key.pem" 2>/dev/null
python3 "${TOOLS}" jwks "${S}/issuer-key.pem" "${S}/jwks.json"

# ---- Redis TLS terminator ----------------------------------------------------
python3 "${TOOLS}" tls-forward "${S}/relay-chain.pem" "${S}/relay-key.pem" "${REDIS_HOSTPORT}" "${S}/redis-tls.port" &
CLEANUP+=("kill $! 2>/dev/null")
for _ in $(seq 1 50); do [ -s "${S}/redis-tls.port" ] && break; sleep 0.1; done
REDIS_TLS_PORT="$(cat "${S}/redis-tls.port")"
CLEANUP+=("python3 $(printf %q "${TOOLS}") redis-clean $(printf %q "${REDIS_HOSTPORT}") ${REDIS_DB} $(printf %q "${NAMESPACE}") >&2")

# ---- relay configuration -------------------------------------------------------
free_port() { python3 -c 'import socket,sys; s=socket.socket(); s.bind((sys.argv[1], 0)); print(s.getsockname()[1]); s.close()' "$1"; }
CONSUMER_PORT="$(free_port 127.0.0.1)"
DEVICE_PORT="$(free_port "${HOST_IP}")"
python3 - "${ROOT}/examples/m1-relay.toml" "${WORK}/relay.toml" <<EOF
import re, sys
text = open(sys.argv[1]).read()
values = {
    "consumer_bind": '"127.0.0.1:${CONSUMER_PORT}"',
    "device_bind": '"${HOST_IP}:${DEVICE_PORT}"',
    "oidc_issuer": '"${ISSUER}"',
    "oidc_jwks_path": '"${S}/jwks.json"',
    "redis_url": '"rediss://localhost:${REDIS_TLS_PORT}/${REDIS_DB}"',
    "redis_namespace": '"${NAMESPACE}"',
    "device_tls_cert_chain": '"${S}/relay-chain.pem"',
    "device_tls_private_key": '"${S}/relay-key.pem"',
    "device_tls_client_ca": '"${S}/device-ca.pem"',
    "consumer_tls_cert_chain": '"${S}/relay-chain.pem"',
    "consumer_tls_private_key": '"${S}/relay-key.pem"',
    "node_id": '"relay-m5-cua-demo"',
    "boot_id": '"m5-cua-demo-boot-${NONCE}"',
    "deployment_incarnation": '"${NAMESPACE}"',
}
for key, value in values.items():
    text, count = re.subn(rf"(?m)^{key} = .*$", f"{key} = {value}", text)
    assert count == 1, key
text = 'redis_tls_root_ca_path = "${S}/server-ca.pem"\n' + text + '\n[http_forward]\nprofiles = ["computer-v1"]\n'
open(sys.argv[2], "w").write(text)
EOF

# ---- the device (guest): binaries, relay name, key, CSR ---------------------
log "installing the device binaries and the backend wrapper in the guest"
COPYFILE_DISABLE=1 tar -C "${GUEST_BIN_DIR}" -cf - tunnel-client tunnel-deadman \
  | gexec_in sudo bash -c 'mkdir -p /opt/agentuplink/bin && tar -C /opt/agentuplink/bin -xf - && chmod 0755 /opt/agentuplink/bin/*'
gexec_in sudo install -m 0755 /dev/stdin /opt/cua-fixture/cua-backend-supervised.sh <"${ROOT}/tests/cua-fixture/cua-backend-supervised.sh"
# The relay's name, pinned in the disposable clone only.
echo "${HOST_IP} ${RELAY_HOST}" | gexec_in sudo tee -a /etc/hosts >/dev/null
GD=/home/cua/demo
gexec sudo -u cua mkdir -p "${GD}" /home/cua/cua-export
gexec_in sudo -u cua tee "${GD}/server-ca.pem" >/dev/null <"${S}/server-ca.pem"
python3 - "${ROOT}/examples/m1-client.toml" <<EOF | gexec_in sudo -u cua tee "${GD}/client.toml" >/dev/null
import re, sys
text = open(sys.argv[1]).read()
text = re.sub(r'(?m)^relay_url = .*$', 'relay_url = "wss://${RELAY_HOST}:${DEVICE_PORT}/v1/tunnel/control"', text)
start = text.index("[exports.")
end = text.index("\n\n", start)
export = '''[exports."${SERVICE}"]
type = "http-forward"

[exports."${SERVICE}".cua]
profile = "computer-v1"
point_width = 1280
point_height = 800
operations = ["describe", "capture", "screen_info", "cursor_position", "click", "double_click", "move", "drag", "scroll", "type_text", "press_key", "hotkey"]

[exports."${SERVICE}".cua.backend]
command = "/opt/cua-fixture/cua-backend-supervised.sh"
args = ["/home/cua/cua-export/backend.address"]
workspace = "/home/cua/cua-export"
address_file = "/home/cua/cua-export/backend.address"
env = { PATH = "/usr/local/bin:/usr/bin:/bin", HOME = "/home/cua" }
startup_seconds = 90'''
sys.stdout.write(text[:start] + export + text[end:])
EOF
gexec sudo -u cua /opt/agentuplink/bin/tunnel-client credentials create --config "${GD}/client.toml" --csr-out device.csr >&2
gexec sudo -u cua cat "${GD}/device.csr" >"${S}/device.csr"

# ---- the issuer's step (host): sign the device CSR ---------------------------
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:%s\n' "${DEVICE}" >"${S}/device-ext.cnf"
openssl x509 -req -in "${S}/device.csr" -CA "${S}/device-ca.pem" -CAkey "${S}/device-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "${S}/device-ext.cnf" -out "${S}/device-cert.pem" 2>/dev/null
gexec_in sudo -u cua tee "${GD}/device-cert.pem" >/dev/null <"${S}/device-cert.pem"
gexec sudo -u cua /opt/agentuplink/bin/tunnel-client credentials import --config "${GD}/client.toml" \
  --certificate device-cert.pem --server-ca "${GD}/server-ca.pem" >&2

# ---- the operator's steps (host): provision and serve --------------------------
cp "${RECORDS}" "${S}/catalog.toml"
( cd "${S}" && "${RELAY_BIN}" provision-catalog --config "${WORK}/relay.toml" --records catalog.toml --dry-run ) >&2
"${RELAY_BIN}" activate-first-incarnation --config "${WORK}/relay.toml" >&2
( cd "${S}" && "${RELAY_BIN}" provision-catalog --config "${WORK}/relay.toml" --records catalog.toml ) >&2
RUST_LOG=warn "${RELAY_BIN}" serve --config "${WORK}/relay.toml" 2>"${WORK}/relay.log" &
RELAY_PID=$!
CLEANUP+=("kill ${RELAY_PID} 2>/dev/null; sleep 1")
for _ in $(seq 1 100); do grep -q "tunnel-relay listening" "${WORK}/relay.log" && break; kill -0 "${RELAY_PID}" || die "relay exited: $(tail -5 "${WORK}/relay.log")"; sleep 0.2; done
grep -q "tunnel-relay listening" "${WORK}/relay.log" || die "relay never listened"

# The ownership gate: each relay port has the relay as its ONLY listener.
for port in "${CONSUMER_PORT}" "${DEVICE_PORT}"; do
  owners="$({ lsof -nP -iTCP:"${port}" -sTCP:LISTEN -t 2>/dev/null || true; } | sort -u | tr '\n' ' ')"
  [ "${owners}" = "${RELAY_PID} " ] || die "port ${port} listeners are '${owners}', expected only the relay ${RELAY_PID}"
done
log "relay ${RELAY_PID} owns consumer 127.0.0.1:${CONSUMER_PORT} and device ${HOST_IP}:${DEVICE_PORT}"

# ---- connect the device (guest), opted in to Lane B ----------------------------
gexec sudo -u cua env AGENT_TUNNEL_CUA_LANE_B=1 TUNNEL_DEADMAN_BIN=/opt/agentuplink/bin/tunnel-deadman \
  setsid bash -c "/opt/agentuplink/bin/tunnel-client connect --config ${GD}/client.toml --json >${GD}/connect.log 2>&1 </dev/null &"
CLEANUP+=("${TART} exec ${VM} sudo pkill -u cua -f 'tunnel-client connect' 2>/dev/null")
for _ in $(seq 1 100); do
  gexec sudo -u cua grep -q '"ready"' "${GD}/connect.log" 2>/dev/null && break
  sleep 0.3
done
gexec sudo -u cua grep -q '"ready"' "${GD}/connect.log" || die "device not ready: $(gexec sudo -u cua tail -5 "${GD}/connect.log")"
log "device session ready"

# ---- the consumer (host) ---------------------------------------------------------
python3 "${TOOLS}" token "${S}/issuer-key.pem" "${ISSUER}" "${AUDIENCE}" "${SUBJECT}" >"${S}/token"
chmod 600 "${S}/token"
gexec cat /tmp/cua-fixture/state.json >"${S}/state.json"
set +e
python3 "${TOOLS}" consumer --consumer-port "${CONSUMER_PORT}" --device "${DEVICE}" --service "${SERVICE}" \
  --ca "${S}/server-ca.pem" --token-file "${S}/token" --state "${S}/state.json" --out "${OUT}" --text "${DEMO_TEXT}"
consumer_exit=$?
set -e
sleep 1
gexec cat /tmp/cua-fixture/state.json >"${OUT}/fixture-state-after.json"
gexec sudo -u cua cat "${GD}/connect.log" | grep -v '^\s*$' >"${OUT}/connect.log" || true
grep -v 'token\|Bearer' "${WORK}/relay.log" >"${OUT}/relay.log" || true

# ---- M5-C09a question (1): does held input survive the server? (guest only) ----
# After the demo, with the device stopped: start the pinned server on guest
# loopback, hold the left button and Shift through it, then read the X
# server's own pointer mask and keymap after the HTTP client has gone and
# again after the server is SIGKILLed. Everything runs inside the guest; the
# held input lands on the fixture VM, which is deleted afterwards.
if [ "${M5_CUA_RESIDUE_PROBE:-1}" = 1 ]; then
  log "M5-C09a residue probe (guest-local, native backend)"
  gexec sudo pkill -u cua -f 'tunnel-client connect' 2>/dev/null || true
  sleep 2
  gexec sudo pkill -u cua -f cua-computer-server 2>/dev/null || true
  RPORT=8123
  gexec sudo -u cua setsid bash -c "cua-server-start native ${RPORT} >/tmp/residue-server.log 2>&1 </dev/null &"
  for _ in $(seq 1 60); do gexec curl -s -o /dev/null "http://127.0.0.1:${RPORT}/status" 2>/dev/null && break; sleep 1; done
  xstate() {
    gexec sudo -u cua env DISPLAY=:0 XAUTHORITY=/home/cua/.Xauthority /opt/cua-server/bin/python -c '
import json
from Xlib import X, XK, display
d = display.Display()
mask = d.screen().root.query_pointer().mask
keys = d.query_keymap()
code = d.keysym_to_keycode(XK.string_to_keysym("Shift_L"))
print(json.dumps({"button1_down": bool(mask & X.Button1Mask), "shift_mask": bool(mask & X.ShiftMask),
                  "shift_l_key_down": bool(keys[code // 8] & (1 << (code % 8)))}, sort_keys=True))'
  }
  cmd() { gexec curl -s -X POST -H 'content-type: application/json' --data "$1" "http://127.0.0.1:${RPORT}/cmd"; }
  {
    echo "{\"baseline\": $(xstate),"
    echo " \"mouse_down\": $(cmd '{"command":"mouse_down","params":{"button":"left"}}' | sed -n 's/^data: //p'),"
    echo " \"key_down\": $(cmd '{"command":"key_down","params":{"key":"shift"}}' | sed -n 's/^data: //p'),"
    echo " \"after_client_disconnect\": $(xstate),"
    gexec sudo pkill -KILL -u cua -f cua-computer-server
    sleep 1
    echo " \"after_server_sigkill\": $(xstate),"
    gexec sudo -u cua env DISPLAY=:0 XAUTHORITY=/home/cua/.Xauthority xdotool mouseup 1 keyup shift
    echo " \"after_guest_cleanup\": $(xstate)}"
  } >"${OUT}/residue-probe.json"
  python3 -m json.tool "${OUT}/residue-probe.json" >/dev/null || die "residue probe output is not JSON"
fi

# ---- the verdict, from the application's own state file --------------------------
python3 - "${OUT}" "${DEMO_TEXT}" "${consumer_exit}" <<'EOF'
import json, sys
out, text, consumer_exit = sys.argv[1], sys.argv[2], int(sys.argv[3])
before = json.load(open(f"{out}/fixture-state-before.json"))
after = json.load(open(f"{out}/fixture-state-after.json"))
consumer = json.load(open(f"{out}/consumer.json"))
verdict = {
    "consumer_exit": consumer_exit,
    "clicks_before": before["clicks"], "clicks_after": after["clicks"],
    "text_before_chars": len(before["text"]),
    "text_matches": after["text"] == text,
    "markers_match_fixture": consumer.get("markers_match_fixture"),
    "unleased_click": consumer.get("unleased_click"),
    "stale_click": consumer.get("stale_click"),
}
verdict["ok"] = (consumer_exit == 0 and verdict["clicks_after"] == verdict["clicks_before"] + 1
                 and verdict["text_matches"] and verdict["markers_match_fixture"]
                 and verdict["unleased_click"] == "lease_not_held"
                 and verdict["stale_click"] == "capture_superseded")
json.dump(verdict, open(f"{out}/verdict.json", "w"), indent=2, sort_keys=True)
print("m5-cua-demo verdict: " + json.dumps(verdict, sort_keys=True))
sys.exit(0 if verdict["ok"] else 1)
EOF
log "evidence in ${OUT}"
