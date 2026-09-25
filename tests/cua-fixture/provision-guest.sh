#!/usr/bin/env bash
# Provision the M5 CUA golden image. Runs INSIDE the Tart guest as root, never
# on the macOS host. scripts/m5-cua-vm.sh copies this directory into the guest
# at /opt/cua-fixture and invokes it; nothing here is meant to run anywhere else.
#
# Result: Xorg (not Xvfb, per M5-03) on the virtio-gpu console, openbox,
# autologin of an unprivileged `cua` user straight into an X session running
# the fixture app, and cua-computer-server 0.3.46 installed hash-locked into
# /opt/cua-server. The server is NOT started here; the host script starts it
# per backend, bound to guest loopback.
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
  echo "refusing: provision-guest.sh runs only inside the Linux guest" >&2
  exit 2
fi
if [ "$(id -u)" != 0 ]; then
  echo "run as root" >&2
  exit 2
fi

SRC=/opt/cua-fixture
export DEBIAN_FRONTEND=noninteractive

# Determinism: no background upgrades changing package versions under a run.
systemctl disable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

apt-get update -q
apt-get install -y -q --no-install-recommends \
  xserver-xorg-core xserver-xorg-input-libinput xinit x11-xserver-utils x11-utils \
  xdotool openbox python3-tk python3-venv python3-dev build-essential \
  fonts-dejavu-core x11vnc imagemagick jq curl
apt-get clean

# Unprivileged session user. No sudo, no password login.
if ! id cua >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash cua
  passwd --lock cua
fi

# Keyboard layout, recorded in the manifest.
cat >/etc/default/keyboard <<'EOF'
XKBMODEL="pc105"
XKBLAYOUT="us"
XKBVARIANT=""
XKBOPTIONS=""
BACKSPACE="guess"
EOF

# Autologin on tty1, straight into startx.
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat >/etc/systemd/system/getty@tty1.service.d/autologin.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin cua --noclear %I $TERM
EOF
systemctl set-default multi-user.target

install -o cua -g cua -m 0644 /dev/stdin /home/cua/.bash_profile <<'EOF'
if [ -z "${DISPLAY:-}" ] && [ "$(tty)" = /dev/tty1 ]; then
  exec startx -- -nolisten tcp vt1 >"$HOME/.xsession.log" 2>&1
fi
EOF

install -o cua -g cua -m 0755 /dev/stdin /home/cua/.xinitrc <<'EOF'
#!/bin/sh
setxkbmap us
xset s off -dpms s noblank
openbox &
python3 /opt/cua-fixture/fixture_app.py &
app=$!
# Measured 2026-09-25 on this image: until something forces an Expose of every
# window, an X GetImage of the root (PIL ImageGrab, ImageMagick `import`)
# returns an all-black frame even though the fixture is mapped. x11vnc's
# startup and `xrefresh` both clear it. Refresh once the fixture has mapped
# so every backend is probed against the same framebuffer.
for _ in $(seq 1 50); do
  xdotool search --name '^agentuplink-cua-fixture$' >/dev/null 2>&1 && break
  sleep 0.2
done
sleep 1
xrefresh
wait "$app"
EOF

# Hash-locked server install. --require-hashes makes pip refuse any artifact
# whose digest is not in the lock, including cua-computer-server itself, whose
# two hashes are the wheel and sdist digests recorded in cua_pin.rs.
python3 -m venv /opt/cua-server
/opt/cua-server/bin/pip install -q --require-hashes --no-deps -r "${SRC}/requirements-linux-aarch64.lock"
/opt/cua-server/bin/pip check

# Launcher used by the host script. Loopback only; telemetry off.
install -m 0755 /dev/stdin /usr/local/bin/cua-server-start <<'EOF'
#!/bin/sh
# usage: cua-server-start <backend> [port] [extra server args...]   (run as user cua)
# Binds guest loopback only. Extra environment (e.g. UNAVAILABLE_WITHOUT_CONTAINER_NAME)
# passes through.
backend="${1:-native}"; port="${2:-8000}"
shift 2 2>/dev/null || shift $#
export DISPLAY=:0 XAUTHORITY=/home/cua/.Xauthority CUA_TELEMETRY_ENABLED=false
if [ "$backend" = vnc ]; then
  # The VNC backend needs an RFB server on the same display: x11vnc, loopback
  # only, no password (the port is not reachable from outside the guest).
  x11vnc -display :0 -localhost -rfbport 5900 -nopw -forever -shared -quiet \
    -bg -o /tmp/x11vnc.log >/dev/null 2>&1
  set -- --vnc-host 127.0.0.1 --vnc-port 5900 "$@"
fi
exec /opt/cua-server/bin/cua-computer-server \
  --host 127.0.0.1 --port "$port" --log-level info --backend "$backend" "$@"
EOF

mkdir -p /etc/cua-golden
cp "${SRC}/requirements-linux-aarch64.lock" /etc/cua-golden/
echo "provisioned $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/etc/cua-golden/provisioned
