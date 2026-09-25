#!/usr/bin/env bash
# Print the M5-03 per-run record as JSON: OS, kernel, display, scale, keyboard
# layout and package versions. Runs INSIDE the guest as root, read-only.
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo "guest only" >&2; exit 2; }

x() { sudo -u cua env DISPLAY=:0 XAUTHORITY=/home/cua/.Xauthority "$@"; }
dpkgv() { dpkg-query -W -f='${Version}' "$1" 2>/dev/null || echo absent; }
pipv() { /opt/cua-server/bin/pip show "$1" 2>/dev/null | awk '/^Version:/{print $2}'; }

dims=$(x xdpyinfo | awk '/dimensions:/{print $2}')
dpi=$(x xdpyinfo | awk '/resolution:/{print $2}')
output=$(x xrandr --current | awk '/ connected/{print $1; exit}')
xkb=$(x setxkbmap -query | awk '/layout:/{print $2}')
xft_dpi=$(x xrdb -query 2>/dev/null | awk '/Xft.dpi/{print $2}')

jq -n \
  --arg os "$(. /etc/os-release; echo "$PRETTY_NAME")" \
  --arg kernel "$(uname -r)" --arg arch "$(uname -m)" \
  --arg dims "$dims" --arg dpi "$dpi" --arg output "$output" \
  --arg xft_dpi "${xft_dpi:-unset}" \
  --arg gdk_scale "${GDK_SCALE:-unset}" \
  --arg xkb "$xkb" \
  --arg xorg "$(dpkgv xserver-xorg-core)" --arg openbox "$(dpkgv openbox)" \
  --arg x11vnc "$(dpkgv x11vnc)" --arg tk "$(dpkgv python3-tk)" \
  --arg python "$(/opt/cua-server/bin/python --version | awk '{print $2}')" \
  --arg server "$(pipv cua-computer-server)" --arg driver "$(pipv cua-driver)" \
  --arg vncdotool "$(pipv vncdotool)" --arg pillow "$(pipv pillow)" \
  --arg pynput "$(pipv pynput)" \
  --arg lock_sha256 "$(sha256sum /etc/cua-golden/requirements-linux-aarch64.lock | cut -d' ' -f1)" \
  --arg provisioned "$(cat /etc/cua-golden/provisioned)" \
  '{os:$os, kernel:$kernel, arch:$arch,
    display:{server:"Xorg (modesetting, virtio-gpu)", output:$output, dimensions:$dims,
             resolution_dpi:$dpi, xft_dpi:$xft_dpi, gdk_scale:$gdk_scale,
             scale_note:"X11 has no per-output scale; no scaling configured"},
    keyboard_layout:$xkb, window_manager:"openbox",
    packages:{xserver_xorg_core:$xorg, openbox:$openbox, x11vnc:$x11vnc, python3_tk:$tk,
              python:$python, cua_computer_server:$server, cua_driver:$driver,
              vncdotool:$vncdotool, pillow:$pillow, pynput:$pynput},
    requirements_lock_sha256:$lock_sha256, provisioned:$provisioned}'
