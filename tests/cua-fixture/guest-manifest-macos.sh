#!/bin/bash
# Print the M5-03 per-run record for the macOS guest as JSON: OS, display
# (pixels, points, backing scale), keyboard layout, SIP, package versions and
# the lock digest. Runs INSIDE the guest as root, read-only. The permission
# state is not read here: it comes from org.agentuplink.cua-permcheck, which
# must run under the server's own TCC identity to mean anything.
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo "guest only" >&2; exit 2; }
[ "$(sysctl -n kern.hv_vmm_present)" = 1 ] || { echo "not a VM; refusing" >&2; exit 2; }

uid="$(id -u cua)"
pipv() { /opt/cua-server/bin/pip show "$1" 2>/dev/null | awk '/^Version:/{print $2}'; }

# NSScreen needs a WindowServer connection in cua's bootstrap namespace, but
# no TCC permission: frame and backingScaleFactor are not protected.
screens="$(launchctl asuser "${uid}" sudo -u cua /opt/cua-server/bin/python -c '
import json
from AppKit import NSScreen
out = []
for s in NSScreen.screens():
    f = s.frame()
    out.append({"points": [int(f.size.width), int(f.size.height)],
                "backing_scale_factor": float(s.backingScaleFactor())})
print(json.dumps(out))' 2>/dev/null || echo '"unavailable: no Aqua session"')"
displays="$(system_profiler SPDisplaysDataType -json 2>/dev/null | /usr/bin/python3 -c '
import json, sys
d = json.load(sys.stdin)
out = []
for gpu in d.get("SPDisplaysDataType", []):
    for disp in gpu.get("spdisplays_ndrvs", []):
        out.append({k: disp.get(k) for k in ("_name", "_spdisplays_pixels", "_spdisplays_resolution",
                                             "spdisplays_pixelresolution", "spdisplays_resolution")
                    if disp.get(k) is not None})
print(json.dumps(out))')"
layout="$(sudo -u cua defaults read com.apple.HIToolbox AppleSelectedInputSources 2>/dev/null \
  | awk -F'= ' '/KeyboardLayout Name/{gsub(/[";]/, "", $2); print $2; exit}')"

/usr/bin/python3 - "$screens" "$displays" <<EOF
import json, sys
print(json.dumps({
  "os": "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))",
  "kernel": "$(uname -r)", "arch": "$(uname -m)",
  "hv_vmm_present": $(sysctl -n kern.hv_vmm_present),
  "sip": "$(csrutil status 2>/dev/null | sed 's/.*: //; s/\.$//')",
  "autologin_user": "$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo none)",
  "display": {"nsscreen": json.loads(sys.argv[1]), "system_profiler": json.loads(sys.argv[2])},
  "keyboard_layout": "${layout:-unset}",
  "packages": {
    "python": "$(/opt/cua-server/bin/python -c 'import platform; print(platform.python_version())')",
    "python_executable": "$(/opt/cua-server/bin/python -c 'import os, sys; print(os.path.realpath(sys.executable))')",
    "tk": "$(/opt/cua-server/bin/python -c 'import tkinter; print(tkinter.Tcl().eval("info patchlevel"))')",
    "cua_computer_server": "$(pipv cua-computer-server)", "cua_driver": "$(pipv cua-driver)",
    "pillow": "$(pipv pillow)", "pynput": "$(pipv pynput)", "pyobjc_core": "$(pipv pyobjc-core)",
  },
  "requirements_lock_sha256": "$(shasum -a 256 /etc/cua-golden/requirements-macos-arm64.lock | cut -d' ' -f1)",
  "provisioned": "$(cat /etc/cua-golden/provisioned)",
}, indent=2, sort_keys=True))
EOF
