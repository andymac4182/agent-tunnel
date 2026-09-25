#!/bin/bash
# Provision the M5 CUA macOS golden image. Runs INSIDE the Tart macOS guest as
# root, never on the macOS host: it refuses unless the kernel reports that it
# is running under a hypervisor. scripts/m5-cua-vm-macos.sh copies this
# directory into the guest at /opt/cua-fixture and invokes it.
#
# Result: a standard (non-admin) `cua` user that logs in automatically into an
# Aqua session; python.org CPython 3.13 (installer pinned by SHA-256 and
# checked for the PSF Developer ID signature); cua-computer-server 0.3.46
# installed hash-locked and wheel-only into /opt/cua-server; and three
# launchd agents in cua's session, none of which runs at load:
#
#   org.agentuplink.cua-fixture    the fixture app (tests/cua-fixture/fixture_app.py)
#   org.agentuplink.cua-server     cua-computer-server on 127.0.0.1, per /etc/agentuplink-cua/server-run.sh
#   org.agentuplink.cua-permcheck  read-only TCC preflight, writes /tmp/cua-permcheck.json
#
# All three are launched by launchd in cua's GUI domain, so each is its own
# TCC "responsible process" and resolves to the same code identity: the
# python.org Python.app (bundle id org.python.python). That is the identity
# the owner grants Screen Recording and Accessibility to, once, in the golden
# image. Nothing here grants anything: TCC cannot be written without turning
# SIP off, and this image keeps SIP on.
set -euo pipefail

if [ "$(uname -s)" != Darwin ]; then
  echo "refusing: provision-guest-macos.sh runs only inside the macOS guest" >&2
  exit 2
fi
if [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null || echo 0)" != 1 ]; then
  echo "refusing: kern.hv_vmm_present is not 1; this is not a virtual machine" >&2
  exit 2
fi
if [ "$(id -u)" != 0 ]; then
  echo "run as root" >&2
  exit 2
fi

SRC=/opt/cua-fixture
# python.org CPython 3.13.15 macOS installer. SHA-256 as published by the
# python.org release API (release_file sha256_sum) on 2026-09-26; the installer
# is additionally required to carry the PSF Developer ID Installer signature.
PY_VERSION=3.13.15
PY_PKG_URL="https://www.python.org/ftp/python/${PY_VERSION}/python-${PY_VERSION}-macos11.pkg"
PY_PKG_SHA256=3b7eaf7f29825f796e8267024435540ddf1f17fc9a97ad58095daa7a75bfdcd3
PY_FW=/Library/Frameworks/Python.framework/Versions/3.13
CUA_USER=cua

# --- Determinism: no background updates, sleep or screen saver under a run.
softwareupdate --schedule off >/dev/null 2>&1 || true
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false
defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool false
pmset -a sleep 0 displaysleep 0 disksleep 0 >/dev/null

# --- CPython from python.org, pinned.
if [ ! -x "${PY_FW}/bin/python3.13" ] || [ "$("${PY_FW}/bin/python3.13" -c 'import platform; print(platform.python_version())')" != "${PY_VERSION}" ]; then
  pkg="$(mktemp -d)/python.pkg"
  curl -fsSL --retry 3 -o "${pkg}" "${PY_PKG_URL}"
  got="$(shasum -a 256 "${pkg}" | awk '{print $1}')"
  if [ "${got}" != "${PY_PKG_SHA256}" ]; then
    echo "python installer digest ${got} != pinned ${PY_PKG_SHA256}" >&2
    exit 1
  fi
  pkgutil --check-signature "${pkg}" | grep -q 'Developer ID Installer: Python Software Foundation (BMM5U3QVKW)' \
    || { echo "python installer is not signed by the PSF Developer ID" >&2; exit 1; }
  installer -pkg "${pkg}" -target / >/dev/null
  rm -f "${pkg}"
fi
"${PY_FW}/bin/python3.13" -c 'import tkinter; print("tk", tkinter.TkVersion)'

# --- Hash-locked server install. --require-hashes makes pip refuse any
# artifact whose digest is not in the lock, including cua-computer-server,
# whose two hashes are the wheel and sdist digests in cua_pin.rs. Wheels only:
# every one of the locked packages has a macOS arm64 or pure-Python wheel.
rm -rf /opt/cua-server
"${PY_FW}/bin/python3.13" -m venv /opt/cua-server
/opt/cua-server/bin/pip install -q --require-hashes --no-deps --only-binary :all: \
  -r "${SRC}/requirements-macos-arm64.lock"
/opt/cua-server/bin/pip check

# --- The unprivileged session user. Standard account, random password known
# only to /etc/kcpassword (autologin needs one); never printed or stored
# anywhere else. Administrative prompts in the guest use the base image's
# documented admin account.
if ! id "${CUA_USER}" >/dev/null 2>&1; then
  pw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
  sysadminctl -addUser "${CUA_USER}" -fullName "CUA Fixture" -password "${pw}" \
    -home "/Users/${CUA_USER}" >/dev/null 2>&1
  createhomedir -c -u "${CUA_USER}" >/dev/null 2>&1 || true
  # /etc/kcpassword: the password XORed with Apple's fixed 11-byte key, padded
  # with NULs to a multiple of 12.
  CUA_PW="${pw}" /usr/bin/python3 - <<'EOF'
import os
key = [0x7D, 0x89, 0x52, 0x23, 0xD2, 0xBC, 0xDD, 0xEA, 0xA3, 0xB9, 0x1F]
pw = bytearray(os.environ["CUA_PW"].encode())
pw += b"\0" * (12 - len(pw) % 12)
enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(pw))
fd = os.open("/etc/kcpassword", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, enc)
os.close(fd)
EOF
  unset pw
fi
dscl . -read "/Users/${CUA_USER}" UniqueID >/dev/null
if dseditgroup -o checkmember -m "${CUA_USER}" admin >/dev/null 2>&1; then
  echo "${CUA_USER} must not be an administrator" >&2
  exit 1
fi
defaults write /Library/Preferences/com.apple.loginwindow autoLoginUser "${CUA_USER}"
chown root:wheel /etc/kcpassword
chmod 600 /etc/kcpassword

home="/Users/${CUA_USER}"
as_cua() { sudo -u "${CUA_USER}" "$@"; }
# Skip every first-login Setup Assistant pane: the base image's admin has
# already seen them for this exact OS build, so copy that record.
install -d -o "${CUA_USER}" -g staff -m 0700 "${home}/Library/Preferences"
if [ -f /Users/admin/Library/Preferences/com.apple.SetupAssistant.plist ]; then
  cp /Users/admin/Library/Preferences/com.apple.SetupAssistant.plist \
    "${home}/Library/Preferences/com.apple.SetupAssistant.plist"
fi
for k in DidSeeCloudSetup DidSeeSiriSetup DidSeePrivacy DidSeeScreenTime DidSeeAppearanceSetup \
    DidSeeAccessibility DidSeeActivationLock DidSeeTouchIDSetup DidSeeSyncSetup DidSeeSyncSetup2 \
    DidSeeApplePaySetup DidSeeiCloudLoginForStorageServices DidSeeTermsOfAddress \
    DidSeeIntelligence DidSeeLockdownMode DidSeeWallpaper DidSeeTrueTonePrivacy \
    SkipFirstLoginOptimization; do
  defaults write "${home}/Library/Preferences/com.apple.SetupAssistant.plist" "${k}" -bool true
done
defaults write "${home}/Library/Preferences/com.apple.SetupAssistant.plist" \
  LastSeenCloudProductVersion "$(sw_vers -productVersion)"
defaults write "${home}/Library/Preferences/com.apple.SetupAssistant.plist" \
  LastSeenBuddyBuildVersion "$(sw_vers -buildVersion)"
chown "${CUA_USER}:staff" "${home}/Library/Preferences/com.apple.SetupAssistant.plist"
# No screen saver, no reopened windows, US keyboard layout (recorded per run).
as_cua defaults -currentHost write com.apple.screensaver idleTime -int 0
as_cua defaults write com.apple.loginwindow TALLogoutSavesState -bool false
as_cua defaults write com.apple.HIToolbox AppleSelectedInputSources -array \
  '<dict><key>InputSourceKind</key><string>Keyboard Layout</string><key>KeyboardLayout ID</key><integer>0</integer><key>KeyboardLayout Name</key><string>U.S.</string></dict>'

# --- Launchers. The server binds guest loopback only; telemetry off (cua-core
# 0.3.1 sends PostHog and OpenTelemetry events by default and reads both
# variables).
install -d -o root -g wheel -m 0755 /usr/local/bin /etc/agentuplink-cua
install -m 0755 /dev/stdin /usr/local/bin/cua-server-start <<'EOF'
#!/bin/sh
# Started only by launchd (org.agentuplink.cua-server) in cua's GUI session.
# /etc/agentuplink-cua/server-run.sh is root-owned and written by the host
# script from its fixed variant table; it sets LABEL, BACKEND and ARGS and may
# export extra environment (e.g. UNAVAILABLE_WITHOUT_CONTAINER_NAME).
LABEL=default BACKEND=native ARGS= PORT=8000
[ -f /etc/agentuplink-cua/server-run.sh ] && . /etc/agentuplink-cua/server-run.sh
export CUA_TELEMETRY_ENABLED=false CUA_TELEMETRY_DISABLED=1
# shellcheck disable=SC2086  # ARGS is a fixed, space-separated flag list
exec /opt/cua-server/bin/cua-computer-server \
  --host 127.0.0.1 --port "${PORT}" --log-level info --backend "${BACKEND}" ${ARGS} \
  >"/tmp/cua-server-${LABEL}.log" 2>&1 </dev/null
EOF
install -m 0755 /dev/stdin /usr/local/bin/cua-fixture-start <<'EOF'
#!/bin/sh
# Started only by launchd (org.agentuplink.cua-fixture) in cua's GUI session.
exec /opt/cua-server/bin/python /opt/cua-fixture/fixture_app.py >/tmp/cua-fixture.log 2>&1 </dev/null
EOF
install -m 0755 /dev/stdin /usr/local/bin/cua-permcheck <<'EOF'
#!/opt/cua-server/bin/python
# Read-only TCC preflight for the identity the server runs as. Launched by
# launchd so it is its own responsible process; neither call prompts.
import json, os, subprocess, sys
from ApplicationServices import AXIsProcessTrusted
from Quartz import CGPreflightScreenCaptureAccess
rec = {
    # The image this process is actually running, which is what TCC judges
    # (the framework's bin/python3.13 re-executes Python.app's binary).
    "process_image": subprocess.run(["ps", "-o", "comm=", "-p", str(os.getpid())],
                                    capture_output=True, text=True).stdout.strip(),
    "sys_executable": sys.executable,
    "screen_recording_preflight": bool(CGPreflightScreenCaptureAccess()),
    "accessibility_trusted": bool(AXIsProcessTrusted()),
}
tmp = "/tmp/.cua-permcheck.json"
with open(tmp, "w") as f:
    json.dump(rec, f, sort_keys=True)
os.replace(tmp, "/tmp/cua-permcheck.json")
EOF

# --- launchd agents in cua's session. None runs at load: the golden image
# boots to an idle desktop (so the owner can reach System Settings), and the
# host script kickstarts the fixture and server in disposable clones only.
agents="${home}/Library/LaunchAgents"
install -d -o "${CUA_USER}" -g staff -m 0755 "${agents}"
write_agent() {
  local label="$1" program="$2"
  cat >"${agents}/${label}.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array><string>${program}</string></array>
  <key>RunAtLoad</key><false/>
  <key>KeepAlive</key><false/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF
  chown "${CUA_USER}:staff" "${agents}/${label}.plist"
  chmod 0644 "${agents}/${label}.plist"
  plutil -lint "${agents}/${label}.plist" >/dev/null
}
write_agent org.agentuplink.cua-fixture /usr/local/bin/cua-fixture-start
write_agent org.agentuplink.cua-server /usr/local/bin/cua-server-start
write_agent org.agentuplink.cua-permcheck /usr/local/bin/cua-permcheck

mkdir -p /etc/cua-golden
cp "${SRC}/requirements-macos-arm64.lock" /etc/cua-golden/
echo "provisioned $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/etc/cua-golden/provisioned
