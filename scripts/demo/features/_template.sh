# shellcheck shell=bash
# Feature plug-in contract for scripts/demo/ (task row M6-C129).
#
# A feature is one file, features/NN-<name>.sh, where NN orders it in
# `show.sh all` and in the device profile. It is SOURCED in a subshell by
# up.sh, status.sh and show.sh, after scripts/demo/lib/common.sh, so every
# demo_* helper is available. Files not matching NN-*.sh (like this one) are
# ignored. Copy this file, rename it, fill it in, set FEATURE_READY=1.
#
# Nothing else needs to change: up.sh adds your service and grant to the
# catalog (add-service + set-grant, or provision-catalog for the first
# feature), your export to the device profile, your profile to the relay's
# [http_forward] table, builds your cargo packages and starts your backend;
# show.sh runs your steps; down.sh stops every process you started with
# demo_spawn.

FEATURE_NAME=example                 # the name `show.sh <name>` takes; matches NN-<name>.sh
FEATURE_TITLE="One line the audience reads"
FEATURE_READY=0                      # 1 once it works end to end through the local relay
FEATURE_TODO="what is missing"       # shown by `show.sh list` while FEATURE_READY=0
FEATURE_REMOTE=0                     # 1 only if the live Fly relay serves this feature
FEATURE_CARGO_PACKAGES=              # extra workspace packages to build, e.g. tunnel-acp-fixture
FEATURE_REQUIRES=                    # extra commands that must be on PATH, e.g. node

# The [service] table body, WITHOUT tenant/device/id (up.sh writes those).
feature_service() {
  printf 'type = "echo"\ndisplay_name = "Example"\noperations = ["echo:invoke"]'
}
# The grant's operations, a TOML array.
feature_grant_operations() { printf '["echo:invoke"]'; }
# An http-forward profile the relay must serve (mcp-2025-11-25,
# mcp-2026-07-28, acp-http-v1), or nothing.
feature_relay_profile() { :; }
# The device export tables. $1 is this feature's catalog service UUID.
feature_export() {
  printf '[exports."%s"]\ntype = "echo"\ndevice_canary = "example:"\n' "$1"
}
# Start device-side backends BEFORE the device connects. Use
# `demo_spawn NAME "$DEMO_LOGS/NAME.log" CMD...` so down.sh stops them, and
# put any files under "$DEMO_STATE/". Return non-zero on failure.
feature_start() { :; }

# The narrated demo. $SERVICE is this feature's service UUID, $DEMO_DEVICE
# the device, $DEMO_TMP a scratch directory. Pattern for each step:
#   demo_step "N. what the audience is about to see"
#   token=$(demo_token "scope")          # never echo it
#   demo_call METHOD "/v1/devices/$DEMO_DEVICE/services/$SERVICE/..." "$token" BODYFILE|- [curl args]
#   demo_expect "label" 200 && demo_info "synthetic result summary"
# demo_expect counts mismatches; show.sh exits 1 if any. Print status codes,
# timings, counts and synthetic markers only: never a token, key, session
# credential or real payload (pipe any body you show through demo_redact).
feature_show() { demo_warn "not implemented"; }
# Same, against the live relay (only when FEATURE_REMOTE=1).
feature_show_remote() { demo_warn "not implemented"; }
