#!/usr/bin/env bash
# Run one narrated demo step per feature (task row M6-C128). Each step says
# what it does and prints the result: HTTP status, timing, and synthetic
# markers. It never prints a token, key or non-synthetic payload.
#
#   scripts/demo/show.sh list              # every feature and whether it is ready
#   scripts/demo/show.sh echo              # one feature
#   scripts/demo/show.sh all               # every ready feature, in order
#   scripts/demo/show.sh --remote echo     # opt-in: against the live Fly relay
#
# Exit 0 when every step matched its expected result, 1 when any did not,
# 2 for a feature that is not available yet (a TODO plug-in).
set -u
. "$(dirname "$0")/lib/common.sh"

target=
for arg in "$@"; do
  case $arg in
    --remote) DEMO_MODE=remote ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    -*) demo_die "unknown option $arg" ;;
    *) [ -z "$target" ] || demo_die "one feature at a time (or 'all')"; target=$arg ;;
  esac
done
[ -n "$target" ] || { sed -n '2,12p' "$0"; exit 2; }

if [ "$target" = list ]; then
  demo_say "demo features (scripts/demo/features/)"
  for f in $(demo_feature_files); do
    (
      demo_load_feature "$f"
      if [ "$FEATURE_READY" = 1 ]; then s=ready; else s="$FEATURE_TODO"; fi
      r=; [ "$FEATURE_REMOTE" = 1 ] && r=" (also --remote)"
      printf '    %-9s %s%s\n              %s\n' "$FEATURE_NAME" "$FEATURE_TITLE" "$r" "$s"
    )
  done
  exit 0
fi

if [ "$DEMO_MODE" = local ]; then
  "$DEMO_DIR/status.sh" --quiet || demo_die "the local demo is not healthy; run scripts/demo/status.sh (or up.sh)"
fi
demo_load_ids
DEMO_TMP=$(mktemp -d "${TMPDIR:-/tmp}/agentuplink-demo.XXXXXX")
trap 'rm -rf "$DEMO_TMP"' EXIT

run_one() {
  local file=$1 rc
  (
    demo_load_feature "$file"
    if [ "$FEATURE_READY" != 1 ]; then
      demo_say "$FEATURE_NAME: not available yet -- $FEATURE_TODO"
      exit 2
    fi
    if [ "$DEMO_MODE" = remote ] && [ "$FEATURE_REMOTE" != 1 ]; then
      demo_say "$FEATURE_NAME: no remote demo (the live relay does not serve it)"
      exit 2
    fi
    DEMO_FAILURES=0
    SERVICE=$(demo_service_id "$FEATURE_NAME")
    printf '\n%s======== %s%s (%s)\n' "$C_B" "$FEATURE_TITLE" "$C_0" "$DEMO_MODE"
    t0=$(demo_now_ms)
    if [ "$DEMO_MODE" = remote ]; then feature_show_remote; else feature_show; fi
    t=$(( $(demo_now_ms) - t0 ))
    if [ "$DEMO_FAILURES" = 0 ]; then
      demo_say "$FEATURE_NAME: all steps as expected ($t ms)"
      exit 0
    fi
    demo_say "$FEATURE_NAME: $DEMO_FAILURES step(s) did not match ($t ms)"
    exit 1
  )
  rc=$?
  return $rc
}

if [ "$target" = all ]; then
  overall=0
  for f in $(demo_feature_files); do
    ready=$(demo_load_feature "$f"; [ "$FEATURE_READY" = 1 ] && { [ "$DEMO_MODE" = local ] || [ "$FEATURE_REMOTE" = 1 ]; } && echo 1)
    [ "$ready" = 1 ] || continue
    run_one "$f" || overall=1
  done
  exit $overall
fi

file=$(demo_feature_file "$target") || demo_die "no feature '$target' (try: scripts/demo/show.sh list)"
run_one "$file"
