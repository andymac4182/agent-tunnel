#!/usr/bin/env bash
# Mint a short-lived consumer token for the local demo (task row M6-C127),
# for a feature demo written in another language (the TypeScript adapters,
# for example). It refuses to write to a terminal, so the token never lands
# on a shared screen: capture it instead.
#
#   TOKEN=$(scripts/demo/token.sh echo:invoke)          # default TTL 300 s
#   TOKEN=$(scripts/demo/token.sh "fs:connect fs:read" 600)
#   TOKEN=$(scripts/demo/token.sh --remote echo:invoke) # live relay issuer (read-only)
set -eu
. "$(dirname "$0")/lib/common.sh"

scope=; ttl=300
for arg in "$@"; do
  case $arg in
    --remote) DEMO_MODE=remote ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) if [ -z "$scope" ]; then scope=$arg; else ttl=$arg; fi ;;
  esac
done
[ -n "$scope" ] || demo_die "usage: TOKEN=\$(scripts/demo/token.sh SCOPE [TTL_SECONDS])"
case $ttl in *[!0-9]*|'') demo_die "TTL must be seconds" ;; esac
[ "$ttl" -le 3600 ] || demo_die "TTL is capped at 3600 s for the demo"
if [ -t 1 ]; then
  demo_die "refusing to print a token to a terminal; capture it: TOKEN=\$(scripts/demo/token.sh $scope)"
fi
demo_token "$scope" "$ttl"
