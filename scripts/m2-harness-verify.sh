#!/bin/sh
set -eu

if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m2-harness-verify: TEST_REDIS_URL must identify a disposable Redis instance." >&2
  exit 2
fi

case "${1:-accelerated}" in
  accelerated) command=verify-m2 ;;
  default) command=verify-m2-default ;;
  faults) command=verify-m2-faults ;;
  *) echo "Usage: sh scripts/m2-harness-verify.sh [accelerated|default|faults]" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
  echo "Usage: sh scripts/m2-harness-verify.sh [accelerated|default|faults]" >&2
  exit 2
fi

echo "m2-harness-verify: building locked workspace binaries" >&2
cargo build --locked --workspace --bins
if [ "$command" = verify-m2 ]; then
  cargo run --locked -p tunnel-test-harness -- verify-m2
  exec cargo run --locked -p tunnel-test-harness -- verify-m2-faults
fi
exec cargo run --locked -p tunnel-test-harness -- "$command"
