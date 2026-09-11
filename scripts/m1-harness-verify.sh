#!/bin/sh
set -eu

if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m1-harness-verify: TEST_REDIS_URL is required; start the CI Redis service and export its URL." >&2
  exit 2
fi

echo "m1-harness-verify: building workspace binaries with Cargo.lock" >&2
cargo build --locked --workspace --bins
exec cargo run --locked -p tunnel-test-harness -- verify "$@"
