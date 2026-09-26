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

gate_output=
cleanup() {
  if [ -n "$gate_output" ]; then
    rm -f "$gate_output"
  fi
}
trap cleanup EXIT

# Run one harness gate and require its pass line as well as its exit status,
# so a gate that exits 0 without having run its stage cannot pass (task row
# M6-C96).  Standard output is the harness's pass lines only; diagnostics go
# to standard error and stream as the gate runs.
run_gate() {
  gate=$1
  required=$2
  gate_output=$(mktemp "${TMPDIR:-/tmp}/m2-harness-verify.XXXXXX")
  status=0
  cargo run --locked -p tunnel-test-harness -- "$gate" >"$gate_output" || status=$?
  cat "$gate_output"
  if [ "$status" -ne 0 ]; then
    exit "$status"
  fi
  if ! grep -q "^$required" "$gate_output"; then
    echo "m2-harness-verify: $gate exited 0 without printing its pass line ($required)" >&2
    exit 1
  fi
  rm -f "$gate_output"
  gate_output=
  echo "m2-harness-verify: $gate ok" >&2
}

echo "m2-harness-verify: building locked workspace binaries" >&2
cargo build --locked --workspace --bins
case "$command" in
  verify-m2)
    run_gate verify-m2 "M2 continuous traffic passed: "
    run_gate verify-m2-faults "M2 fault sequence passed: "
    ;;
  verify-m2-default)
    run_gate verify-m2-default "M2 continuous traffic passed: "
    ;;
  verify-m2-faults)
    run_gate verify-m2-faults "M2 fault sequence passed: "
    ;;
esac
