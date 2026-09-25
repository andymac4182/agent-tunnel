#!/bin/sh
# Parallel survey runner.
#
# The serial runner spends ~21 minutes on 73 gates that are mostly waiting on
# sockets and Redis, not burning CPU. Gates use isolated Redis namespaces and
# ephemeral ports, so most can run concurrently.
#
# Timing-sensitive gates are deliberately NOT run concurrently: this session
# has measured load-induced false failures on exactly those (credential expiry,
# recovery attempts, GOAWAY rotation, peer capacity, timing boundaries), and a
# false failure costs far more investigation time than the minutes saved.
# They run serially after the parallel pass.
#
# Measured on 2026-09-14 against the 73-gate suite: 897 s wall and 73/73 passing,
# against a 1248 s serial baseline. The parallel lane finished its 63 gates in
# about 332 s (896 s of work at 3 jobs); the 10 serial gates are 565 s of that
# total, so the serial tail now dominates. Overlapping the two lanes would reach
# roughly 10 minutes but would put parallel load underneath the timing-sensitive
# gates, which is the exact thing this split exists to avoid.
#
# Usage: m7-gates-parallel.sh <label> [jobs]
#
# Every run writes into its own new directory, gates-<label>-<UTC>-<pid>, and
# stamps it with run.txt (nonce, label, head).  It used to write into
# gates-<label> and truncate that directory's summary.tsv, so two agents
# sharing one scratchpad and choosing the same label -- `final`, `check` --
# overwrote each other's logs, and a gate log left by an earlier run read like
# this run's.  A result is attributable only if it names the run that wrote it
# (docs/tasks.md M6-C16).  `M7_GATES_LIST_ONLY=1` stops after the gate lists,
# which is what scripts/test_scratch_log_names.py uses.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
S=${M7_GATE_OUTPUT_DIR:-${TMPDIR:-/tmp}/m7-gates}
mkdir -p "$S"
label=${1:?label}
jobs=${2:-3}
nonce=m7-gates-$label-$(date -u '+%Y%m%dT%H%M%SZ')-$$
out=$S/gates-$nonce
suffix=0
# `mkdir` without -p fails on an existing directory, so a name is never reused.
until mkdir "$out" 2>/dev/null; do
  suffix=$((suffix + 1))
  [ "$suffix" -le 100 ] || { echo "cannot create a fresh output directory under $S" >&2; exit 2; }
  out=$S/gates-$nonce-$suffix
done
cd "$REPO" || exit 2
head=$(git rev-parse --short=12 HEAD)
printf 'nonce=%s\nlabel=%s\nhead=%s\noutput=%s\n' "$nonce" "$label" "$head" "$out" > "$out/run.txt"
echo "output=$out nonce=$nonce head=$head"
export TEST_REDIS_URL=${TEST_REDIS_URL:-redis://127.0.0.1:63790/}
export TUNNEL_CATALOG_REDIS_URL=${TUNNEL_CATALOG_REDIS_URL:-$TEST_REDIS_URL}
export RUST_LOG=${RUST_LOG:-info}
export C11_SOURCE_ID=${C11_SOURCE_ID:-git-$(git rev-parse --short=12 HEAD)}
export C11_BUILD_ID=${C11_BUILD_ID:-local-$label}
# Keep a failing C11 child's stderr.  Without this the gate reports only a byte
# count and a marker list, and the evidence needed to diagnose it is discarded
# at the moment it is produced.
export C11_CHILD_FAILURE_DIR=${C11_CHILD_FAILURE_DIR:-$out/c11-child-failures}
mkdir -p "$C11_CHILD_FAILURE_DIR"
: > "$out/summary.tsv"

# Gates whose assertions are bounded by real deadlines; these run alone.
#
# The tunnel-catalog Redis integration tests are here for a measured reason.
# They assert against the catalog's own two-second Redis operation bound, which
# is a product constant, so running them beside the parallel lane measures how
# busy the machine is rather than the property under test.  Under six competing
# CPU hogs they fail four times out of four with `Database(timed out)` during
# fixture setup, and they pass every standalone run.  The product bound is not
# the thing to relax, so the schedule is.
SERIAL='credential-expiry|recovery-attempts|goaway|peer-capacity|timing-boundaries|queue-saturation|og02|c11-diagnostics|chaos|tunnel-catalog'

python3 - "$REPO/scripts/m7-harness-verify.sh" <<'PY' > "$out/gates.list"
import re, sys
src = open(sys.argv[1]).read()
for m in re.finditer(r'gate "([^"]+)" \\\n\s+(.+?)\n(?=\n|gate |echo )', src, re.S):
    print(f"{m.group(1)}\t{' '.join(m.group(2).split())}")
PY

grep -Ev "$SERIAL" "$out/gates.list" > "$out/parallel.list"
grep -E "$SERIAL" "$out/gates.list" > "$out/serial.list"
echo "parallel=$(wc -l < "$out/parallel.list") serial=$(wc -l < "$out/serial.list") jobs=$jobs"
[ "${M7_GATES_LIST_ONLY:-0}" = 1 ] && exit 0

run_one() {
  glabel=$1; gcmd=$2; idx=$3
  slug=$(printf '%s' "$glabel" | tr -c 'A-Za-z0-9' '-' | cut -c1-70)
  log="$out/$(printf '%03d' "$idx")-$slug.log"
  start=$(date +%s)
  sh -c "python3 $REPO/scripts/m7-run-bounded.py 600 '$log' $gcmd" >/dev/null 2>&1
  rc=$?
  end=$(date +%s)
  printf '%s\t%s\t%s\t%s\n' "$rc" "$((end-start))" "$glabel" "$log" >> "$out/summary.tsv"
  printf 'rc=%s %ss %s\n' "$rc" "$((end-start))" "$glabel"
}

i=0
while IFS="$(printf '\t')" read -r glabel gcmd; do
  i=$((i+1))
  run_one "$glabel" "$gcmd" "$i" &
  while [ "$(jobs -p | wc -l)" -ge "$jobs" ]; do wait -n 2>/dev/null || sleep 1; done
done < "$out/parallel.list"
wait

while IFS="$(printf '\t')" read -r glabel gcmd; do
  i=$((i+1))
  run_one "$glabel" "$gcmd" "$i"
done < "$out/serial.list"

echo "run: $out nonce=$nonce head=$head"
echo "done: $(awk -F'\t' '$1==0' "$out/summary.tsv" | wc -l | tr -d ' ') passed, $(awk -F'\t' '$1!=0' "$out/summary.tsv" | wc -l | tr -d ' ') failed of $i"
