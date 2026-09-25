#!/bin/sh
# Task row M6-03: run the four experiments of scripts/m6-soak.py in sequence.
#
#   scripts/m6-soak-all.sh BIN_DIR BIN_HEAD LOGS_DIR
#
# Each experiment waits until the host's 1-minute load average is below
# M6_SOAK_MAX_LOAD (default 20) before it starts, and records the load with
# every sample and event.  The short experiments (chaos, load, fairness) run
# through the shared throttle gate when M6_SOAK_GATE names it; the 2-hour soak
# does not hold a gate slot.
set -u
bins=$1 head=$2 logs=$3
here=$(cd "$(dirname "$0")" && pwd)
max=${M6_SOAK_MAX_LOAD:-20}
gate=${M6_SOAK_GATE:-}
load1() { sysctl -n vm.loadavg | awk '{print $2}'; }
quiet() {  # wait outside any gate slot, so a waiting run holds nothing
  while [ "$(echo "$(load1) >= $max" | bc)" = 1 ]; do sleep 30; done
}
for experiment in chaos load fairness; do
  quiet
  echo "m6-soak-all: $experiment start $(date +%Y-%m-%dT%H:%M:%S%z) load=$(sysctl -n vm.loadavg)"
  if [ -n "$gate" ]; then
    $gate nice -n 10 python3 "$here/m6-soak.py" "$experiment" --bin-dir "$bins" --bin-head "$head" \
      --logs "$logs" --max-load "$max" > "$logs/$experiment-driver.log" 2>&1
  else
    nice -n 10 python3 "$here/m6-soak.py" "$experiment" --bin-dir "$bins" --bin-head "$head" \
      --logs "$logs" --max-load "$max" > "$logs/$experiment-driver.log" 2>&1
  fi
  echo "m6-soak-all: $experiment exit=$? $(date +%Y-%m-%dT%H:%M:%S%z)"
done
quiet
echo "m6-soak-all: soak start $(date +%Y-%m-%dT%H:%M:%S%z) load=$(sysctl -n vm.loadavg)"
nice -n 10 python3 "$here/m6-soak.py" soak --bin-dir "$bins" --bin-head "$head" --logs "$logs" \
  --max-load "$max" --duration "${M6_SOAK_DURATION:-7260}" > "$logs/soak-driver.log" 2>&1
echo "m6-soak-all: soak exit=$? $(date +%Y-%m-%dT%H:%M:%S%z)"
