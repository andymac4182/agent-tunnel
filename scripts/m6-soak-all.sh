#!/bin/sh
# Task row M6-03: run the four experiments of scripts/m6-soak.py in sequence.
#
#   scripts/m6-soak-all.sh BIN_DIR BIN_HEAD LOGS_DIR
#
# Each experiment waits until the host's 1-minute load average is below
# M6_SOAK_MAX_LOAD (default 20) before it starts, and records the load with
# every sample and event.  The short experiments (chaos, load, fairness) run
# through the shared throttle gate when M6_SOAK_GATE names it; the 2-hour soak
# does not hold a gate slot.  M6_SOAK_CHAOS_ARGS adds chaos arguments (the
# hosted workflow passes --dedicated-redis); M6_SOAK_LOAD_ARGS adds load
# arguments (for example a bulk --payload 65536); M6_SOAK_FAIRNESS_ARGS adds
# fairness arguments (for example --flood-processes 2); M6_SOAK_DURATION sets the soak;
# M6_SOAK_EXPERIMENTS selects a subset (default "chaos load fairness soak");
# M6_SOAK_REDIS names the plaintext Redis (default 127.0.0.1:63790).
set -u
bins=$1 head=$2 logs=$3
here=$(cd "$(dirname "$0")" && pwd)
max=${M6_SOAK_MAX_LOAD:-20}
gate=${M6_SOAK_GATE:-}
redis=${M6_SOAK_REDIS:-127.0.0.1:63790}
load1() { python3 -c 'import os; print(os.getloadavg()[0])'; }
quiet() {  # wait outside any gate slot, so a waiting run holds nothing
  while python3 -c "import os,sys; sys.exit(0 if os.getloadavg()[0] >= $max else 1)"; do
    sleep 30
  done
}
host() { echo "uptime=$(uptime) nproc=$(getconf _NPROCESSORS_ONLN)"; }
for experiment in ${M6_SOAK_EXPERIMENTS:-chaos load fairness soak}; do
  [ "$experiment" = soak ] && continue
  quiet
  extra=""
  [ "$experiment" = chaos ] && extra=${M6_SOAK_CHAOS_ARGS:-}
  [ "$experiment" = load ] && extra=${M6_SOAK_LOAD_ARGS:-}
  [ "$experiment" = fairness ] && extra=${M6_SOAK_FAIRNESS_ARGS:-}
  echo "m6-soak-all: $experiment start $(date +%Y-%m-%dT%H:%M:%S%z) $(host)"
  # shellcheck disable=SC2086
  if [ -n "$gate" ]; then
    $gate nice -n 10 python3 "$here/m6-soak.py" "$experiment" --bin-dir "$bins" --bin-head "$head" \
      --logs "$logs" --redis "$redis" --max-load "$max" $extra > "$logs/$experiment-driver.log" 2>&1
  else
    nice -n 10 python3 "$here/m6-soak.py" "$experiment" --bin-dir "$bins" --bin-head "$head" \
      --logs "$logs" --redis "$redis" --max-load "$max" $extra > "$logs/$experiment-driver.log" 2>&1
  fi
  echo "m6-soak-all: $experiment exit=$? $(date +%Y-%m-%dT%H:%M:%S%z) $(host)"
done
case " ${M6_SOAK_EXPERIMENTS:-chaos load fairness soak} " in *" soak "*) ;; *) exit 0;; esac
quiet
echo "m6-soak-all: soak start $(date +%Y-%m-%dT%H:%M:%S%z) $(host)"
nice -n 10 python3 "$here/m6-soak.py" soak --bin-dir "$bins" --bin-head "$head" --logs "$logs" \
  --redis "$redis" --max-load "$max" --duration "${M6_SOAK_DURATION:-7260}" > "$logs/soak-driver.log" 2>&1
echo "m6-soak-all: soak exit=$? $(date +%Y-%m-%dT%H:%M:%S%z) $(host)"
