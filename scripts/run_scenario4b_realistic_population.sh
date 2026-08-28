#!/usr/bin/env bash
# Reproduces the Scenario 4b heterogeneous multi-supplier, multi-batch
# simulator population: extracts the pure-logic core of
# simulator/traceability-simulator.html (everything before the
# "UI wiring" comment), appends
# simulator/scenario4b_realistic_population_driver.js, and runs the
# result under Node. No numbers in the driver are hand-picked to match a
# hoped-for outcome; the driver prints whatever the engine actually
# computes as JSON.
#
# Requires Docker (uses node:20-slim) so this repo does not depend on a
# local Node install; swap `docker run ... node` for a local `node` call
# if you have one.
set -euo pipefail
cd "$(dirname "$0")/.."

CORE_START=194   # first line of the <script> block's chaincode-engine section
CORE_END=357     # last line before "---------- UI wiring ----------"

TMP_CORE=$(mktemp /tmp/sim_core.XXXXXX)
sed -n "${CORE_START},${CORE_END}p" simulator/traceability-simulator.html > "$TMP_CORE"

TMP_FULL=$(mktemp /tmp/sim_full.XXXXXX)
cat "$TMP_CORE" simulator/scenario4b_realistic_population_driver.js > "$TMP_FULL"

docker run --rm -v "$(pwd):$(pwd)" -v "/tmp:/tmp" -w "$(pwd)" node:20-slim node "$TMP_FULL"

rm -f "$TMP_CORE" "$TMP_FULL"
