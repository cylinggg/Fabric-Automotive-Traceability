#!/usr/bin/env bash
# Real commit-latency and recall-processing-time benchmark against the live
# local Fabric test-network, at N = 10 / 100 / 1,000 components per batch.
#
# Methodology:
#   - Every RegisterComponent invoke uses `peer chaincode invoke --waitForEvent`,
#     so the CLI blocks until the peer's deliver-filtered service confirms the
#     transaction committed VALID; the wall-clock duration of that command is
#     therefore a genuine commit-latency sample (submit -> endorse -> order ->
#     validate -> commit), not merely the time to submit.
#   - Transactions are issued serially, one RegisterComponent at a time, to a
#     single batch (BENCH-<N>), so component IDs are BCOMP-<N>-<i>.
#   - After all N components are registered, a single TriggerRecall call for
#     that batch is timed the same way: that duration is the batch's real
#     "recall processing time" at that scale.
#   - Failure rate = invokes that did not report "committed with status (VALID)"
#     out of N, including any command that errored or timed out.
#   - Raw per-transaction timings are written to
#     evidence/benchmark_N<N>_raw.csv; the summary (median, p95, failure rate,
#     recall processing time) is appended to evidence/benchmark_summary.txt.
#
# This script does not fabricate or estimate figures: every number it prints
# is measured on this run's real local Fabric test-network.
set -uo pipefail

N="${1:?usage: benchmark_scale.sh <N> [suffix]}"
SUFFIX="${2:-}"
cd "/Users/chenyuling/Desktop/論文/fabric-samples/test-network"
export PATH=${PWD}/../bin:/opt/homebrew/bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
P1=organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
P2=organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

EVDIR="/Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/evidence"
RAW="$EVDIR/benchmark_N${N}${SUFFIX}_raw.csv"
mkdir -p "$EVDIR"
echo "index,component_id,duration_s,committed_valid" > "$RAW"

BATCH="BENCH-${N}${SUFFIX}"
echo "=== Benchmark start: N=${N}, batch=${BATCH}, $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a "$EVDIR/benchmark_run.log"

FAIL=0
for ((i=1; i<=N; i++)); do
  CID="BCOMP-${N}${SUFFIX}-${i}"
  H=$(printf 'benchmark report %s %s' "$BATCH" "$i" | shasum -a 256 | awk '{print $1}')
  T0=$(date +%s.%N)
  OUT=$(peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
    -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
    --waitForEvent --waitForEventTimeout 30s \
    -c "{\"function\":\"RegisterComponent\",\"Args\":[\"$CID\",\"$BATCH\",\"Tier2Supplier\",\"$H\",\"Org2MSP\"]}" 2>&1)
  T1=$(date +%s.%N)
  DUR=$(python3 -c "print(round($T1-$T0,3))")
  if echo "$OUT" | grep -q "committed with status (VALID)"; then
    VALID=1
  else
    VALID=0
    FAIL=$((FAIL+1))
    echo "$OUT" >> "$EVDIR/benchmark_N${N}${SUFFIX}_failures.log"
  fi
  echo "${i},${CID},${DUR},${VALID}" >> "$RAW"
  if (( i % 50 == 0 )); then
    echo "  ...${i}/${N} registered ($(date -u +%H:%M:%S))" | tee -a "$EVDIR/benchmark_run.log"
  fi
done

echo "=== Registration phase done for N=${N} at $(date -u +%Y-%m-%dT%H:%M:%SZ); running TriggerRecall on ${BATCH} ===" | tee -a "$EVDIR/benchmark_run.log"

T0=$(date +%s.%N)
RECALL_OUT=$(peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
  -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
  --waitForEvent --waitForEventTimeout 60s \
  -c "{\"function\":\"TriggerRecall\",\"Args\":[\"$BATCH\",\"benchmark recall test N=${N}\"]}" 2>&1)
T1=$(date +%s.%N)
RECALL_DUR=$(python3 -c "print(round($T1-$T0,3))")
RECALL_VALID=$(echo "$RECALL_OUT" | grep -c "committed with status (VALID)")
echo "$RECALL_OUT" > "$EVDIR/benchmark_N${N}${SUFFIX}_recall_output.log"

# Summary statistics from the raw CSV (successful commits only for latency stats)
python3 - "$RAW" "$N" "$FAIL" "$RECALL_DUR" "$RECALL_VALID" "$BATCH" <<'PYEOF' >> "$EVDIR/benchmark_summary.txt"
import csv, sys, statistics
raw_path, n, fail, recall_dur, recall_valid, batch = sys.argv[1:7]
durs = []
with open(raw_path) as f:
    for row in csv.DictReader(f):
        if row["committed_valid"] == "1":
            durs.append(float(row["duration_s"]))
n = int(n); fail = int(fail); recall_valid = int(recall_valid)
if durs:
    durs_sorted = sorted(durs)
    median = statistics.median(durs_sorted)
    p95_idx = min(len(durs_sorted)-1, int(round(0.95*(len(durs_sorted)-1))))
    p95 = durs_sorted[p95_idx]
else:
    median = p95 = float("nan")
print(f"--- N={n} batch={batch} ---")
print(f"registrations attempted: {n}, failed: {fail}, failure_rate: {fail/n:.4f}")
print(f"commit latency (successful invokes only): median={median:.3f}s p95={p95:.3f}s min={min(durs) if durs else float('nan'):.3f}s max={max(durs) if durs else float('nan'):.3f}s")
print(f"TriggerRecall processing time for batch of {n}: {float(recall_dur):.3f}s (committed_valid={'yes' if recall_valid>=1 else 'NO - see benchmark_N%d_recall_output.log' % n})")
print()
PYEOF

echo "=== Benchmark N=${N} complete at $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a "$EVDIR/benchmark_run.log"
tail -5 "$EVDIR/benchmark_summary.txt"
